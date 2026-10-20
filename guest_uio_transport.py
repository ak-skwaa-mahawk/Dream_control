#!/usr/bin/env python3
"""
Guest UIO Transport Layer:
Interfaces with /dev/uio0 when present under seL4, or runs a bit-exact
in-memory CAmkES dataport emulation using standard Python.
"""

import os
import mmap
import struct
import select
import hashlib
from typing import Optional

SOVP_OFFSET_PROPOSAL = 0x0000
SOVP_OFFSET_APPROVAL = 0x0400
SOVP_OFFSET_VERDICT  = 0x0600
SOVP_OFFSET_RESULT   = 0x0800
PAGE_SIZE            = 4096

SOVP_MAGIC   = 0x534F5650
SOVV_MAGIC   = 0x534F5656
SOVQ_MAGIC   = 0x534F5651
SOVX_MAGIC   = 0x534F5658

SOVP_VERSION = 1
TOOL_READ_FILE    = 0x0001
TOOL_HTTP_GET     = 0x0002
TOOL_WRITE_FILE   = 0x0101
TOOL_SEND_MESSAGE = 0x0102

DECISION_DENY   = 0
DECISION_ALLOW  = 1
DECISION_QUORUM = 2

SOVR_STATUS_OK                = 0x0000
SOVR_STATUS_ERR_MAGIC         = 0xE001
SOVR_STATUS_ERR_VERSION       = 0xE002
SOVR_STATUS_ERR_ARGS_LEN      = 0xE003
SOVR_STATUS_ERR_CANONICAL     = 0xE004
SOVR_STATUS_ERR_SEQUENCE      = 0xE005
SOVR_STATUS_ERR_UNKNOWN_TOOL  = 0xE006
SOVR_STATUS_PENDING_APPROVAL  = 0xE007
SOVR_STATUS_ERR_STALE         = 0xE008
SOVR_STATUS_ERR_QUORUM_COUNT  = 0xE00A

SOVP_POLICY = {
    TOOL_READ_FILE:    (DECISION_ALLOW,  0,    1, 256),
    TOOL_HTTP_GET:     (DECISION_ALLOW,  0,    1, 512),
    TOOL_WRITE_FILE:   (DECISION_QUORUM, 0x07, 2, 992),
    TOOL_SEND_MESSAGE: (DECISION_QUORUM, 0x07, 2, 992),
}

class SovereignGateUIO:
    def __init__(self, uio_device: str = "/dev/uio0"):
        self.uio_device = uio_device
        self.fd: Optional[int] = None
        self._is_mock = False
        self.last_seq = 0
        self.active_challenge = b'\x00' * 64
        self.active_seq = 0
        self.active_mask = 0

        if os.path.exists(self.uio_device):
            self.fd = os.open(self.uio_device, os.O_RDWR | os.O_SYNC)
            self.mem = mmap.mmap(self.fd, PAGE_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
        else:
            self._is_mock = True
            self.mem = mmap.mmap(-1, PAGE_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)

    def write_proposal(self, frame: bytes) -> None:
        self.mem.seek(SOVP_OFFSET_APPROVAL)
        self.mem.write(b'\x00' * 4)
        self.mem.seek(SOVP_OFFSET_PROPOSAL)
        self.mem.write(frame)
        self.mem.flush()

    def write_approval(self, frame: bytes) -> None:
        self.mem.seek(SOVP_OFFSET_APPROVAL)
        self.mem.write(frame)
        self.mem.flush()

    def read_verdict(self) -> bytes:
        self.mem.seek(SOVP_OFFSET_VERDICT)
        return self.mem.read(96)

    def read_result(self) -> bytes:
        self.mem.seek(SOVP_OFFSET_RESULT)
        return self.mem.read(1024)

    def ring_doorbell(self) -> None:
        if not self._is_mock and self.fd is not None:
            os.write(self.fd, struct.pack("<I", 1))
            return

        self.mem.seek(SOVP_OFFSET_APPROVAL)
        app_magic = struct.unpack("<I", self.mem.read(4))[0]

        if app_magic == SOVQ_MAGIC:
            self.mem.seek(SOVP_OFFSET_APPROVAL)
            app_frame = self.mem.read(440)
            magic, ver, _, seq, bitmap, qcount = struct.unpack("<IHHQBB", app_frame[:18])

            if seq != self.active_seq or self.active_seq == 0:
                status = SOVR_STATUS_ERR_STALE
            elif bin(bitmap).count("1") != qcount or (bitmap & self.active_mask) != self.active_mask:
                status = SOVR_STATUS_ERR_QUORUM_COUNT
            else:
                status = SOVR_STATUS_OK

            decision = DECISION_ALLOW if status == SOVR_STATUS_OK else DECISION_DENY
            verdict = struct.pack("<IHBBQ16s64s", SOVV_MAGIC, status, decision, 0, seq, b'\x00'*16, b'\x00'*64)
            self.mem.seek(SOVP_OFFSET_VERDICT)
            self.mem.write(verdict)

            if status == SOVR_STATUS_OK:
                res_msg = b"EXEC_WRITE_OK\n"
                res_frame = struct.pack("<IHHQ", SOVX_MAGIC, SOVR_STATUS_OK, len(res_msg), seq) + res_msg.ljust(1008, b'\x00')
                self.mem.seek(SOVP_OFFSET_RESULT)
                self.mem.write(res_frame)
                self.active_seq = 0

            self.mem.seek(SOVP_OFFSET_APPROVAL)
            self.mem.write(b'\x00' * 4)
            return

        self.mem.seek(SOVP_OFFSET_PROPOSAL)
        prop_frame = self.mem.read(1024)
        magic, ver_tool, seq, session, arg_len = struct.unpack("<IIQQH", prop_frame[:26])
        ver = ver_tool & 0xFFFF
        tool_id = (ver_tool >> 16) & 0xFFFF
        args = prop_frame[32:32 + 992]

        if magic != SOVP_MAGIC:
            self._write_deny(SOVR_STATUS_ERR_MAGIC, seq); return
        if ver != SOVP_VERSION:
            self._write_deny(SOVR_STATUS_ERR_VERSION, seq); return
        if seq <= self.last_seq:
            self._write_deny(SOVR_STATUS_ERR_SEQUENCE, seq); return
        if arg_len > 992:
            self._write_deny(SOVR_STATUS_ERR_ARGS_LEN, seq); return
        if any(b != 0 for b in args[arg_len:]):
            self._write_deny(SOVR_STATUS_ERR_CANONICAL, seq); return
        if tool_id not in SOVP_POLICY:
            self._write_deny(SOVR_STATUS_ERR_UNKNOWN_TOOL, seq); return

        policy_decision, req_mask, min_len, max_len = SOVP_POLICY[tool_id]
        if arg_len < min_len or arg_len > max_len:
            self._write_deny(SOVR_STATUS_ERR_ARGS_LEN, seq); return

        self.last_seq = seq

        if policy_decision == DECISION_ALLOW:
            verdict = struct.pack("<IHBBQ16s64s", SOVV_MAGIC, SOVR_STATUS_OK, DECISION_ALLOW, 0, seq, b'\x00'*16, b'\x00'*64)
            self.mem.seek(SOVP_OFFSET_VERDICT)
            self.mem.write(verdict)

            res_msg = b"EXEC_READ_OK\n"
            res_frame = struct.pack("<IHHQ", SOVX_MAGIC, SOVR_STATUS_OK, len(res_msg), seq) + res_msg.ljust(1008, b'\x00')
            self.mem.seek(SOVP_OFFSET_RESULT)
            self.mem.write(res_frame)
            return

        if policy_decision == DECISION_QUORUM:
            nonce = bytes(range(0xA0, 0xB0))
            preimage = b"SOVP-APPROVE-v1" + prop_frame + nonce
            challenge = hashlib.sha512(preimage).digest()

            self.active_seq = seq
            self.active_mask = req_mask
            self.active_challenge = challenge

            verdict = struct.pack("<IHBBQ16s64s", SOVV_MAGIC, SOVR_STATUS_PENDING_APPROVAL, DECISION_QUORUM, req_mask, seq, nonce, challenge)
            self.mem.seek(SOVP_OFFSET_VERDICT)
            self.mem.write(verdict)

    def _write_deny(self, status: int, seq: int) -> None:
        verdict = struct.pack("<IHBBQ16s64s", SOVV_MAGIC, status, DECISION_DENY, 0, seq, b'\x00'*16, b'\x00'*64)
        self.mem.seek(SOVP_OFFSET_VERDICT)
        self.mem.write(verdict)

    def wait_for_verdict(self, timeout_sec: float = 2.0) -> bool:
        if self._is_mock or self.fd is None:
            return True
        r, _, _ = select.select([self.fd], [], [], timeout_sec)
        if r:
            os.read(self.fd, 4)
            return True
        return False

    def close(self) -> None:
        if self.mem:
            self.mem.close()
        if self.fd is not None:
            os.close(self.fd)


# --- Sovereign Appliance Relayer Egress Hook ---
import os
import json

PIPE_PATH = "/data/data/com.termux/files/home/sovereign-appliance/state_queue.pipe"

def emit_to_relayer(previous_root: str, memory_ids: list, prior_poly: list, cand_poly: list, half_life: float = 24.0):
    payload = {
        "previousRoot": previous_root,
        "activeMemoryIds": memory_ids,
        "decayHalfLifeHours": half_life,
        "priorPolygon": prior_poly,
        "candidatePolygon": cand_poly
    }
    if os.path.exists(PIPE_PATH):
        try:
            with open(PIPE_PATH, "w") as p:
                p.write(json.dumps(payload) + "\n")
            print("[UIO Transport] Successfully relayed state transition to ZK daemon.")
        except Exception as e:
            print(f"[UIO Transport Error] Failed to write to FIFO: {e}")
    else:
        print(f"[UIO Transport Error] Pipe not found at {PIPE_PATH}")
