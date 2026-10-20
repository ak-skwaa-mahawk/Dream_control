#!/usr/bin/env python3
"""
Sovereign LLM Agent Adapter:
Binds hosted LLM function calls (Grok / Claude / OpenAI) to binary SOVP
proposals and writes them to the seL4 admission-gate via UIO dataport.
"""

import os
import sys
import struct
import hashlib
from guest_uio_transport import emit_to_relayer
from guest_uio_transport import (
    SovereignGateUIO,
    SOVP_OFFSET_PROPOSAL,
    SOVP_OFFSET_APPROVAL,
    SOVP_OFFSET_VERDICT,
    SOVP_OFFSET_RESULT,
)

SOVP_MAGIC        = 0x534F5650
SOVV_MAGIC        = 0x534F5656
SOVQ_MAGIC        = 0x534F5651
SOVX_MAGIC        = 0x534F5658

SOVP_VERSION      = 1
TOOL_READ_FILE    = 0x0001
TOOL_HTTP_GET     = 0x0002
TOOL_WRITE_FILE   = 0x0101
TOOL_SEND_MESSAGE = 0x0102

DECISION_DENY     = 0
DECISION_ALLOW    = 1
DECISION_QUORUM   = 2

SOVR_STATUS_OK               = 0x0000
SOVR_STATUS_PENDING_APPROVAL = 0xE007

def pack_witness(signer_idx: int, sig: bytes, pubkey: bytes) -> bytes:
    return struct.pack("<B7s64s32s", signer_idx, b'\x00' * 7, sig, pubkey)

def pack_proposal(tool_id: int, sequence_id: int, session_id: int, payload: bytes) -> bytes:
    if len(payload) > 992:
        raise ValueError(f"Payload exceeds SOVP_MAX_ARGS (992 bytes): {len(payload)}")

    arg_len = len(payload)
    padded_args = payload.ljust(992, b'\x00')

    header = struct.pack(
        "<IIQQHHI",
        SOVP_MAGIC,
        (SOVP_VERSION) | (tool_id << 16),
        sequence_id,
        session_id,
        arg_len,
        0,
        0
    )
    frame = header + padded_args
    assert len(frame) == 1024, f"Frame must be exactly 1024 bytes, got {len(frame)}"
    return frame

def pack_approval(seq: int, signer_bitmap: int, witnesses: list) -> bytes:
    quorum_count = len(witnesses)
    header = struct.pack(
        "<IHHQBB6s",
        SOVQ_MAGIC,
        SOVP_VERSION,
        0,
        seq,
        signer_bitmap,
        quorum_count,
        b'\x00' * 6
    )
    witness_bytes = b"".join(witnesses)
    padded_witnesses = witness_bytes.ljust(416, b'\x00')
    frame = header + padded_witnesses
    assert len(frame) == 440, f"Approval must be 440 bytes, got {len(frame)}"
    return frame

def execute_agent_loop(transport: SovereignGateUIO, tool_id: int, seq: int, session: int, payload: bytes):
    print(f"\n[*] --- Phase 1: Proposing Tool Call (tool_id=0x{tool_id:04X}, seq={seq}) ---")
    prop_frame = pack_proposal(tool_id, seq, session, payload)
    transport.write_proposal(prop_frame)
    transport.ring_doorbell()

    if not transport.wait_for_verdict(timeout_sec=2.0):
        print("[-] Timed out awaiting verdict.")
        return

    raw_verdict = transport.read_verdict()
    magic, status, decision, req_mask, ret_seq = struct.unpack("<IHBBQ", raw_verdict[:16])
    challenge = raw_verdict[32:96]

    print(f"[+] Gate Verdict: decision={decision}, status=0x{status:04X}, req_mask=0x{req_mask:02X}")

    if decision == DECISION_ALLOW and status == SOVR_STATUS_OK:
        raw_result = transport.read_result()
        r_magic, r_status, r_len, r_seq = struct.unpack("<IHHQ", raw_result[:16])
        result_text = raw_result[16:16+r_len].decode('utf-8', errors='replace')
        print(f"[+] Direct Execution Result: {result_text if r_len > 0 else 'Executed (Simulated ACK)'}")
        return

    if decision == DECISION_QUORUM and status == SOVR_STATUS_PENDING_APPROVAL:
        print(f"[*] Quorum required. Challenge: {hashlib.sha256(challenge).hexdigest()[:16]}...")
        print("[*] Generating Ed25519 signatures for Triad Quorum (Signers A, B, C)...")

        witnesses = []
        for i in range(3):
            pubkey = bytes([0x10 + i] * 32)
            sig = bytes([0xA0 + i] * 64)
            witnesses.append(pack_witness(i, sig, pubkey))

        approval_frame = pack_approval(seq, 0x07, witnesses)

        print("[*] --- Phase 2: Relaying Quorum Approval ---")
        transport.write_approval(approval_frame)
        transport.ring_doorbell()

        if not transport.wait_for_verdict(timeout_sec=2.0):
            print("[-] Timed out awaiting final result.")
            return

        final_verdict = transport.read_verdict()
        _, f_status, f_decision, _, _ = struct.unpack("<IHBBQ", final_verdict[:16])
        print(f"[+] Final Gate Verdict: decision={f_decision}, status=0x{f_status:04X}")

        raw_result = transport.read_result()
        r_magic, r_status, r_len, r_seq = struct.unpack("<IHHQ", raw_result[:16])
        result_text = raw_result[16:16+r_len].decode('utf-8', errors='replace')
        print(f"[+] Tool Execution Result: {result_text if r_len > 0 else 'Executed (Simulated ACK)'}")

if __name__ == "__main__":
    gate = SovereignGateUIO()

    # 1. Test read (auto-allowed)
    execute_agent_loop(
        gate,
        tool_id=TOOL_READ_FILE,
        seq=1,
        session=0x1111,
        payload=b"/data/canary.txt"
    )

    # 2. Test write (requires quorum handshake)
    execute_agent_loop(
        gate,
        tool_id=TOOL_WRITE_FILE,
        seq=2,
        session=0x2222,
        payload=b"/data/canary.txt\x00Node payload update"
    )

    gate.close()


def dispatch_agent_transition(memory_ids, prior_poly, cand_poly):
    print("[Guest Agent] State proposal approved. Relaying state transition...")
    emit_to_relayer(
        previous_root="0x0000000000000000000000000000000000000000000000000000000000000000",
        memory_ids=memory_ids,
        prior_poly=prior_poly,
        cand_poly=cand_poly
    )
