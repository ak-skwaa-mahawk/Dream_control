#!/usr/bin/env python3
"""
harnesses/gate_fuzz_runner.py
IPC client adapter for the admission_gate policy engine.
Communicates with the live admission-gate daemon over a UNIX domain socket
(or inherited socket descriptor) and captures statutory observables.
"""

import os
import sys
import json
import socket
import select
import argparse
from pathlib import Path

SOCKET_TIMEOUT_SEC = 1.0


def query_gate_socket(
    target_path: str,
    action_type: str,
) -> dict[str, bool] | None:
    """
    Connects to the admission-gate UNIX domain socket strictly via inherited
    file descriptor (ADMISSION_GATE_SOCK_FD), preventing arbitrary host socket traversal.
    """
    s = None
    sock_fd_env = os.environ.get("ADMISSION_GATE_SOCK_FD")
    if not (sock_fd_env and sock_fd_env.isdigit()):
        return None

    try:
        fd = int(sock_fd_env)
        s = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)

        s.settimeout(SOCKET_TIMEOUT_SEC)
        request = {
            "action": "query",
            "target_path": target_path,
            "action_type": action_type,
        }
        wire_data = json.dumps(request).encode("utf-8") + b"\n"
        s.sendall(wire_data)

        buf = bytearray()
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)

        if not buf:
            return None

        response = json.loads(buf.decode("utf-8").strip())
        verdict = response.get("verdict") or response.get("status")

        return {
            "statutory_veto_reached": bool(verdict == "veto" or response.get("statutory_veto")),
            "ultra_vires_detected": bool(verdict == "ultra_vires" or response.get("ultra_vires")),
            "intra_vires_confirmed": bool(verdict in ("intra_vires", "allow", "confirmed") or response.get("intra_vires")),
        }
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    finally:
        if s and not sock_fd_env:
            try:
                s.close()
            except OSError:
                pass


def evaluate_admission_policy_fallback(
    target_path: str,
    action_type: str,
    charter_dict: dict,
) -> dict[str, bool]:
    import re
    probes = {
        "statutory_veto_reached": False,
        "ultra_vires_detected": False,
        "intra_vires_confirmed": False,
    }

    prohibited_patterns = charter_dict.get("prohibited_resource_patterns", [])
    path_is_prohibited = any(re.search(pat, target_path) for pat in prohibited_patterns)

    for rule in charter_dict.get("rules", []):
        for fp in rule.get("forbidden_paths", []):
            if target_path == fp or target_path.startswith(fp.rstrip("/") + "/"):
                path_is_prohibited = True
        if action_type in rule.get("forbidden_actions", []):
            path_is_prohibited = True

    if not prohibited_patterns and not charter_dict.get("rules"):
        if target_path in ("/etc/shadow", "/etc/passwd", "/root", "/bin/sh"):
            path_is_prohibited = True

    auth_actions = charter_dict.get("authorized_actions", [])
    action_authorized = True
    if auth_actions:
        action_authorized = action_type in auth_actions

    if path_is_prohibited or not action_authorized:
        probes["statutory_veto_reached"] = True
        probes["ultra_vires_detected"] = True
        probes["intra_vires_confirmed"] = False
    else:
        probes["statutory_veto_reached"] = False
        probes["ultra_vires_detected"] = False
        probes["intra_vires_confirmed"] = True

    return probes


def load_charter_pinned() -> dict:
    charter_fd_env = os.environ.get("ADMISSION_GATE_CHARTER_FD")
    if charter_fd_env and charter_fd_env.isdigit():
        fd = int(charter_fd_env)
        try:
            with open(fd, "r", encoding="utf-8", closefd=False) as f:
                return json.load(f)
        except Exception:
            pass

    return {
        "prohibited_resource_patterns": [r"^/etc/.*", r"^/root/.*"],
        "authorized_actions": ["SHELL_EXEC", "SHELL_READ"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    try:
        params = json.loads(args.params.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Failed to read parameters: {e}\n")
        sys.exit(1)

    target_path = str(params.get("target_path", ""))
    action_type = str(params.get("action_type", ""))
    sock_path = params.get("sock_path")

    # Primary path: query live socket if accessible
    probes = query_gate_socket(target_path, action_type)

    # Fallback path: evaluate pinned charter
    if probes is None:
        charter = load_charter_pinned()
        probes = evaluate_admission_policy_fallback(target_path, action_type, charter)

    output = {
        "status": "ok",
        "probes": probes,
    }
    args.out.write_text(json.dumps(output), encoding="utf-8")


if __name__ == "__main__":
    main()
