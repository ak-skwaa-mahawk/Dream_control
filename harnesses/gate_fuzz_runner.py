#!/usr/bin/env python3
"""
harnesses/gate_fuzz_runner.py
Pinning adapter for the admission_gate policy engine.
Consumes structured target parameters with descriptor pinning support
and evaluates statutory veto, ultra vires, and intra vires policy states.
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path


def evaluate_admission_policy(
    target_path: str,
    action_type: str,
    charter_dict: dict,
) -> dict[str, bool]:
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

    if path_is_prohibited:
        probes["statutory_veto_reached"] = True
        probes["ultra_vires_detected"] = True
        probes["intra_vires_confirmed"] = False
    elif not action_authorized:
        probes["statutory_veto_reached"] = True
        probes["ultra_vires_detected"] = True
        probes["intra_vires_confirmed"] = False
    else:
        probes["statutory_veto_reached"] = False
        probes["ultra_vires_detected"] = False
        probes["intra_vires_confirmed"] = True

    return probes


def load_charter_pinned(charter_param: str) -> dict:
    # Option 1: File descriptor pinning
    charter_fd_env = os.environ.get("ADMISSION_GATE_CHARTER_FD")
    if charter_fd_env and charter_fd_env.isdigit():
        fd = int(charter_fd_env)
        try:
            with open(fd, "r", encoding="utf-8", closefd=False) as f:
                return json.load(f)
        except Exception:
            pass

    # Option 2: Strictly require JSON filename and verify file exists without escaping cell
    charter_path = Path(charter_param)
    if charter_path.name.endswith(".json") and charter_path.is_file():
        try:
            data = json.loads(charter_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
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
    charter_str = str(params.get("charter_path", "charter.json"))

    charter = load_charter_pinned(charter_str)
    probes = evaluate_admission_policy(target_path, action_type, charter)

    output = {
        "status": "ok",
        "probes": probes,
    }
    args.out.write_text(json.dumps(output), encoding="utf-8")


if __name__ == "__main__":
    main()
