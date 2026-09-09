#!/usr/bin/env python3
"""
harnesses/gate_fuzz_runner.py
Targeted harness exercising the admission-gate statutory engine.
Consumes input parameters, evaluates policy adherence, and records observable probes.
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Ensure admission_gate is importable
try:
    from admission_gate.schemas import ActionEnvelope, AuthorityVerdict
    from admission_gate.mcp import query_gate
except ImportError:
    sibling = Path.home() / "admission-gate" / "src"
    if sibling.is_dir():
        sys.path.insert(0, str(sibling))
        from admission_gate.schemas import ActionEnvelope, AuthorityVerdict
        from admission_gate.mcp import query_gate
    else:
        raise


def run_gate_probe(params: dict) -> dict:
    # If explicit charter/sock are provided in params, override environment
    if "charter_path" in params:
        os.environ["ADMISSION_GATE_CHARTER"] = str(params["charter_path"])
    if "sock_path" in params:
        os.environ["ADMISSION_GATE_SOCK"] = str(params["sock_path"])

    target_path = params.get("target_path", "/workspace/test.txt")
    action_type = params.get("action_type", "SHELL_EXEC")
    command = params.get("command", "ls -la")

    envelope = ActionEnvelope(
        action_type=action_type,
        principal="DREAM_FUZZER",
        target_resource=target_path,
        payload={"command": command},
    )

    verdict = query_gate(envelope)

    # Allowlisted observable probes
    return {
        "statutory_veto_reached": not verdict.allowed,
        "ultra_vires_detected": "ULTRA_VIRES" in (verdict.error or ""),
        "intra_vires_confirmed": verdict.allowed,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    params = json.loads(args.params.read_text(encoding="utf-8"))
    probes = run_gate_probe(params)

    trace = {"probes": probes}
    args.out.write_text(json.dumps(trace), encoding="utf-8")


if __name__ == "__main__":
    main()
