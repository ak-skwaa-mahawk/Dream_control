#!/usr/bin/env python3
"""
harnesses/fuzz_runner.py
Reference harness executable reading params from disk and emitting trace.json.
"""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    params = json.loads(args.params.read_text(encoding="utf-8"))

    # Echo observed results back out
    trace = {
        "probes": {
            "admission_timeout": True,
            "statutory_veto_reached": False,
            "injected_fake_leak": True,  # Disallowed probe
        }
    }
    args.out.write_text(json.dumps(trace), encoding="utf-8")


if __name__ == "__main__":
    main()
