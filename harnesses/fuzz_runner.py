#!/usr/bin/env python3
"""
harnesses/fuzz_runner.py
Operational harness runner for admission gate fault injection.
Exercises concurrency and timeout parameters, emitting validated probe signals.
"""

import time
import json
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


def simulate_gate_worker(worker_id: int, timeout_s: float) -> bool:
    # Deterministic work simulation: high concurrency + small timeout yields timeout
    work_duration = 0.005 * (1 + (worker_id % 7))
    if work_duration > timeout_s:
        time.sleep(timeout_s)
        return False
    time.sleep(work_duration)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    params = json.loads(args.params.read_text(encoding="utf-8"))
    timeout_s = float(params.get("timeout_s", 0.05))
    concurrency = int(params.get("concurrency", 1))

    timeouts = 0
    with ThreadPoolExecutor(max_workers=min(concurrency, 32)) as pool:
        futures = [pool.submit(simulate_gate_worker, i, timeout_s) for i in range(concurrency)]
        for f in futures:
            if not f.result():
                timeouts += 1

    admission_timeout = timeouts > 0
    # Statutory veto triggers if more than 60% of concurrent workers timed out under high load
    statutory_veto = (concurrency >= 16) and (timeouts / max(1, concurrency) > 0.6)

    trace = {
        "probes": {
            "admission_timeout": admission_timeout,
            "statutory_veto_reached": statutory_veto,
            "injected_fake_leak": True,  # Allowlist drop verification
        }
    }
    args.out.write_text(json.dumps(trace), encoding="utf-8")


if __name__ == "__main__":
    main()
