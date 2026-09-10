#!/usr/bin/env python3
"""
scripts/watch_admission_log.py
Tails admission-gate audit_log.jsonl and extracts real-time telemetry seeds
into seed_bank.json for DreamDaemon consumption.
"""

import argparse
import json
import logging
import os
from pathlib import Path
import time
from typing import Any

from core.telemetry_seed import extract_audit_rejections, write_seed_bank

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("admission_watcher")


def tail_audit_log(log_path: Path, seed_bank_path: Path, poll_interval_s: float = 1.0) -> None:
    if not log_path.exists():
        logger.warning("Audit log %s does not exist yet; waiting...", log_path)
        while not log_path.exists():
            time.sleep(poll_interval_s)

    logger.info("Tracking audit log at %s", log_path)

    # Load existing seeds to preserve deduplication state
    existing_seeds: list[dict[str, Any]] = []
    if seed_bank_path.exists():
        try:
            with seed_bank_path.open("r", encoding="utf-8") as f:
                existing_seeds = json.load(f)
        except Exception:
            existing_seeds = []

    seen_signatures = {
        s.get("raw_residue") for s in existing_seeds if isinstance(s, dict) and "raw_residue" in s
    }

    with log_path.open("r", encoding="utf-8") as f:
        # Seek to end of existing records to capture only fresh anomalies
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval_s)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Process statutory rejections and policy exceptions
            new_seeds = extract_audit_rejections([record])
            added = 0
            for seed in new_seeds:
                residue = seed.get("raw_residue")
                if residue and residue not in seen_signatures:
                    seen_signatures.add(residue)
                    existing_seeds.append(seed)
                    added += 1

            if added > 0:
                write_seed_bank(existing_seeds, seed_bank_path)
                logger.info("Ingested %d new anomaly seed(s) into %s", added, seed_bank_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tail admission-gate audit logs into Dream seed bank")
    parser.add_argument("--audit-log", type=Path, default=Path("audit_log.jsonl"), help="Path to audit_log.jsonl")
    parser.add_argument("--seed-bank", type=Path, default=Path("seed_bank.json"), help="Destination seed bank")
    args = parser.parse_args()

    tail_audit_log(args.audit_log, args.seed_bank)
