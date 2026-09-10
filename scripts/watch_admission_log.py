#!/usr/bin/env python3
"""
scripts/watch_admission_log.py
Tails admission-gate audit_log.jsonl and ingests real-time telemetry anomaly seeds
into seed_bank.json for DreamDaemon synthesis.
"""

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1 if "scripts" in str(__file__) or "core" in str(__file__) else 0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import argparse
import json
import logging
import os
from pathlib import Path
import time
from typing import Any

from core.telemetry_seed import ANOMALY_PATTERNS, write_seed_bank

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("admission_watcher")


def parse_audit_entry_to_seed(entry: dict[str, Any], line_no: int = 1) -> dict[str, Any] | None:
    """Extract a seed from an audit log entry if it represents a rejection or anomaly."""
    is_anomaly = False
    raw_residue = ""

    if entry.get("policy_passed") is False or entry.get("decision") == "DENY":
        is_anomaly = True
        raw_residue = entry.get("reason", "") or entry.get("statutory_veto_reason", "")
        if not raw_residue and "proposal" in entry:
            raw_residue = f"Rejected proposal: {entry['proposal']}"

    if not is_anomaly:
        dumped = json.dumps(entry)
        for pattern in ANOMALY_PATTERNS:
            if pattern.search(dumped):
                is_anomaly = True
                raw_residue = f"Pattern match ({pattern.pattern}): {dumped[:120]}"
                break

    if is_anomaly:
        return {
            "source": "admission_gate_audit",
            "seed_type": "audit_rejection",
            "line_number": line_no,
            "raw_residue": raw_residue or "statutory_veto",
            "entry": entry,
        }
    return None


def tail_audit_log(
    log_path: Path,
    seed_bank_path: Path,
    poll_interval_s: float = 0.5,
    max_iterations: int | None = None,
    seek_to_end: bool = True,
) -> None:
    """Tails log_path for audit events and appends newly discovered seeds to seed_bank_path."""
    iterations = 0
    if not log_path.exists():
        logger.warning("Audit log %s does not exist yet; waiting...", log_path)
        while not log_path.exists():
            time.sleep(poll_interval_s)
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                return

    logger.info("Tracking audit log at %s", log_path)

    existing_seeds: list[dict[str, Any]] = []
    if seed_bank_path.exists():
        try:
            with seed_bank_path.open("r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, list):
                    existing_seeds = content
        except Exception:
            existing_seeds = []

    seen_residues = {
        s.get("raw_residue") for s in existing_seeds if isinstance(s, dict) and "raw_residue" in s
    }

    with log_path.open("r", encoding="utf-8") as f:
        if seek_to_end:
            f.seek(0, os.SEEK_END)
        line_counter = 0

        while True:
            line = f.readline()
            if not line:
                if max_iterations is not None:
                    iterations += 1
                    if iterations >= max_iterations:
                        break
                time.sleep(poll_interval_s)
                continue

            line_clean = line.strip()
            if not line_clean:
                continue

            line_counter += 1
            try:
                record = json.loads(line_clean)
            except json.JSONDecodeError:
                continue

            seed = parse_audit_entry_to_seed(record, line_no=line_counter)
            if seed:
                residue = seed.get("raw_residue")
                if residue and residue not in seen_residues:
                    seen_residues.add(residue)
                    existing_seeds.append(seed)
                    write_seed_bank(existing_seeds, seed_bank_path)
                    logger.info("Ingested anomaly seed into %s: %s", seed_bank_path, residue[:60])

            if max_iterations is not None:
                iterations += 1
                if iterations >= max_iterations:
                    break


def parse_args():
    parser = argparse.ArgumentParser(description="Tail admission-gate audit logs into Dream seed bank")
    parser.add_argument("--audit-log", type=Path, default=Path("audit_log.jsonl"), help="Path to audit_log.jsonl")
    parser.add_argument("--seed-bank", type=Path, default=Path("seed_bank.json"), help="Destination seed bank")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval in seconds")
    parser.add_argument("--from-start", action="store_true", help="Read log from start instead of tailing end")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    tail_audit_log(args.audit_log, args.seed_bank, poll_interval_s=args.poll_interval, seek_to_end=not args.from_start)