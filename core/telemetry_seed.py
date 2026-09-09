#!/usr/bin/env python3
"""
core/telemetry_seed.py
Extracts anomalous log lines, timeout events, and gate vetoes 
from sovereign-manifold to seed the dream loop.
"""

import re
import json
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path.home() / "sovereign-manifold" / "logs"

ANOMALY_PATTERNS = [
    re.compile(r"timeout", re.IGNORECASE),
    re.compile(r"veto", re.IGNORECASE),
    re.compile(r"exit\s*(?:code\s*)?12[46]", re.IGNORECASE),
    re.compile(r"drift", re.IGNORECASE),
    re.compile(r"panic", re.IGNORECASE),
]


def extract_log_seeds(log_dir: Path = DEFAULT_LOG_PATH, max_seeds: int = 50) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    if not log_dir.is_dir():
        return seeds

    for log_file in sorted(log_dir.glob("*.log"), reverse=True):
        try:
            with log_file.open("r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    if not line_clean:
                        continue

                    if any(pattern.search(line_clean) for pattern in ANOMALY_PATTERNS):
                        seeds.append({
                            "seed_type": "telemetry_outlier",
                            "source_file": log_file.name,
                            "line_no": line_no,
                            "raw_residue": line_clean[:256],
                        })
                        if len(seeds) >= max_seeds:
                            return seeds
        except OSError:
            continue

    return seeds


def write_seed_bank(seeds: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(seeds, indent=2), encoding="utf-8")


if __name__ == "__main__":
    extracted = extract_log_seeds()
    print(f"Extracted {len(extracted)} telemetry seeds.")
