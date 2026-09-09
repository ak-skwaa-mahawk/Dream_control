#!/usr/bin/env python3
"""
core/telemetry_seed.py
Extracts anomalous log lines, timeout events, statutory vetoes,
and gate policy rejections from manifold logs and admission-gate audit streams.
"""

import re
import json
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path.home() / "sovereign-manifold" / "logs"
DEFAULT_AUDIT_LOG = Path.home() / "admission-gate" / "audit_log.jsonl"

ANOMALY_PATTERNS = [
    re.compile(r"timeout", re.IGNORECASE),
    re.compile(r"veto", re.IGNORECASE),
    re.compile(r"exit\s*(?:code\s*)?12[46]", re.IGNORECASE),
    re.compile(r"drift", re.IGNORECASE),
    re.compile(r"panic", re.IGNORECASE),
]


def extract_audit_seeds(audit_path: Path = DEFAULT_AUDIT_LOG, max_seeds: int = 50) -> list[dict[str, Any]]:
    """Extract policy rejections and timeout anomalies from admission-gate audit_log.jsonl."""
    seeds: list[dict[str, Any]] = []
    if not audit_path.is_file():
        return seeds

    try:
        with audit_path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line_clean = line.strip()
                if not line_clean:
                    continue
                try:
                    entry = json.loads(line_clean)
                except json.JSONDecodeError:
                    continue

                policy_passed = entry.get("policy_passed", True)
                timeout_fired = entry.get("timeout_fired", False)

                if not policy_passed or timeout_fired:
                    proposal = entry.get("proposal", {})
                    seeds.append({
                        "seed_type": "admission_gate_rejection",
                        "source_file": audit_path.name,
                        "line_no": line_no,
                        "command": proposal.get("command", ""),
                        "target_path": proposal.get("target_path", ""),
                        "risk_tier": entry.get("effective_risk_tier", proposal.get("risk_tier", 1)),
                        "reason": entry.get("policy_reason", "Unspecified rejection"),
                        "raw_residue": line_clean[:256],
                    })
                    if len(seeds) >= max_seeds:
                        return seeds
    except OSError:
        pass

    return seeds


def extract_log_seeds(log_dir: Path = DEFAULT_LOG_PATH, max_seeds: int = 50) -> list[dict[str, Any]]:
    """Extract unstructured anomalous log lines matching known failure patterns."""
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


def collect_all_seeds(
    log_dir: Path = DEFAULT_LOG_PATH,
    audit_path: Path = DEFAULT_AUDIT_LOG,
    max_seeds: int = 100,
) -> list[dict[str, Any]]:
    """Aggregate anomalies from both unstructured system logs and admission audit trails."""
    audit_seeds = extract_audit_seeds(audit_path=audit_path, max_seeds=max_seeds // 2)
    log_seeds = extract_log_seeds(log_dir=log_dir, max_seeds=max_seeds - len(audit_seeds))
    return audit_seeds + log_seeds


def write_seed_bank(seeds: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(seeds, indent=2), encoding="utf-8")


if __name__ == "__main__":
    extracted = collect_all_seeds()
    print(f"Extracted {len(extracted)} telemetry and audit seeds.")
