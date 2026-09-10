#!/usr/bin/env python3
"""Inspect and report corpus signatures, saturation decay ratios, and mutation yield."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from core.dream_evaluator import SignatureCorpus


def analyze_corpus(corpus_path: Path) -> dict[str, Any]:
    """Load corpus file and compute aggregate metrics."""
    if not corpus_path.is_file():
        return {
            "exists": False,
            "error": f"File not found: {corpus_path}",
            "harnesses": {},
            "total_signatures": 0,
            "total_observations": 0,
        }

    try:
        data = json.loads(corpus_path.read_text(encoding="utf-8"))
    except Exception as err:
        return {
            "exists": False,
            "error": f"Corpus deserialization failed: {err}",
            "harnesses": {},
            "total_signatures": 0,
            "total_observations": 0,
        }

    # Reconstitute corpus to use its decay calculation methods
    corpus = SignatureCorpus()
    if isinstance(data, dict):
        corpus.frequencies = {
            hid: dict(sigs) for hid, sigs in data.items() if isinstance(sigs, dict)
        }

    harness_metrics: dict[str, Any] = {}
    total_signatures = 0
    total_observations = 0

    for hid, sig_counts in corpus.frequencies.items():
        count_sigs = len(sig_counts)
        obs = sum(sig_counts.values())
        total_signatures += count_sigs
        total_observations += obs

        # Calculate decay ratio across observed signatures for this harness
        decay_snapshots: list[dict[str, Any]] = []
        for sig, frequency in sorted(sig_counts.items(), key=lambda x: x[1], reverse=True):
            # Compute current novelty for each recorded signature under standard decay modes
            linear_novelty = 1.0 / frequency if frequency > 0 else 1.0
            steep_novelty = 0.5 ** (frequency - 1) if frequency > 0 else 1.0

            decay_snapshots.append({
                "signature": sig,
                "occurrences": frequency,
                "novelty_linear": round(linear_novelty, 4),
                "novelty_steep": round(steep_novelty, 4),
            })

        # Mutation yield proxy: unique signature discovery density over total observations
        mutation_yield = round((count_sigs / obs), 4) if obs > 0 else 0.0

        harness_metrics[hid] = {
            "unique_signatures": count_sigs,
            "total_observations": obs,
            "mutation_yield": mutation_yield,
            "signatures": decay_snapshots,
        }

    return {
        "exists": True,
        "corpus_file": str(corpus_path),
        "total_signatures": total_signatures,
        "total_observations": total_observations,
        "global_mutation_yield": round((total_signatures / total_observations), 4) if total_observations > 0 else 0.0,
        "harnesses": harness_metrics,
    }


def format_text_report(metrics: dict[str, Any]) -> str:
    """Format metrics dictionary into a readable CLI summary report."""
    if not metrics.get("exists", False):
        return f"[!] Corpus Error: {metrics.get('error', 'Corpus does not exist.')}"

    lines: list[str] = [
        "============================================================",
        "              DREAM CORPUS METRICS & YIELD REPORT           ",
        "============================================================",
        f"Corpus Path:           {metrics['corpus_file']}",
        f"Total Unique Sigs:     {metrics['total_signatures']}",
        f"Total Observations:    {metrics['total_observations']}",
        f"Global Mutation Yield: {metrics['global_mutation_yield'] * 100:.2f}%",
        "------------------------------------------------------------",
    ]

    for hid, stats in metrics["harnesses"].items():
        lines.append(f"Harness: {hid}")
        lines.append(f"  Unique Sigs:     {stats['unique_signatures']}")
        lines.append(f"  Observations:    {stats['total_observations']}")
        lines.append(f"  Mutation Yield:  {stats['mutation_yield'] * 100:.2f}%")
        lines.append("  Top Signatures (occurrences | linear novelty | steep novelty):")
        for s in stats["signatures"][:5]:
            sig_short = s["signature"][:28] + ("..." if len(s["signature"]) > 28 else "")
            lines.append(
                f"    - {sig_short:<32} count: {s['occurrences']:<4} "
                f"nov_lin: {s['novelty_linear']:<6} nov_exp: {s['novelty_steep']}"
            )
        if len(stats["signatures"]) > 5:
            lines.append(f"    ... and {len(stats['signatures']) - 5} more signature(s)")
        lines.append("------------------------------------------------------------")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze and dump dream corpus coverage and decay metrics.")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("corpus.json"),
        help="Path to corpus JSON file (default: corpus.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw structured metrics in JSON format",
    )
    args = parser.parse_args()

    metrics = analyze_corpus(args.corpus)
    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        print(format_text_report(metrics))

    return 0 if metrics.get("exists", False) else 1


if __name__ == "__main__":
    sys.exit(main())
