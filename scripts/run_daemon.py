#!/usr/bin/env python3
"""
scripts/run_daemon.py
Continuous operational daemon runner orchestrating Dream_control cycles
against admission-gate and other registered harnesses.
"""

import sys
import time
import argparse
import logging
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.dream_contract import HarnessSpec, ParamSpec
from core.dream_daemon import DreamDaemon

logger = logging.getLogger("run_daemon")


def build_default_catalog(harness_tree: Path) -> dict[str, HarnessSpec]:
    gate_runner = (harness_tree / "harnesses" / "gate_fuzz_runner.py").resolve()
    fuzz_runner = (harness_tree / "harnesses" / "fuzz_runner.py").resolve()

    catalog: dict[str, HarnessSpec] = {}

    if gate_runner.is_file():
        catalog["admission_gate_policy"] = HarnessSpec(
            harness_id="admission_gate_policy",
            target_subsystem="admission_gate",
            params={
                "target_path": ParamSpec(kind="str", lo=1, hi=256),
                "action_type": ParamSpec(kind="str", lo=1, hi=64),
                "charter_path": ParamSpec(kind="str", lo=1, hi=512),
                "sock_path": ParamSpec(kind="str", lo=1, hi=512),
            },
            allowed_observables=frozenset([
                "statutory_veto_reached",
                "ultra_vires_detected",
                "intra_vires_confirmed",
            ]),
            runner_binary=gate_runner,
        )

    if fuzz_runner.is_file():
        catalog["process_fuzzer"] = HarnessSpec(
            harness_id="process_fuzzer",
            target_subsystem="concurrency_limits",
            params={
                "concurrency": ParamSpec(kind="int", lo=1, hi=128),
                "tight_timeout": ParamSpec(kind="int", lo=1, hi=5000),
            },
            allowed_observables=frozenset(["veto", "timeout", "intra_vires"]),
            runner_binary=fuzz_runner,
        )

    return catalog


def dummy_llm_callable(prompt: str, temperature: float = 0.7) -> str:
    """Deterministic fallback generator satisfying the two-phase Dreamer compiler contract."""
    return (
        "```json\n"
        "{\n"
        '  "harness_id": "admission_gate_policy",\n'
        '  "parameters": {\n'
        '    "target_path": "/etc/shadow",\n'
        '    "action_type": "SHELL_EXEC",\n'
        '    "charter_path": "charter.json",\n'
        '    "sock_path": "/nonexistent.sock"\n'
        "  },\n"
        '  "expected": "statutory_veto_reached"\n'
        "}\n"
        "```"
    )


def main():
    parser = argparse.ArgumentParser(description="Dream_control Continuous Operational Daemon")
    parser.add_argument("--iterations", type=int, default=0, help="Number of cycles to run (0 = infinite)")
    parser.add_argument("--interval", type=float, default=1.0, help="Delay between cycles in seconds")
    parser.add_argument("--k-replicates", type=int, default=3, help="Replication count for deterministic gating")
    parser.add_argument("--workspace", type=Path, default=PROJECT_ROOT / "run_workspace")
    parser.add_argument("--data-dir", type=Path, default=PROJECT_ROOT / "data")
    parser.add_argument("--audit-log", type=Path, default=Path.home() / "admission-gate" / "audit_log.jsonl")
    parser.add_argument("--log-dir", type=Path, default=Path.home() / "sovereign-manifold" / "logs")
    args = parser.parse_args()

    args.workspace.mkdir(parents=True, exist_ok=True)
    args.data_dir.mkdir(parents=True, exist_ok=True)

    catalog = build_default_catalog(PROJECT_ROOT)
    if not catalog:
        logger.error("No valid harnesses found in catalog. Aborting.")
        sys.exit(1)

    logger.info(f"Loaded {len(catalog)} harnesses: {list(catalog.keys())}")

    daemon = DreamDaemon(
        catalog=catalog,
        workspace_root=args.workspace,
        seed_bank_path=args.data_dir / "seeds.json",
        llm_callable=dummy_llm_callable,
        harness_tree=PROJECT_ROOT,
        corpus_path=args.data_dir / "corpus.json",
        flaky_bank_path=args.data_dir / "flaky_seeds.json",
        log_dir=args.log_dir if args.log_dir.is_dir() else None,
        audit_path=args.audit_log if args.audit_log.is_file() else None,
        k_replicates=args.k_replicates,
    )

    cycle_count = 0
    try:
        while True:
            cycle_count += 1
            logger.info(f"=== Starting Cycle {cycle_count} ===")
            result = daemon.run_cycle()
            if result:
                logger.info(
                    f"Result: decision={result['decision']} score={result['score']:.2f}"
                )

            if args.iterations > 0 and cycle_count >= args.iterations:
                logger.info(f"Completed requested {args.iterations} iterations.")
                break

            if args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Daemon halted by operator.")


if __name__ == "__main__":
    main()
