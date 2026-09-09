#!/usr/bin/env python3
"""
scripts/run_daemon.py
Continuous operational daemon runner orchestrating Dream_control cycles
against admission-gate and other registered harnesses with structured inference.
"""

import os
import sys
import time
import json
import argparse
import logging
import urllib.request
import urllib.error
from pathlib import Path

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
                "timeout_s": ParamSpec(kind="float", lo=0.001, hi=1.0),
            },
            allowed_observables=frozenset([
                "statutory_veto_reached",
                "admission_timeout",
            ]),
            runner_binary=fuzz_runner,
        )

    return catalog


class StructuredInferenceCompiler:
    """
    Two-phase constrained compiler. Queries a local or remote OpenAI-compatible API
    with temperature variation, falling back to schema-synthesized mutations.
    """
    def __init__(self, endpoint: str | None = None, api_key: str | None = None, model: str = "default"):
        self.endpoint = endpoint or os.environ.get("LLM_ENDPOINT")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "EMPTY")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-3.5-turbo")

    def __call__(self, prompt: str, temperature: float = 0.7) -> str:
        if self.endpoint:
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                }
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "response_format": {"type": "json_object"} if temperature <= 0.3 else None,
                }
                req = urllib.request.Request(
                    self.endpoint,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    content = res_json["choices"][0]["message"]["content"]
                    return content
            except Exception as e:
                logger.warning(f"Inference endpoint call failed ({e}); using constrained fallback generator.")

        # Constrained fallback generation respecting prompt phases
        if temperature > 0.5:
            # Phase 1: High-entropy hypothesis
            return (
                "Hypothesis: Stressing path boundary checks against /etc/passwd "
                "with an unprivileged SHELL_READ should trigger statutory_veto_reached."
            )
        else:
            from core.dream_scheduler import dispatch_cold_uniform
            cat = build_default_catalog(PROJECT_ROOT)
            cold = dispatch_cold_uniform(cat)
            hid = cold["harness_id"]
            exp_obs = "statutory_veto_reached" if hid == "admission_gate_policy" else "admission_timeout"
            sample = {
                "harness_id": hid,
                "parameters": cold["parameters"],
                "expected": exp_obs,
            }
            return f"```json\n{json.dumps(sample, indent=2)}\n```"


def main():
    parser = argparse.ArgumentParser(description="Dream_control Continuous Operational Daemon")
    parser.add_argument("--iterations", type=int, default=0, help="Number of cycles to run (0 = infinite)")
    parser.add_argument("--interval", type=float, default=1.0, help="Delay between cycles in seconds")
    parser.add_argument("--k-replicates", type=int, default=3, help="Replication count for deterministic gating")
    parser.add_argument("--workspace", type=Path, default=PROJECT_ROOT / "run_workspace")
    parser.add_argument("--data-dir", type=Path, default=PROJECT_ROOT / "data")
    parser.add_argument("--audit-log", type=Path, default=Path.home() / "admission-gate" / "audit_log.jsonl")
    parser.add_argument("--log-dir", type=Path, default=Path.home() / "sovereign-manifold" / "logs")
    parser.add_argument("--llm-endpoint", type=str, default=None, help="OpenAI-compatible inference URL")
    parser.add_argument(
        "--allow-unconfined",
        action="store_true",
        default=False,
        help="Permit unconfined execution if Linux namespaces/cgroups are unavailable",
    )
    args = parser.parse_args()

    args.workspace.mkdir(parents=True, exist_ok=True)
    args.data_dir.mkdir(parents=True, exist_ok=True)

    catalog = build_default_catalog(PROJECT_ROOT)
    if not catalog:
        logger.error("No valid harnesses found in catalog. Aborting.")
        sys.exit(1)

    logger.info(f"Loaded {len(catalog)} harnesses: {list(catalog.keys())}")

    compiler = StructuredInferenceCompiler(endpoint=args.llm_endpoint)

    daemon = DreamDaemon(
        catalog=catalog,
        workspace_root=args.workspace,
        seed_bank_path=args.data_dir / "seeds.json",
        llm_callable=compiler,
        harness_tree=PROJECT_ROOT / "harnesses",
        corpus_path=args.data_dir / "corpus.json",
        flaky_bank_path=args.data_dir / "flaky_seeds.json",
        log_dir=args.log_dir if args.log_dir.is_dir() else None,
        audit_path=args.audit_log if args.audit_log.is_file() else None,
        k_replicates=args.k_replicates,
        require_isolation=not args.allow_unconfined,
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
