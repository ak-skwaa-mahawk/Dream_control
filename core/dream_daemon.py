#!/usr/bin/env python3
"""
core/dream_daemon.py
Top-level autonomous idle runner coordinating scheduling, generation,
warden execution, trace evaluation, and seed bank updates.
"""

import time
import json
import logging
from pathlib import Path
from typing import Callable, Mapping, Any

from core.dream_contract import HarnessSpec, Experiment, RawTrace
from core.dream_scheduler import schedule_next_dream
from core.dreamer import generate_experiment
from core.warden import execute_in_cell
from core.dream_evaluator import SignatureCorpus, evaluate_traces, compute_signature
from core.telemetry_seed import extract_log_seeds, write_seed_bank

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dream_daemon")


class DreamDaemon:
    def __init__(
        self,
        catalog: Mapping[str, HarnessSpec],
        workspace_root: Path,
        seed_bank_path: Path,
        llm_callable: Callable[[str, float], str],
        harness_tree: Path | None = None,
    ):
        self.catalog = catalog
        self.workspace_root = workspace_root
        self.seed_bank_path = seed_bank_path
        self.llm_callable = llm_callable
        self.harness_tree = harness_tree
        self.corpus = SignatureCorpus()
        self.promoted_seeds: list[dict[str, Any]] = self._load_seeds()

    def _load_seeds(self) -> list[dict[str, Any]]:
        if self.seed_bank_path.is_file():
            try:
                return json.loads(self.seed_bank_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        return []

    def _save_seeds(self) -> None:
        write_seed_bank(self.promoted_seeds, self.seed_bank_path)

    def run_cycle(self) -> dict[str, Any] | None:
        outliers = extract_log_seeds()
        plan = schedule_next_dream(self.promoted_seeds, self.catalog, outliers)
        mode = plan["mode"]
        logger.info(f"Dispatching cycle with mode: {mode}")

        exp: Experiment
        if mode == "telemetry_perturbation":
            try:
                exp = generate_experiment(plan["seed_data"], self.catalog, self.llm_callable)
            except Exception as e:
                logger.warning(f"Generation failed for telemetry seed: {e}")
                return None
        else:
            hid = plan["harness_id"]
            spec = self.catalog[hid]
            exp = Experiment(
                dream_id=f"dream_{int(time.time()*1000)}",
                harness_id=hid,
                parameters=plan["parameters"],
                expected=next(iter(spec.allowed_observables)) if spec.allowed_observables else "timeout",
                unexpected=("panic",),
                budget_ms=1000,
            )

        spec = self.catalog[exp.harness_id]
        trace: RawTrace = execute_in_cell(
            spec=spec,
            validated_params=dict(exp.parameters),
            budget_ms=exp.budget_ms,
            workspace_root=self.workspace_root,
            harness_tree=self.harness_tree,
        )

        sig0 = compute_signature(trace)
        novelty = self.corpus.get_novelty(exp.harness_id, sig0)
        verdict = evaluate_traces(exp, [trace], novelty=novelty)
        self.corpus.record(exp.harness_id, sig0)

        logger.info(
            f"Cycle finished: decision={verdict.decision} score={verdict.score:.2f} novelty={verdict.novelty:.2f}"
        )

        if verdict.decision in ("promote_candidate", "flaky"):
            self.promoted_seeds.append({
                "experiment_hash": exp.experiment_hash,
                "harness_id": exp.harness_id,
                "parameters": dict(exp.parameters),
                "signature": sig0,
                "score": verdict.score,
                "decision": verdict.decision,
            })
            self._save_seeds()

        return {
            "dream_id": exp.dream_id,
            "decision": verdict.decision,
            "score": verdict.score,
            "trace": trace,
        }
