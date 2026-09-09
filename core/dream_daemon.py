#!/usr/bin/env python3
"""
core/dream_daemon.py
Autonomous idle runner with K>=3 replication, flaky seed quarantine,
and persistent signature corpus tracking.
"""

import time
import json
import logging
from pathlib import Path
from typing import Callable, Mapping, Any

from core.dream_contract import HarnessSpec, Experiment, RawTrace, Verdict
from core.dream_scheduler import schedule_next_dream
from core.dreamer import generate_experiment
from core.warden import execute_in_cell
from core.dream_evaluator import SignatureCorpus, evaluate_traces, compute_signature
from core.telemetry_seed import extract_log_seeds, write_seed_bank

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dream_daemon")

DEFAULT_K_REPLICATES = 3


class DreamDaemon:
    def __init__(
        self,
        catalog: Mapping[str, HarnessSpec],
        workspace_root: Path,
        seed_bank_path: Path,
        llm_callable: Callable[[str, float], str],
        harness_tree: Path,
        corpus_path: Path | None = None,
        flaky_bank_path: Path | None = None,
        log_dir: Path | None = None,
        k_replicates: int = DEFAULT_K_REPLICATES,
    ):
        self.catalog = catalog
        self.workspace_root = workspace_root
        self.seed_bank_path = seed_bank_path
        self.flaky_bank_path = flaky_bank_path or seed_bank_path.parent / "flaky_seeds.json"
        self.corpus_path = corpus_path or seed_bank_path.parent / "corpus.json"
        self.llm_callable = llm_callable
        self.harness_tree = harness_tree
        self.log_dir = log_dir
        self.k_replicates = max(1, k_replicates)

        self.corpus = self._load_corpus()
        self.promoted_seeds: list[dict[str, Any]] = self._load_json_list(self.seed_bank_path)
        self.flaky_seeds: list[dict[str, Any]] = self._load_json_list(self.flaky_bank_path)

    def _load_json_list(self, path: Path) -> list[dict[str, Any]]:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except (OSError, json.JSONDecodeError):
                pass
        return []

    def _save_json_list(self, data: list[dict[str, Any]], path: Path) -> None:
        write_seed_bank(data, path)

    def _load_corpus(self) -> SignatureCorpus:
        corpus = SignatureCorpus()
        if self.corpus_path.is_file():
            try:
                raw = json.loads(self.corpus_path.read_text(encoding="utf-8"))
                for hid, sig_list in raw.items():
                    if hid in self.catalog and isinstance(sig_list, list):
                        corpus._corpus[hid] = list(sig_list)
            except (OSError, json.JSONDecodeError):
                pass
        return corpus

    def _save_corpus(self) -> None:
        self.corpus_path.parent.mkdir(parents=True, exist_ok=True)
        self.corpus_path.write_text(json.dumps(self.corpus._corpus, indent=2), encoding="utf-8")

    def run_cycle(self) -> dict[str, Any] | None:
        outliers = extract_log_seeds(log_dir=self.log_dir) if self.log_dir else []
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
        traces: list[RawTrace] = []

        for _ in range(self.k_replicates):
            trace = execute_in_cell(
                spec=spec,
                validated_params=dict(exp.parameters),
                budget_ms=exp.budget_ms,
                workspace_root=self.workspace_root,
                harness_tree=self.harness_tree,
            )
            traces.append(trace)

        sig0 = compute_signature(traces[0])
        novelty = self.corpus.get_novelty(exp.harness_id, sig0)
        verdict = evaluate_traces(exp, traces, novelty=novelty)

        logger.info(
            f"Cycle completed: decision={verdict.decision} score={verdict.score:.2f} novelty={verdict.novelty:.2f}"
        )

        entry = {
            "experiment_hash": exp.experiment_hash,
            "harness_id": exp.harness_id,
            "parameters": dict(exp.parameters),
            "signature": sig0,
            "score": verdict.score,
            "decision": verdict.decision,
            "k_replicates": self.k_replicates,
        }

        if verdict.decision == "promote_candidate":
            self.corpus.record(exp.harness_id, sig0)
            self._save_corpus()
            self.promoted_seeds.append(entry)
            self._save_json_list(self.promoted_seeds, self.seed_bank_path)
        elif verdict.decision == "flaky":
            self.flaky_seeds.append(entry)
            self._save_json_list(self.flaky_seeds, self.flaky_bank_path)

        return {
            "dream_id": exp.dream_id,
            "decision": verdict.decision,
            "score": verdict.score,
            "trace": traces[0],
            "k_replicates": self.k_replicates,
        }
