#!/usr/bin/env python3
"""
core/dream_daemon.py
Autonomous idle runner with K>=3 replication, flaky seed quarantine,
persistent signature corpus tracking, descriptor pinning, and hot-path validation.
"""

import os
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
from core.experiment_validator import decode_params
from core.telemetry_seed import collect_all_seeds, extract_log_seeds, write_seed_bank

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dream_daemon")

DEFAULT_K_REPLICATES = 3


def derive_expected_observable(spec: HarnessSpec) -> str:
    if spec.harness_id == "admission_gate_policy":
        return "statutory_veto_reached"
    if spec.harness_id == "process_fuzzer":
        return "admission_timeout"
    return next(iter(spec.allowed_observables)) if spec.allowed_observables else "timeout"


def compute_experiment_budget_ms(spec: HarnessSpec, params: Mapping[str, Any]) -> int:
    if spec.harness_id == "process_fuzzer":
        concurrency = int(params.get("concurrency", 1))
        timeout_s = float(params.get("timeout_s", 0.05))
        return min(10000, int(500 + (concurrency * timeout_s * 1000) * 1.5))
    return 2000


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
        audit_path: Path | None = None,
        charter_path: Path | None = None,
        k_replicates: int = DEFAULT_K_REPLICATES,
        require_isolation: bool = False,
    ):
        self.catalog = catalog
        self.workspace_root = workspace_root
        self.seed_bank_path = seed_bank_path
        self.flaky_bank_path = flaky_bank_path or seed_bank_path.parent / "flaky_seeds.json"
        self.corpus_path = corpus_path or seed_bank_path.parent / "corpus.json"
        self.llm_callable = llm_callable
        self.harness_tree = harness_tree
        self.log_dir = log_dir
        self.audit_path = audit_path
        self.charter_path = charter_path
        self.k_replicates = max(1, k_replicates)
        self.require_isolation = require_isolation

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
        outliers: list[dict[str, Any]] = []
        if self.log_dir or self.audit_path:
            log_d = self.log_dir or Path("/nonexistent/log/dir")
            audit_f = self.audit_path or Path("/nonexistent/audit.jsonl")
            outliers = collect_all_seeds(log_dir=log_d, audit_path=audit_f)

        mutation_candidates = self.promoted_seeds + self.flaky_seeds
        plan = schedule_next_dream(mutation_candidates, self.catalog, outliers)
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
            try:
                validated = decode_params(spec, plan["parameters"])
            except Exception as e:
                logger.warning(f"Hot-path parameter validation failed: {e}")
                return None

            budget = compute_experiment_budget_ms(spec, validated)
            exp = Experiment(
                dream_id=f"dream_{int(time.time()*1000)}",
                harness_id=hid,
                parameters=validated,
                expected=derive_expected_observable(spec),
                unexpected=("panic",),
                budget_ms=budget,
            )

        spec = self.catalog[exp.harness_id]
        traces: list[RawTrace] = []

        # Open pinned charter FD if specified
        charter_fd: int | None = None
        pass_fds = ()
        extra_env = {}
        if self.charter_path and self.charter_path.is_file():
            try:
                charter_fd = os.open(str(self.charter_path), os.O_RDONLY)
                pass_fds = (charter_fd,)
                extra_env["ADMISSION_GATE_CHARTER_FD"] = str(charter_fd)
            except OSError:
                pass

        try:
            for _ in range(self.k_replicates):
                trace = execute_in_cell(
                    spec=spec,
                    validated_params=dict(exp.parameters),
                    budget_ms=exp.budget_ms,
                    workspace_root=self.workspace_root,
                    harness_tree=self.harness_tree,
                    pass_fds=pass_fds,
                    extra_env=extra_env,
                    require_isolation=self.require_isolation,
                )
                traces.append(trace)
        finally:
            if charter_fd is not None:
                try:
                    os.close(charter_fd)
                except OSError:
                    pass

        sig0 = compute_signature(traces[0])
        novelty = self.corpus.get_novelty(exp.harness_id, sig0)
        verdict = evaluate_traces(exp, traces, novelty=novelty)

        # In strict isolation mode, downgrade decision if isolation wasn't established
        if self.require_isolation and not any(t.isolation.get("unshare") for t in traces):
            logger.warning("Rejecting candidate: execution was unconfined (unshare unavailable)")
            verdict = Verdict(
                decision="discard",
                score=0.0,
                novelty=0.0,
                reasons=("unconfined_execution",),
                signature=sig0,
            )

        self.corpus.record(exp.harness_id, sig0)
        self._save_corpus()

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
            "reasons": list(verdict.reasons),
            "isolation": dict(traces[0].isolation),
            "k_replicates": self.k_replicates,
        }

        if verdict.decision == "promote_candidate":
            existing = {(s["harness_id"], s["signature"]) for s in self.promoted_seeds}
            if (entry["harness_id"], entry["signature"]) not in existing:
                self.promoted_seeds.append(entry)
                self._save_json_list(self.promoted_seeds, self.seed_bank_path)
        elif verdict.decision == "flaky":
            existing_flaky = {(s["harness_id"], s["signature"]) for s in self.flaky_seeds}
            if (entry["harness_id"], entry["signature"]) not in existing_flaky:
                self.flaky_seeds.append(entry)
                self._save_json_list(self.flaky_seeds, self.flaky_bank_path)

        return {
            "dream_id": exp.dream_id,
            "decision": verdict.decision,
            "score": verdict.score,
            "trace": traces[0],
            "k_replicates": self.k_replicates,
        }
