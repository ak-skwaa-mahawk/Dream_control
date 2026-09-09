#!/usr/bin/env python3
"""
core/dream_evaluator.py
Pure evaluation logic, bit-exact trace signatures, and corpus-frequency novelty decay.
"""

from hashlib import sha256
import json
from typing import Sequence
from core.dream_contract import Experiment, RawTrace, Verdict


class SignatureCorpus:
    """Tracks historical signatures per harness to compute frequency-based novelty decay."""

    def __init__(self):
        self._corpus: dict[str, list[str]] = {}

    def get_novelty(self, harness_id: str, sig0: str) -> float:
        history = self._corpus.get(harness_id, [])
        matches = sum(1 for s in history if s == sig0)
        return 1.0 - (matches / (1.0 + len(history)))

    def record(self, harness_id: str, sig0: str) -> None:
        if harness_id not in self._corpus:
            self._corpus[harness_id] = []
        self._corpus[harness_id].append(sig0)


def compute_signature(t: RawTrace) -> str:
    iso = getattr(t, "isolation", {}) or {}
    payload = {
        "exit": t.exit_code,
        "signal": t.signal,
        "probes": dict(sorted(t.probes.items())),
        "isolated": bool(iso.get("unshare") and iso.get("cgroup")),
    }
    return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def evaluate_traces(
    exp: Experiment,
    traces: Sequence[RawTrace],
    novelty: float,
    tau: float = 2.0,
) -> Verdict:
    if not traces:
        raise ValueError("Must supply at least one trace for evaluation.")

    primary = traces[0]
    sig0 = compute_signature(primary)

    observed = {name for name, bit in primary.probes.items() if bit}
    if primary.signal not in (None, 0) or (primary.exit_code is not None and primary.exit_code < 0):
        observed.add("panic")
    if primary.exit_code == 124:
        observed.add("timeout")

    match = exp.expected in observed
    surprise = any(u in observed for u in exp.unexpected)

    score = (1.0 if match else 0.0) + (2.0 if surprise else 0.0) + novelty
    reproduced = all(compute_signature(t) == sig0 for t in traces)

    if score < tau:
        decision = "discard"
    elif reproduced:
        decision = "promote_candidate"
    else:
        decision = "flaky"

    return Verdict(
        score=score,
        match=match,
        surprise=surprise,
        novelty=novelty,
        signature=sig0,
        decision=decision,
    )
