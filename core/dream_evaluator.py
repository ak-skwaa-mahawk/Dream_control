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

    MAX_CORPUS_HISTORY = 200

    def record(self, harness_id: str, sig0: str) -> None:
        if harness_id not in self._corpus:
            self._corpus[harness_id] = []
        history = self._corpus[harness_id]
        history.append(sig0)
        if len(history) > self.MAX_CORPUS_HISTORY:
            self._corpus[harness_id] = history[-self.MAX_CORPUS_HISTORY:]


def compute_signature(t: RawTrace) -> str:
    payload = {
        "exit": t.exit_code,
        "signal": t.signal,
        "probes": dict(sorted(t.probes.items())),
    }
    return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def compute_pairwise_jaccard(sets: list[set[str]]) -> float:
    if len(sets) <= 1:
        return 1.0
    pairs = 0
    total_sim = 0.0
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            s1, s2 = sets[i], sets[j]
            if not s1 and not s2:
                sim = 1.0
            else:
                sim = len(s1 & s2) / len(s1 | s2)
            total_sim += sim
            pairs += 1
    return total_sim / pairs if pairs > 0 else 1.0


def evaluate_traces(
    exp: Experiment,
    traces: Sequence[RawTrace],
    novelty: float,
    tau: float = 2.0,
    require_isolation: bool = False,
    consensus_threshold: float = 0.67,
) -> Verdict:
    if not traces:
        raise ValueError("Must supply at least one trace for evaluation.")

    primary = traces[0]
    sig0 = compute_signature(primary)
    reasons = []

    # 1. Isolation Gate
    if require_isolation:
        for t in traces:
            iso = t.isolation
            host_isolated = bool(iso.get("unshare") and iso.get("landlock") and iso.get("cgroup"))
            docker_isolated = bool(iso.get("backend") == "docker" and iso.get("capabilities_dropped"))
            if not (host_isolated or docker_isolated):
                return Verdict(
                    score=0.0,
                    match=False,
                    surprise=False,
                    novelty=novelty,
                    signature=sig0,
                    decision="discard",
                    reasons=("isolation_requirement_unmet",),
                )

    # 2. Extract Observables per Trace
    probe_sets: list[set[str]] = []
    for t in traces:
        obs = {name for name, bit in t.probes.items() if bit}
        if t.signal not in (None, 0) or (t.exit_code is not None and t.exit_code < 0):
            obs.add("panic")
        if t.exit_code == 124:
            obs.add("timeout")
        probe_sets.append(obs)

    primary_obs = probe_sets[0]
    match = exp.expected in primary_obs
    surprise = any(u in primary_obs for u in exp.unexpected)

    # 3. Strict Unexpected Observable Gate (Zero-Tolerance Security Invariant)
    unexpected_keys = set(exp.unexpected)
    for obs in probe_sets:
        triggered_unexpected = unexpected_keys.intersection(obs)
        if triggered_unexpected:
            return Verdict(
                score=0.0,
                match=match,
                surprise=True,
                novelty=novelty,
                signature=sig0,
                decision="discard",
                reasons=(f"unexpected_observable_triggered:{sorted(triggered_unexpected)}",),
            )

    # 4. Signatures & Identity Check
    signatures = [compute_signature(t) for t in traces]
    reproduced = all(s == sig0 for s in signatures)
    all_observed_expected = all(exp.expected in obs for obs in probe_sets) if exp.expected else True

    # 5. Deterministic Hard Consensus
    if reproduced:
        score = (1.0 if match else 0.0) + (2.0 if surprise else 0.0) + novelty
        if score < tau:
            decision = "discard"
        else:
            decision = "promote_candidate"
            reasons.append("novel_behavior_reproduced")
        return Verdict(
            score=score,
            match=match,
            surprise=surprise,
            novelty=novelty,
            signature=sig0,
            decision=decision,
            reasons=tuple(reasons),
        )

    # 6. Probabilistic Soft Consensus & Jaccard Flakiness Scoring
    mean_jaccard = compute_pairwise_jaccard(probe_sets)
    flakiness_score = 1.0 - mean_jaccard

    if all_observed_expected and mean_jaccard >= consensus_threshold:
        score = ((1.0 if match else 0.0) + (2.0 if surprise else 0.0) + novelty) * mean_jaccard
        if score < tau:
            decision = "discard"
        else:
            decision = "promote_soft"
            reasons.append(f"soft_consensus:mean_jaccard={mean_jaccard:.2f}")
            reasons.append(f"flakiness={flakiness_score:.2f}")
        return Verdict(
            score=score,
            match=match,
            surprise=surprise,
            novelty=novelty,
            signature=sig0,
            decision=decision,
            reasons=tuple(reasons),
        )

    # 7. Flaky Divergence
    reasons.append(f"divergent_signatures:{len(set(signatures))}")
    reasons.append(f"flakiness={flakiness_score:.2f}")
    return Verdict(
        score=0.0,
        match=match,
        surprise=surprise,
        novelty=novelty,
        signature=sig0,
        decision="flaky",
        reasons=tuple(reasons),
    )
