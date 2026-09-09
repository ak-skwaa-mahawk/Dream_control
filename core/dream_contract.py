HARD_MAX_BUDGET_MS: int = 5000
#!/usr/bin/env python3
"""
core/dream_contract.py
Immutable data structures and strict typing definitions for Dream_control.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Mapping, Any

Observable = Literal[
    "veto",
    "timeout",
    "intra_vires",
    "statutory_veto_reached",
    "ultra_vires_detected",
    "intra_vires_confirmed",
    "admission_timeout",
    "panic",
    "drift",
    "cross_tenant_leak",
]


class SecurityViolation(PermissionError):
    """Raised when harness execution violates tree boundary or containment invariants."""
    pass


@dataclass(frozen=True)
class ParamSpec:
    kind: Literal["int", "float", "str"]
    lo: float
    hi: float


@dataclass(frozen=True)
class HarnessSpec:
    harness_id: str
    target_subsystem: str
    params: Mapping[str, ParamSpec]
    allowed_observables: frozenset[Observable]
    runner_binary: Path


@dataclass(frozen=True)
class RawTrace:
    exit_code: int | None
    wall_ms: int
    probes: Mapping[str, bool]
    stdout_hash: str
    stderr_hash: str
    signal: int | None = None
    max_rss_kb: int = 0
    isolation: Mapping[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class Experiment:
    dream_id: str
    harness_id: str
    parameters: Mapping[str, Any]
    expected: Observable
    unexpected: tuple[Observable, ...]
    budget_ms: int

    @property
    def experiment_hash(self) -> str:
        import hashlib
        import json
        payload = {
            "harness_id": self.harness_id,
            "parameters": self.parameters,
            "expected": self.expected,
            "unexpected": sorted(list(self.unexpected)),
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:16]


@dataclass(frozen=True)
class Verdict:
    decision: Literal["promote_candidate", "discard", "flaky"]
    score: float
    novelty: float
    reasons: tuple[str, ...] = ()
    match: bool = False
    surprise: bool = False
    signature: str = ""
