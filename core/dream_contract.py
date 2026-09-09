#!/usr/bin/env python3
"""
core/dream_contract.py
Immutable contracts, typed observables, and frozen catalog structures.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping, Literal

Observable = Literal[
    "timeout",
    "panic",
    "veto_bypass",
    "admission_timeout",
    "statutory_veto_reached",
    "cross_tenant_leak",
]


@dataclass(frozen=True)
class ParamSpec:
    kind: Literal["int", "float"]
    lo: float
    hi: float


@dataclass(frozen=True)
class RawTrace:
    exit_code: int | None
    signal: int | None
    wall_ms: int
    max_rss_kb: int
    stdout_sha256: str
    stderr_sha256: str
    probes: Mapping[str, bool]


@dataclass(frozen=True)
class HarnessSpec:
    harness_id: str
    target_subsystem: str
    params: Mapping[str, ParamSpec]
    allowed_observables: frozenset[Observable]
    runner_binary: Path

    def __post_init__(self):
        # Enforce canonical path resolution inside dedicated harness directory
        harness_tree = Path("/opt/sovereign/harnesses").resolve()
        resolved = self.runner_binary.resolve()
        if not resolved.is_relative_to(harness_tree):
            raise ValueError(f"runner_binary {resolved} escapes sandbox root {harness_tree}")
        if not resolved.is_file():
            raise FileNotFoundError(f"runner_binary {resolved} does not exist")


@dataclass(frozen=True)
class Experiment:
    dream_id: str
    harness_id: str
    parameters: Mapping[str, int | float]
    expected: Observable
    unexpected: tuple[Observable, ...]
    budget_ms: int

    @property
    def experiment_hash(self) -> str:
        body = json.dumps(
            {
                "harness_id": self.harness_id,
                "parameters": dict(sorted(self.parameters.items())),
                "expected": self.expected,
            },
            sort_keys=True,
        )
        return sha256(body.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Verdict:
    score: float
    match: bool
    surprise: bool
    novelty: float
    signature: str
    decision: Literal["promote_candidate", "flaky", "discard"]
