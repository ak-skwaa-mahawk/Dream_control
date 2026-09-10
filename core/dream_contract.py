#!/usr/bin/env python3
"""

HARD_MAX_BUDGET_MS: int = 5000

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
    "socket_bound",
    "ancillary_passed",
    "abstract_leaked",
    "descriptor_vetoed",
    "socket_truncated",
    "connection_refused",
    "permission_denied",
    "protocol_error",
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

from enum import Enum


class CharterTransportType(str, Enum):
    FD_INHERIT = "fd"
    ENV_INLINE = "env_inline"
    SOCKET_STREAM = "socket"

ADMISSION_GATE_SPEC = HarnessSpec(
    harness_id="admission_gate_policy",
    target_subsystem="admission_gate",
    params={
        "command": ParamSpec(kind="str", lo=1.0, hi=256.0),
        "target_path": ParamSpec(kind="str", lo=1.0, hi=256.0),
    },
    allowed_observables=frozenset({
        "intra_vires_confirmed",
        "statutory_veto_reached",
        "ultra_vires_detected",
    }),
    runner_binary=Path("harnesses/admission_gate_harness.py"),
)

PROCESS_FUZZER_SPEC = HarnessSpec(
    harness_id="process_fuzzer",
    target_subsystem="process_lifecycle",
    params={
        "concurrency": ParamSpec(kind="int", lo=1.0, hi=32.0),
        "timeout_s": ParamSpec(kind="float", lo=0.001, hi=5.0),
    },
    allowed_observables=frozenset({
        "intra_vires_confirmed",
        "admission_timeout",
        "statutory_veto_reached",
    }),
    runner_binary=Path("harnesses/process_fuzzer.py"),
)

PATH_ESCAPE_SPEC = HarnessSpec(
    harness_id="path_escape_fuzzer",
    target_subsystem="filesystem_isolation",
    params={
        "target_path": ParamSpec(kind="str", lo=1.0, hi=256.0),
        "mode": ParamSpec(kind="str", lo=1.0, hi=16.0),
        "use_symlink": ParamSpec(kind="int", lo=0.0, hi=1.0),
        "null_byte_inject": ParamSpec(kind="int", lo=0.0, hi=1.0),
    },
    allowed_observables=frozenset({
        "intra_vires_confirmed",
        "statutory_veto_reached",
        "ultra_vires_detected",
        "path_traversal_blocked",
        "symlink_containment_verified",
    }),
    runner_binary=Path("harnesses/path_escape_fuzzer.py"),
)

UNIX_SOCK_SPEC = HarnessSpec(
    harness_id="unix_sock_fuzzer",
    target_subsystem="ipc_socket_cell",
    params={
        "payload_len": ParamSpec(kind="int", lo=0.0, hi=65536.0),
        "use_abstract": ParamSpec(kind="int", lo=0.0, hi=1.0),
        "pass_descriptor": ParamSpec(kind="int", lo=0.0, hi=1.0),
    },
    allowed_observables=frozenset({
        "socket_bound",
        "ancillary_passed",
        "abstract_leaked",
        "descriptor_vetoed",
        "socket_truncated",
        "connection_refused",
        "permission_denied",
        "protocol_error",
    }),
    runner_binary=Path("harnesses/unix_sock_fuzzer.py"),
)

DEFAULT_CATALOG: dict[str, HarnessSpec] = {
    "unix_sock_fuzzer": UNIX_SOCK_SPEC,
    "admission_gate_policy": ADMISSION_GATE_SPEC,
    "process_fuzzer": PROCESS_FUZZER_SPEC,
    "path_escape_fuzzer": PATH_ESCAPE_SPEC,
}
