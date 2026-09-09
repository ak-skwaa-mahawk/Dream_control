#!/usr/bin/env python3
"""
core/warden.py
Cell runner enforcing prefix checks, probe allowlisting, and process group boundaries.
"""

import os
import json
import time
import signal
import hashlib
import tempfile
import subprocess
from pathlib import Path
from core.dream_contract import HarnessSpec, RawTrace

MAX_STDIO = 64 * 1024  # 64 KB limit


def _hash_capped(data: bytes) -> str:
    return hashlib.sha256(data[:MAX_STDIO]).hexdigest()


def _empty_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "PYTHONIOENCODING": "utf-8",
    }


def _read_probes(spec: HarnessSpec, trace_file: Path) -> dict[str, bool]:
    allowed = set(spec.allowed_observables)
    try:
        raw = json.loads(trace_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    probes = raw.get("probes", {})
    return {
        k: bool(v)
        for k, v in probes.items()
        if k in allowed and isinstance(v, bool)
    }


def execute_in_cell(
    spec: HarnessSpec,
    validated_params: dict[str, int | float],
    budget_ms: int,
    workspace_root: Path,
    harness_tree: Path | None = None,
) -> RawTrace:
    # Warden checks binary paths against allowed tree
    if harness_tree is not None:
        resolved = spec.runner_binary.resolve()
        if not resolved.is_relative_to(harness_tree.resolve()):
            raise PermissionError(f"runner_binary {resolved} escapes harness tree {harness_tree}")
        if not resolved.is_file():
            raise FileNotFoundError(f"runner_binary {resolved} not found")

    workspace_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    cell_dir = Path(tempfile.mkdtemp(prefix="cell_", dir=workspace_root))
    os.chmod(cell_dir, 0o700)

    param_file = cell_dir / "params.json"
    trace_file = cell_dir / "trace.json"
    param_file.write_text(json.dumps(validated_params, sort_keys=True), encoding="utf-8")

    cmd = [
        "/usr/bin/python3", "-I",
        str(spec.runner_binary),
        "--params", str(param_file),
        "--out", str(trace_file),
    ]

    t0 = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cell_dir),
        env=_empty_env(),
        start_new_session=True,
    )

    timed_out = False
    stdout_b = b""
    stderr_b = b""

    try:
        stdout_b, stderr_b = proc.communicate(timeout=budget_ms / 1000.0)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        stdout_b, stderr_b = proc.communicate()
        exit_code = 124

    wall_ms = int((time.monotonic() - t0) * 1000)
    sig = None
    if exit_code is not None and exit_code < 0:
        sig = -exit_code
        exit_code = None

    probes = {} if timed_out else _read_probes(spec, trace_file)

    try:
        if param_file.exists():
            param_file.unlink()
        if trace_file.exists():
            trace_file.unlink()
        cell_dir.rmdir()
    except OSError:
        pass

    return RawTrace(
        exit_code=exit_code,
        signal=sig,
        wall_ms=wall_ms,
        max_rss_kb=0,
        stdout_sha256=_hash_capped(stdout_b or b""),
        stderr_sha256=_hash_capped(stderr_b or b""),
        probes=probes,
    )
