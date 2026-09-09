#!/usr/bin/env python3
"""
core/warden.py
Runs harnesses in isolated sub-processes with POSIX timeout traps,
probe allowlisting, and strict harness tree containment.
"""

import os
import sys
import time
import json
import signal
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Mapping, Any
from core.dream_contract import HarnessSpec, RawTrace, SecurityViolation

MAX_STDIO_BYTES = 64 * 1024


def execute_in_cell(
    spec: HarnessSpec,
    validated_params: Mapping[str, Any],
    budget_ms: int,
    workspace_root: Path,
    harness_tree: Path,
) -> RawTrace:
    resolved_binary = spec.runner_binary.resolve()
    resolved_tree = harness_tree.resolve()
    if not resolved_binary.is_relative_to(resolved_tree):
        raise SecurityViolation(
            f"Harness binary outside designated harness tree: {resolved_binary} not in {resolved_tree}"
        )

    effective_budget_ms = max(10, min(budget_ms, 5000))
    timeout_sec = effective_budget_ms / 1000.0

    workspace_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="cell_", dir=workspace_root))
    params_path = run_dir / "params.json"
    out_path = run_dir / "out.json"

    params_path.write_text(json.dumps(dict(validated_params)), encoding="utf-8")

    if resolved_binary.suffix == ".py":
        cmd = [sys.executable, "-I", str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]
    else:
        cmd = [str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]

    clean_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }

    probes_captured: dict[str, bool] = {}
    exit_code: int | None = -1
    signal_num: int | None = 0
    stdout_bytes = b""
    stderr_bytes = b""

    t_start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(run_dir),
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        stdout_raw, stderr_raw = proc.communicate(timeout=timeout_sec)
        exit_code = proc.returncode
        stdout_bytes = stdout_raw[:MAX_STDIO_BYTES]
        stderr_bytes = stderr_raw[:MAX_STDIO_BYTES]
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            stdout_raw, stderr_raw = proc.communicate(timeout=0.5)
            stdout_bytes = stdout_raw[:MAX_STDIO_BYTES]
            stderr_bytes = stderr_raw[:MAX_STDIO_BYTES]
        except Exception:
            pass
        exit_code = 124
    finally:
        wall_ms = int((time.perf_counter() - t_start) * 1000)

    if exit_code is not None:
        if exit_code < 0:
            signal_num = -exit_code
        elif exit_code > 128 and exit_code != 124:
            signal_num = exit_code - 128

    if out_path.is_file():
        try:
            raw_out = json.loads(out_path.read_text(encoding="utf-8"))
            raw_probes = raw_out.get("probes", {})
            if isinstance(raw_probes, dict):
                for k, v in raw_probes.items():
                    if k in spec.allowed_observables and isinstance(v, bool) and v is True:
                        probes_captured[k] = True
        except (OSError, json.JSONDecodeError):
            pass

    try:
        if params_path.is_file():
            params_path.unlink()
        if out_path.is_file():
            out_path.unlink()
        run_dir.rmdir()
    except OSError:
        pass

    stdout_hash = hashlib.sha256(stdout_bytes).hexdigest()
    stderr_hash = hashlib.sha256(stderr_bytes).hexdigest()

    return RawTrace(
        exit_code=exit_code,
        signal=signal_num,
        wall_ms=wall_ms,
        max_rss_kb=0,
        stdout_sha256=stdout_hash,
        stderr_sha256=stderr_hash,
        probes=probes_captured,
    )
