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

    try:
        resolved_binary.relative_to(resolved_tree)
    except ValueError:
        raise SecurityViolation(
            f"Security violation: binary {resolved_binary} outside harness tree {resolved_tree}"
        )

    workspace_root.mkdir(parents=True, exist_ok=True)
    run_id = f"cell_{int(time.time() * 1e6)}_{os.getpid()}"
    run_dir = workspace_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)

    params_path = run_dir / "params.json"
    out_path = run_dir / "out.json"
    params_path.write_text(json.dumps(validated_params), encoding="utf-8")

    if resolved_binary.suffix == ".py":
        cmd = [sys.executable, "-I", str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]
    else:
        cmd = [str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]

    clean_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }

    timeout_sec = max(0.01, budget_ms / 1000.0)
    stdout_bytes = b""
    stderr_bytes = b""
    exit_code: int | None = None
    signal_num: int | None = None
    probes_captured: dict[str, bool] = {}

    t_start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(run_dir),
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_raw, stderr_raw = proc.communicate(timeout=timeout_sec)
        stdout_bytes = stdout_raw[:MAX_STDIO_BYTES]
        stderr_bytes = stderr_raw[:MAX_STDIO_BYTES]
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            stdout_raw, stderr_raw = proc.communicate(timeout=1.0)
            stdout_bytes = stdout_raw[:MAX_STDIO_BYTES]
            stderr_bytes = stderr_raw[:MAX_STDIO_BYTES]
        except Exception:
            pass
        exit_code = 124
        signal_num = signal.SIGKILL
    finally:
        wall_ms = int((time.perf_counter() - t_start) * 1000)

    if exit_code is not None and exit_code != 124:
        if exit_code < 0:
            signal_num = -exit_code
        elif exit_code > 128:
            signal_num = exit_code - 128

    # Skip probe ingest entirely if execution timed out
    if exit_code != 124 and out_path.is_file():
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
        wall_ms=wall_ms,
        probes=probes_captured,
        stdout_hash=stdout_hash,
        stderr_hash=stderr_hash,
        signal=signal_num,
        max_rss_kb=0,
    )
