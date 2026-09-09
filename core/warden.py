#!/usr/bin/env python3
"""
core/warden.py
Hermetic harness runner with POSIX timeouts, cgroup v2 accounting/limits,
Linux mount/PID namespace containment, non-blocking stream drain,
and probe allowlisting.
"""

import os
import sys
import time
import json
import signal
import select
import hashlib
import subprocess
from pathlib import Path
from typing import Mapping, Any

from core.dream_contract import HarnessSpec, RawTrace, SecurityViolation

MAX_STDIO_BYTES = 64 * 1024
DEFAULT_MEM_MAX_BYTES = 128 * 1024 * 1024  # 128MB ceiling
DEFAULT_CGROUP2_ROOT = Path("/sys/fs/cgroup")


def _try_setup_cgroup(cell_id: str, mem_max: int = DEFAULT_MEM_MAX_BYTES) -> tuple[Path | None, bool]:
    if not DEFAULT_CGROUP2_ROOT.is_dir():
        return None, False

    cg_path = DEFAULT_CGROUP2_ROOT / "dream_warden" / cell_id
    try:
        cg_path.mkdir(parents=True, exist_ok=True)
        max_file = cg_path / "memory.max"
        if max_file.exists():
            max_file.write_text(str(mem_max), encoding="utf-8")
        return cg_path, True
    except (OSError, PermissionError):
        return None, False


def _read_cgroup_peak_kb(cg_path: Path | None) -> int:
    if not cg_path:
        return 0
    peak_file = cg_path / "memory.peak"
    try:
        if peak_file.is_file():
            val = int(peak_file.read_text(encoding="utf-8").strip())
            return max(0, val // 1024)
    except (OSError, ValueError):
        pass
    return 0


def _cleanup_cgroup(cg_path: Path | None) -> None:
    if not cg_path:
        return
    try:
        cg_path.rmdir()
    except OSError:
        pass


def _read_bounded_pipes(proc: subprocess.Popen, timeout_sec: float) -> tuple[bytes, bytes, bool]:
    """Reads stdout and stderr safely; drains overflow to prevent child stalls and drops closed pipes."""
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    t_start = time.perf_counter()

    for pipe in (proc.stdout, proc.stderr):
        if pipe:
            os.set_blocking(pipe.fileno(), False)

    timed_out = False
    active_pipes = [p for p in (proc.stdout, proc.stderr) if p]

    while active_pipes:
        elapsed = time.perf_counter() - t_start
        remaining = timeout_sec - elapsed
        if remaining <= 0:
            timed_out = True
            break

        rlist, _, _ = select.select(active_pipes, [], [], min(remaining, 0.05))
        for pipe in rlist:
            try:
                chunk = pipe.read(4096)
            except OSError:
                chunk = b""

            if not chunk:
                # EOF reached on this stream
                active_pipes.remove(pipe)
                continue

            if pipe is proc.stdout:
                if len(stdout_buf) < MAX_STDIO_BYTES:
                    avail = MAX_STDIO_BYTES - len(stdout_buf)
                    stdout_buf.extend(chunk[:avail])
            elif pipe is proc.stderr:
                if len(stderr_buf) < MAX_STDIO_BYTES:
                    avail = MAX_STDIO_BYTES - len(stderr_buf)
                    stderr_buf.extend(chunk[:avail])

        if proc.poll() is not None and not rlist:
            break

    return bytes(stdout_buf), bytes(stderr_buf), timed_out


def execute_in_cell(
    spec: HarnessSpec,
    validated_params: Mapping[str, Any],
    budget_ms: int,
    workspace_root: Path,
    harness_tree: Path,
    pass_fds: tuple[int, ...] = (),
    extra_env: Mapping[str, str] | None = None,
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
    try:
        os.chmod(workspace_root, 0o700)
    except OSError:
        pass

    run_id = f"cell_{int(time.time() * 1e6)}_{os.getpid()}"
    run_dir = workspace_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)

    params_path = run_dir / "params.json"
    out_path = run_dir / "out.json"
    params_path.write_text(json.dumps(validated_params), encoding="utf-8")

    if resolved_binary.suffix == ".py":
        base_cmd = [sys.executable, "-I", str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]
    else:
        base_cmd = [str(resolved_binary), "--params", str(params_path), "--out", str(out_path)]

    cmd = list(base_cmd)
    isolation_audit = {
        "unshare": False,
        "cgroup": False,
        "session": True,
    }

    unshare_bin = "/usr/bin/unshare"
    if os.path.isfile(unshare_bin) and os.access(unshare_bin, os.X_OK):
        probe = subprocess.run([unshare_bin, "-r", "--pid", "true"], capture_output=True)
        if probe.returncode == 0:
            # Enforce mount namespace isolation with private propagation
            cmd = [unshare_bin, "-r", "--pid", "--mount-proc", "--net", "--ipc", "--mount"] + base_cmd
            isolation_audit["unshare"] = True

    clean_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
    }
    if extra_env:
        clean_env.update(extra_env)

    cg_path, has_cg = _try_setup_cgroup(run_id)
    isolation_audit["cgroup"] = has_cg

    def _preexec_init():
        if has_cg and cg_path:
            try:
                (cg_path / "cgroup.procs").write_text(str(os.getpid()), encoding="utf-8")
            except OSError:
                pass

    timeout_sec = max(0.01, budget_ms / 1000.0)
    stdout_bytes = b""
    stderr_bytes = b""
    exit_code: int | None = None
    signal_num: int | None = None
    probes_captured: dict[str, bool] = {}

    t_start = time.perf_counter()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(run_dir),
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=pass_fds,
            preexec_fn=_preexec_init if has_cg else None,
        )
        stdout_bytes, stderr_bytes, timed_out = _read_bounded_pipes(proc, timeout_sec)
        if timed_out:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            exit_code = 124
            signal_num = None
        else:
            exit_code = proc.wait()
    except Exception:
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        exit_code = 124
        signal_num = None
    finally:
        wall_ms = int((time.perf_counter() - t_start) * 1000)
        if proc:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    max_rss_kb = _read_cgroup_peak_kb(cg_path) if has_cg else 0
    _cleanup_cgroup(cg_path)

    if exit_code is not None and exit_code != 124:
        if exit_code < 0:
            signal_num = -exit_code
        elif exit_code > 128:
            signal_num = exit_code - 128

    if exit_code != 124 and out_path.is_file():
        try:
            raw_out = json.loads(out_path.read_text(encoding="utf-8"))
            raw_probes = raw_out.get("probes", {})
            if isinstance(raw_probes, dict):
                # Preserve both True and False values for all declared observables
                for k in spec.allowed_observables:
                    if k in raw_probes and isinstance(raw_probes[k], bool):
                        probes_captured[k] = raw_probes[k]
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
        max_rss_kb=max_rss_kb,
        isolation=isolation_audit,
    )
