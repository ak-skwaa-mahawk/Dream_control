#!/usr/bin/env python3
"""
core/warden.py
Hermetic harness runner with POSIX timeouts, cgroup v2 accounting/limits,
Linux mount/PID namespace containment, Landlock ABI filesystem restrictions,
non-blocking stream drain, and probe allowlisting.
"""

import os
import sys
import time
import json
import signal
import select
import hashlib
import ctypes
import subprocess
from pathlib import Path
from typing import Mapping, Any

from core.dream_contract import HarnessSpec, RawTrace, SecurityViolation

MAX_STDIO_BYTES = 64 * 1024
DEFAULT_MEM_MAX_BYTES = 128 * 1024 * 1024  # 128MB ceiling
DEFAULT_CGROUP2_ROOT = Path("/sys/fs/cgroup")

# Landlock ABI constants
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

# Access rights (ABI v1)
ACCESS_FS_EXECUTE = 1 << 0
ACCESS_FS_WRITE_FILE = 1 << 1
ACCESS_FS_READ_FILE = 1 << 2
ACCESS_FS_READ_DIR = 1 << 3
ACCESS_FS_REMOVE_DIR = 1 << 4
ACCESS_FS_REMOVE_FILE = 1 << 5
ACCESS_FS_MAKE_CHAR = 1 << 6
ACCESS_FS_MAKE_DIR = 1 << 7
ACCESS_FS_MAKE_REG = 1 << 8
ACCESS_FS_MAKE_SOCK = 1 << 9
ACCESS_FS_MAKE_FIFO = 1 << 10
ACCESS_FS_MAKE_BLOCK = 1 << 11
ACCESS_FS_MAKE_SYM = 1 << 12

ACCESS_FS_RO = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
ACCESS_FS_RW = (
    ACCESS_FS_RO
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
)


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _get_syscall_numbers():
    # Syscall numbers for x86_64 and aarch64 (ARM64)
    import platform
    machine = platform.machine().lower()
    if "aarch64" in machine or "arm64" in machine:
        return 444, 445, 446  # create_ruleset, add_rule, restrict_self
    # Default to x86_64
    return 444, 445, 446


def _probe_landlock() -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        sys_create_ruleset, _, _ = _get_syscall_numbers()
        res = libc.syscall(sys_create_ruleset, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
        return res >= 1
    except Exception:
        return False


HAS_LANDLOCK = _probe_landlock()


def _apply_landlock(run_dir: Path, harness_path: Path):
    if not HAS_LANDLOCK:
        return

    libc = ctypes.CDLL(None, use_errno=True)
    sys_create_ruleset, sys_add_rule, sys_restrict_self = _get_syscall_numbers()

    attr = LandlockRulesetAttr()
    attr.handled_access_fs = ACCESS_FS_RW

    ruleset_fd = libc.syscall(sys_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        return

    try:
        # Paths to allow read-only access (interpreter, standard libs, harness binary)
        ro_paths = [
            "/usr",
            "/lib",
            "/bin",
            sys.prefix,
            str(harness_path.resolve()),
        ]
        # On Android / Termux environments
        termux_prefix = os.environ.get("PREFIX")
        if termux_prefix and os.path.exists(termux_prefix):
            ro_paths.append(termux_prefix)

        for p in ro_paths:
            if not os.path.exists(p):
                continue
            fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            try:
                path_attr = LandlockPathBeneathAttr()
                path_attr.allowed_access = ACCESS_FS_RO
                path_attr.parent_fd = fd
                libc.syscall(sys_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(path_attr), 0)
            finally:
                os.close(fd)

        # Allow full read-write access to the ephemeral cell directory only
        rw_fd = os.open(str(run_dir.resolve()), os.O_PATH | os.O_CLOEXEC)
        try:
            path_attr = LandlockPathBeneathAttr()
            path_attr.allowed_access = ACCESS_FS_RW
            path_attr.parent_fd = rw_fd
            libc.syscall(sys_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(path_attr), 0)
        finally:
            os.close(rw_fd)

        # Apply no_new_privs and enforce restrictions
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0:
            libc.syscall(sys_restrict_self, ruleset_fd, 0)
    finally:
        os.close(ruleset_fd)


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
        "landlock": bool(HAS_LANDLOCK),
        "session": True,
    }

    unshare_bin = "/usr/bin/unshare"
    if os.path.isfile(unshare_bin) and os.access(unshare_bin, os.X_OK):
        probe = subprocess.run([unshare_bin, "-r", "--pid", "true"], capture_output=True)
        if probe.returncode == 0:
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
        if HAS_LANDLOCK:
            _apply_landlock(run_dir, resolved_binary)

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
            preexec_fn=_preexec_init if (has_cg or HAS_LANDLOCK) else None,
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
