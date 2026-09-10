import base64
#!/usr/bin/env python3
"""
core/warden.py
Hermetic harness runner with POSIX timeouts, cgroup v2 accounting/limits,
Linux mount/PID namespace containment (--fork), attested Landlock ABI restrictions,
strict env allowlisting, and probe filtering.
"""

import os
import sys
import time
import json
import signal
import select
import hashlib
import ctypes
import platform
import subprocess
import shutil
import uuid
from pathlib import Path
from typing import Protocol, runtime_checkable, Mapping, Any

from core.dream_contract import HarnessSpec, RawTrace, SecurityViolation

MAX_STDIO_BYTES = 64 * 1024
DEFAULT_MEM_MAX_BYTES = 128 * 1024 * 1024  # 128MB ceiling
DEFAULT_CGROUP2_ROOT = Path("/sys/fs/cgroup")
DEFAULT_MEM_MAX_BYTES = 128 * 1024 * 1024  # 128MB hard ceiling
DEFAULT_MEM_HIGH_BYTES = 96 * 1024 * 1024  # 96MB proactive throttling threshold
DEFAULT_PIDS_MAX = 32                      # Strict anti-fork-bomb ceiling
DEFAULT_CPU_MAX_SPEC = "50000 100000"     # 0.5 core quota (50ms / 100ms)
HARD_MAX_BUDGET_MS = 5000  # Universal warden ceiling

ALLOWED_EXTRA_ENV = frozenset([
    "ADMISSION_GATE_CHARTER_FD",
    "ADMISSION_GATE_SOCK_FD",
])

# Landlock ABI constants
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

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

ALL_HANDLED_FS = (
    ACCESS_FS_RW
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_SYM
)


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _get_landlock_syscall_numbers() -> tuple[int, int, int]:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return 444, 445, 446
    if m in ("aarch64", "arm64"):
        return 444, 445, 446
    if m.startswith("riscv"):
        return 444, 445, 446
    if m in ("i386", "i686"):
        return 444, 445, 446
    return 444, 445, 446


def _probe_landlock_safe() -> bool:
    sys_create, _, _ = _get_landlock_syscall_numbers()
    probe_code = (
        "import ctypes\n"
        "try:\n"
        "    libc = ctypes.CDLL(None)\n"
        f"    res = libc.syscall({sys_create}, None, 0, 1)\n"
        "    exit(0 if res >= 1 else 1)\n"
        "except Exception:\n"
        "    exit(1)\n"
    )
    try:
        res = subprocess.run(
            [sys.executable, "-c", probe_code],
            capture_output=True,
            timeout=1.0,
        )
        return res.returncode == 0
    except Exception:
        return False


HAS_LANDLOCK = _probe_landlock_safe()


def _apply_landlock(run_dir: Path, harness_path: Path) -> bool:
    if not HAS_LANDLOCK:
        return False

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        sys_create, sys_add, sys_restrict = _get_landlock_syscall_numbers()

        attr = LandlockRulesetAttr()
        attr.handled_access_fs = ALL_HANDLED_FS

        ruleset_fd = libc.syscall(sys_create, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if ruleset_fd < 0:
            return False

        try:
            ro_paths = [
                "/usr",
                "/lib",
                "/bin",
                sys.prefix,
                str(harness_path.resolve()),
            "/proc",
            "/dev/urandom",
            "/dev/random",
            "/dev/null",
            ]
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
                    if libc.syscall(sys_add, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(path_attr), 0) < 0:
                        return False
                finally:
                    os.close(fd)

            rw_fd = os.open(str(run_dir.resolve()), os.O_PATH | os.O_CLOEXEC)
            try:
                path_attr = LandlockPathBeneathAttr()
                path_attr.allowed_access = ACCESS_FS_RW
                path_attr.parent_fd = rw_fd
                if libc.syscall(sys_add, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(path_attr), 0) < 0:
                    return False
            finally:
                os.close(rw_fd)

            if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                return False
            if libc.syscall(sys_restrict, ruleset_fd, 0) != 0:
                return False
            return True
        finally:
            os.close(ruleset_fd)
    except Exception:
        return False


def _try_setup_cgroup(
    cell_id: str,
    mem_max: int = DEFAULT_MEM_MAX_BYTES,
    mem_high: int = DEFAULT_MEM_HIGH_BYTES,
    pids_max: int = DEFAULT_PIDS_MAX,
    cpu_max_spec: str = DEFAULT_CPU_MAX_SPEC,
) -> tuple[Path | None, bool]:
    if not DEFAULT_CGROUP2_ROOT.is_dir():
        return None, False

    cg_path = DEFAULT_CGROUP2_ROOT / "dream_warden" / cell_id
    try:
        cg_path.mkdir(parents=True, exist_ok=True)

        high_file = cg_path / "memory.high"
        if high_file.exists():
            high_file.write_text(str(mem_high), encoding="utf-8")

        max_file = cg_path / "memory.max"
        if max_file.exists():
            max_file.write_text(str(mem_max), encoding="utf-8")

        pids_file = cg_path / "pids.max"
        if pids_file.exists():
            pids_file.write_text(str(pids_max), encoding="utf-8")

        cpu_file = cg_path / "cpu.max"
        if cpu_file.exists():
            cpu_file.write_text(cpu_max_spec, encoding="utf-8")

        return cg_path, True
    except (OSError, PermissionError):
        return None, False


def _read_cgroup_memory_events(cg_path: Path | None) -> dict[str, int]:
    events: dict[str, int] = {}
    if not cg_path:
        return events
    events_file = cg_path / "memory.events"
    try:
        if events_file.is_file():
            for line in events_file.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split()
                if len(parts) == 2 and parts[1].isdigit():
                    events[parts[0]] = int(parts[1])
    except (OSError, ValueError):
        pass
    return events


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
        kill_file = cg_path / "cgroup.kill"
        if kill_file.is_file():
            try:
                kill_file.write_text("1", encoding="utf-8")
            except OSError:
                pass
        for _ in range(5):
            try:
                cg_path.rmdir()
                break
            except OSError:
                time.sleep(0.01)
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


def _execute_host_landlock(
    spec: HarnessSpec,
    validated_params: Mapping[str, Any],
    budget_ms: int,
    workspace_root: Path,
    harness_tree: Path,
    pass_fds: tuple[int, ...] = (),
    extra_env: Mapping[str, str] | None = None,
    require_isolation: bool = False,
) -> RawTrace:
    resolved_binary = spec.runner_binary.resolve()
    resolved_tree = harness_tree.resolve()

    try:
        resolved_binary.relative_to(resolved_tree)
    except ValueError:
        raise SecurityViolation(
            f"Security violation: binary {resolved_binary} outside harness tree {resolved_tree}"
        )

    # Universal budget ceiling
    effective_budget_ms = min(budget_ms, HARD_MAX_BUDGET_MS)

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
        "landlock": False,
        "session": True,
    }

    unshare_bin = "/usr/bin/unshare"
    has_unshare = False
    if os.path.isfile(unshare_bin) and os.access(unshare_bin, os.X_OK):
        probe = subprocess.run([unshare_bin, "-r", "--fork", "--pid", "true"], capture_output=True)
        if probe.returncode == 0:
            # Probe if unshare supports cgroup namespace flag
            cg_flag = ["--cgroup"] if subprocess.run([unshare_bin, "--help"], capture_output=True).stdout.find(b"--cgroup") != -1 else []
            cmd = [unshare_bin, "-r", "--fork", "--pid", "--mount-proc", "--net", "--ipc", "--uts", "--mount"] + cg_flag + base_cmd
            has_unshare = True
            isolation_audit["unshare"] = True

    cg_path, has_cg = _try_setup_cgroup(run_id)
    isolation_audit["cgroup"] = has_cg

    # Fail closed pre-launch if strict isolation is mandated
    if require_isolation and not (has_unshare and HAS_LANDLOCK and has_cg):
        try:
            params_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)
            run_dir.rmdir()
        except OSError:
            pass
        missing = [k for k, v in [("unshare", has_unshare), ("landlock", HAS_LANDLOCK), ("cgroup", has_cg)] if not v]
        raise SecurityViolation(f"Host environment failed required isolation guarantees: {missing}")

    clean_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
    }
    # Enforce strict extra_env allowlist
    if extra_env:
        for k, v in extra_env.items():
            if k in ALLOWED_EXTRA_ENV:
                clean_env[k] = v

    status_r, status_w = os.pipe()

    def _preexec_init():
        try:
            if has_cg and cg_path:
                try:
                    (cg_path / "cgroup.procs").write_text(str(os.getpid()), encoding="utf-8")
                except OSError:
                    pass

            ll_ok = False
            if HAS_LANDLOCK:
                ll_ok = _apply_landlock(run_dir, resolved_binary)
            os.write(status_w, b"1" if ll_ok else b"0")
        except Exception:
            os.write(status_w, b"0")
        finally:
            try:
                os.close(status_w)
            except OSError:
                pass

    timeout_sec = max(0.01, effective_budget_ms / 1000.0)
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
            preexec_fn=_preexec_init,
        )
        os.close(status_w)

        try:
            status_data = os.read(status_r, 1)
            isolation_audit["landlock"] = (status_data == b"1")
        except OSError:
            isolation_audit["landlock"] = False
        finally:
            os.close(status_r)

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
        try:
            os.close(status_r)
        except OSError:
            pass
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
    cg_events = _read_cgroup_memory_events(cg_path) if has_cg else {}
    if cg_events:
        isolation_audit["cgroup_events"] = cg_events
        if cg_events.get("high", 0) > 0:
            isolation_audit["memory_throttled"] = True
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


@runtime_checkable
class CellBackend(Protocol):
    """Abstract boundary protocol for hermetic execution cell backends."""

    def execute(
        self,
        spec: HarnessSpec,
        validated_params: dict[str, Any],
        budget_ms: int,
        workspace_root: Path,
        harness_tree: Path,
        pass_fds: tuple[int, ...] = (),
        extra_env: Mapping[str, str] | None = None,
        require_isolation: bool = False,
    ) -> RawTrace:
        ...


class HostLandlockBackend:
    """Host-level isolation engine using Linux namespaces, cgroups v2, and Landlock ABI."""

    def execute(
        self,
        spec: HarnessSpec,
        validated_params: dict[str, Any],
        budget_ms: int,
        workspace_root: Path,
        harness_tree: Path,
        pass_fds: tuple[int, ...] = (),
        extra_env: Mapping[str, str] | None = None,
        require_isolation: bool = False,
    ) -> RawTrace:
        return _execute_host_landlock(
            spec=spec,
            validated_params=validated_params,
            budget_ms=budget_ms,
            workspace_root=workspace_root,
            harness_tree=harness_tree,
            pass_fds=pass_fds,
            extra_env=extra_env,
            require_isolation=require_isolation,
        )


class DockerCellBackend:
    """Container-level isolation engine executing harnesses inside hermetic OCI containers."""

    def __init__(
        self,
        image: str = "python:3.14-slim",
        docker_bin: str = "docker",
        memory_limit: str = "256m",
        pids_limit: int = 64,
        cpus: float = 0.5,
    ):
        self.image = image
        self.docker_bin = docker_bin
        self.memory_limit = memory_limit
        self.pids_limit = pids_limit
        self.cpus = cpus

    def is_available(self) -> bool:
        bin_path = shutil.which(self.docker_bin)
        if not bin_path:
            return False
        try:
            res = subprocess.run(
                [bin_path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
            return res.returncode == 0
        except Exception:
            return False

    def execute(
        self,
        spec: HarnessSpec,
        validated_params: dict[str, Any],
        budget_ms: int,
        workspace_root: Path,
        harness_tree: Path,
        pass_fds: tuple[int, ...] = (),
        extra_env: Mapping[str, str] | None = None,
        require_isolation: bool = False,
    ) -> RawTrace:
        available = self.is_available()
        if require_isolation and not available:
            raise SecurityViolation(
                "Host environment failed required Docker isolation guarantees: docker daemon unavailable"
            )

        workspace_root = workspace_root.resolve()
        harness_tree = harness_tree.resolve()
        target_path = (harness_tree / spec.runner_binary.name).resolve()

        if not str(target_path).startswith(str(harness_tree)):
            raise SecurityViolation("Target binary escapes designated harness tree")

        run_id = f"cell_docker_{uuid.uuid4().hex[:8]}"
        cell_dir = workspace_root / run_id
        cell_dir.mkdir(parents=True, exist_ok=True)

        params_file = cell_dir / "params.json"
        out_file = cell_dir / "out.json"
        params_file.write_text(json.dumps(validated_params), encoding="utf-8")

        # Translate file descriptor inheritance into container-safe inline payload
        container_env = dict(extra_env or {})
        charter_fd_str = container_env.pop("ADMISSION_GATE_CHARTER_FD", None)
        if charter_fd_str and charter_fd_str.isdigit() and "ADMISSION_GATE_CHARTER_PAYLOAD" not in container_env:
            try:
                fd = int(charter_fd_str)
                # Read from host fd without closing it
                with open(fd, "r", encoding="utf-8", closefd=False) as f:
                    pos = f.tell() if f.seekable() else 0
                    if f.seekable():
                        f.seek(0)
                    raw_data = f.read()
                    if f.seekable():
                        f.seek(pos)
                    b64_payload = base64.b64encode(raw_data.encode("utf-8")).decode("ascii")
                    container_env["ADMISSION_GATE_CHARTER_PAYLOAD"] = b64_payload
            except Exception:
                pass
        elif pass_fds and "ADMISSION_GATE_CHARTER_PAYLOAD" not in container_env:
            for fd in pass_fds:
                try:
                    with open(fd, "r", encoding="utf-8", closefd=False) as f:
                        if f.seekable():
                            f.seek(0)
                        raw_data = f.read()
                        b64_payload = base64.b64encode(raw_data.encode("utf-8")).decode("ascii")
                        container_env["ADMISSION_GATE_CHARTER_PAYLOAD"] = b64_payload
                        break
                except Exception:
                    continue

        docker_cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--memory={self.memory_limit}",
            f"--pids-limit={self.pids_limit}",
            f"--cpus={self.cpus}",
            "-v", f"{cell_dir}:/workspace:rw",
            "-v", f"{harness_tree}:/harnesses:ro",
            "-w", "/workspace",
        ]

        for k, v in container_env.items():
            docker_cmd.extend(["-e", f"{k}={v}"])

        docker_cmd.extend([
            self.image,
            "python3",
            f"/harnesses/{target_path.name}",
            "--params", "/workspace/params.json",
            "--out", "/workspace/out.json",
        ])

        start_time = time.monotonic()
        timed_out = False
        exit_code = 0
        stdout_raw = ""
        stderr_raw = ""

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=max(0.1, budget_ms / 1000.0),
            )
            exit_code = proc.returncode
            stdout_raw = (proc.stdout or "")[:MAX_STDIO_BYTES]
            stderr_raw = (proc.stderr or "")[:MAX_STDIO_BYTES]
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stdout_raw = (exc.stdout.decode() if isinstance(exc.stdout, bytes) else str(exc.stdout or ""))[:MAX_STDIO_BYTES]
            stderr_raw = (exc.stderr.decode() if isinstance(exc.stderr, bytes) else str(exc.stderr or ""))[:MAX_STDIO_BYTES]
        except FileNotFoundError:
            if require_isolation:
                raise SecurityViolation("Docker binary not found under required isolation")
            exit_code = 127
            stderr_raw = "Docker binary unavailable"
        finally:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

        observables: dict[str, Any] = {}
        if out_file.exists():
            try:
                raw_out = json.loads(out_file.read_text(encoding="utf-8"))
                observables = raw_out.get("probes", {})
            except Exception:
                pass

        if timed_out:
            observables["timeout"] = True

        shutil.rmtree(cell_dir, ignore_errors=True)

        import hashlib
        stdout_hash = hashlib.sha256(stdout_raw.encode("utf-8", errors="replace")).hexdigest()
        stderr_hash = hashlib.sha256(stderr_raw.encode("utf-8", errors="replace")).hexdigest()

        return RawTrace(
            exit_code=exit_code,
            wall_ms=elapsed_ms,
            probes=observables,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            signal=None,
            max_rss_kb=0,
            isolation={
                "backend": "docker",
                "container_image": self.image,
                "network_isolated": True,
                "capabilities_dropped": True,
                "available": available,
            },
        )


def execute_in_cell(
    spec: HarnessSpec,
    validated_params: dict[str, Any],
    budget_ms: int,
    workspace_root: Path,
    harness_tree: Path,
    pass_fds: tuple[int, ...] = (),
    extra_env: Mapping[str, str] | None = None,
    require_isolation: bool = False,
    backend: CellBackend | str | None = None,
) -> RawTrace:
    """Dispatches execution to a configured CellBackend (defaults to HostLandlockBackend)."""
    if backend is None:
        env_backend = os.environ.get("WARDEN_BACKEND", "host").lower()
        if env_backend == "docker":
            selected_backend: CellBackend = DockerCellBackend()
        else:
            selected_backend = HostLandlockBackend()
    elif isinstance(backend, str):
        if backend.lower() == "docker":
            selected_backend = DockerCellBackend()
        elif backend.lower() in ("host", "landlock"):
            selected_backend = HostLandlockBackend()
        else:
            raise ValueError(f"Unknown cell backend name: {backend}")
    else:
        selected_backend = backend

    return selected_backend.execute(
        spec=spec,
        validated_params=validated_params,
        budget_ms=budget_ms,
        workspace_root=workspace_root,
        harness_tree=harness_tree,
        pass_fds=pass_fds,
        extra_env=extra_env,
        require_isolation=require_isolation,
    )
