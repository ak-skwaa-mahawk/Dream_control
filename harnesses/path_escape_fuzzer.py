#!/usr/bin/env python3
"""
harnesses/path_escape_fuzzer.py
Specialized fuzzing harness for validating Landlock boundary restrictions,
symlink escaping, /proc traversal, and path sanitization.
"""

import json
import os
from pathlib import Path
import sys

ALLOWED_OBSERVABLES = {
    "intra_vires_confirmed",
    "statutory_veto_reached",
    "ultra_vires_detected",
    "path_traversal_blocked",
    "symlink_containment_verified",
}


def run_harness():
    params_file = Path("params.json")
    if not params_file.exists():
        print("params.json not found", file=sys.stderr)
        sys.exit(1)

    try:
        with params_file.open("r", encoding="utf-8") as f:
            params = json.load(f)
    except Exception as e:
        print(f"Error reading params: {e}", file=sys.stderr)
        sys.exit(1)

    target_path_str = str(params.get("target_path", "/etc/passwd"))
    mode = str(params.get("mode", "read"))
    use_symlink = bool(params.get("use_symlink", False))
    null_byte_inject = bool(params.get("null_byte_inject", False))
    workspace_dir = Path.cwd().resolve()

    if null_byte_inject:
        target_path_str = target_path_str + "\x00.txt"

    probes = {
        "workspace_root": str(workspace_dir),
        "target_requested": target_path_str,
        "escape_attempted": 1,
        "sandbox_enforced": 0,
    }

    test_target = target_path_str
    if use_symlink:
        link_path = workspace_dir / "fuzz_symlink_test"
        try:
            if link_path.is_symlink() or link_path.exists():
                link_path.unlink()
            os.symlink(target_path_str, link_path)
            test_target = str(link_path)
            probes["symlink_created"] = 1
        except (PermissionError, OSError) as e:
            probes["symlink_creation_failed"] = 1
            # OS / Landlock blocked symlink creation to arbitrary target
            out = {
                "signal": "statutory_veto_reached",
                "probes": probes,
                "detail": f"Symlink creation blocked: {e}",
            }
            write_output(out)
            sys.exit(0)

    # Attempt to open/read target
    try:
        if mode == "write":
            with open(test_target, "w", encoding="utf-8") as f:
                f.write("fuzz_escape_probe\n")
        else:
            with open(test_target, "r", encoding="utf-8", errors="replace") as f:
                _ = f.read(64)

        # If we succeeded, check if the resolved path was legitimately inside workspace
        try:
            resolved = Path(test_target).resolve()
            is_inside = (resolved == workspace_dir or workspace_dir in resolved.parents)
        except Exception:
            is_inside = False

        if is_inside:
            probes["sandbox_enforced"] = 1
            out = {
                "signal": "intra_vires_confirmed",
                "probes": probes,
                "detail": "Path resolution remained inside workspace subtree",
            }
        else:
            probes["boundary_violated"] = 1
            out = {
                "signal": "ultra_vires_detected",
                "probes": probes,
                "detail": f"Path escape succeeded: accessed {resolved}",
            }

    except (PermissionError, FileNotFoundError, OSError) as e:
        # Landlock, permissions, or system boundaries held
        probes["sandbox_enforced"] = 1
        out = {
            "signal": "statutory_veto_reached",
            "probes": probes,
            "detail": f"Access blocked by sandbox boundary: {e}",
        }

    write_output(out)
    sys.exit(0)


def write_output(data: dict):
    # Ensure signal is strictly within allowed observables
    sig = data.get("signal", "statutory_veto_reached")
    if sig not in ALLOWED_OBSERVABLES:
        data["signal"] = "statutory_veto_reached"

    with open("out.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    run_harness()
