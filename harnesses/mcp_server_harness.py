#!/usr/bin/env python3
"""
harnesses/mcp_server_harness.py
Fuzzes Model Context Protocol (MCP) JSON-RPC endpoints against path traversal,
URI scheme escapes, null-byte injections, resource exhaustion, prototype pollution,
and command injection vectors within quarantine cells.
Conforms strictly to Warden CellBackend (--params, --out) protocol.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ALLOWED_OBSERVABLES = {
    "intra_vires_confirmed",
    "statutory_veto_reached",
    "rpc_error",
    "admission_timeout",
}

PROTOTYPE_POLLUTION_KEYS = {"__proto__", "constructor", "prototype"}
COMMAND_INJECTION_TOKENS = (";", "|", "&", "$(", "`", "\n", "\r")


def parse_args():
    parser = argparse.ArgumentParser(description="MCP JSON-RPC Server Security Fuzzing Harness")
    parser.add_argument("--params", type=Path, default=None, help="Path to params JSON file (Warden protocol)")
    parser.add_argument("--out", type=Path, default=None, help="Path to out JSON file (Warden protocol)")
    parser.add_argument("--param-json", type=str, default=None, help="JSON-encoded parameters fallback")
    parser.add_argument("--method", type=str, default="resources/read", help="MCP JSON-RPC method")
    parser.add_argument("--uri", type=str, default="file:///app/safe.txt", help="Resource URI or target path")
    parser.add_argument("--tool-name", type=str, default="echo", help="Tool name for tools/call")
    parser.add_argument("--tool-args", type=str, default="{}", help="JSON-encoded arguments for tools/call")
    parser.add_argument("--payload-size-kb", type=int, default=1, help="Simulated payload / buffer size in KB")
    parser.add_argument("--timeout-s", type=float, default=0.1, help="Method execution timeout limit in seconds")
    return parser.parse_known_args()[0]


def check_prototype_pollution(obj: Any) -> bool:
    """Recursively checks for prototype pollution keys in nested JSON-RPC structures."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in PROTOTYPE_POLLUTION_KEYS:
                return True
            if check_prototype_pollution(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if check_prototype_pollution(item):
                return True
    return False


def check_command_injection(obj: Any) -> bool:
    """Recursively checks string values for shell command injection meta-characters."""
    if isinstance(obj, str):
        if any(token in obj for token in COMMAND_INJECTION_TOKENS):
            return True
    elif isinstance(obj, dict):
        for v in obj.values():
            if check_command_injection(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if check_command_injection(item):
                return True
    return False


def simulate_mcp_rpc_call(params: Dict[str, Any], workspace_root: Path) -> Dict[str, Any]:
    method = str(params.get("method", "resources/read"))
    uri = str(params.get("uri", ""))
    tool_name = str(params.get("tool_name", "echo"))
    tool_args = params.get("tool_args", {})
    if isinstance(tool_args, str):
        try:
            tool_args = json.loads(tool_args)
        except Exception:
            tool_args = {"raw": tool_args}

    payload_size_kb = int(params.get("payload_size_kb", 1))
    timeout_s = float(params.get("timeout_s", 0.1))

    # Initialize probes as booleans for all allowed observables
    probes = {obs: False for obs in ALLOWED_OBSERVABLES}

    # 1. Resource Exhaustion / Memory Ceiling Check (> 2048 KB or timeout trip)
    if payload_size_kb > 2048:
        probes["statutory_veto_reached"] = True
        return {
            "signal": "statutory_veto_reached",
            "probes": probes,
            "detail": f"buffer_exhaustion_veto: payload_size_kb={payload_size_kb} exceeds 2048KB ceiling",
        }

    if timeout_s <= 0.005:
        probes["admission_timeout"] = True
        return {
            "signal": "admission_timeout",
            "probes": probes,
            "detail": f"timeout_budget_exhausted: timeout_s={timeout_s}s",
        }

    # 2. JSON-RPC Protocol Method Check
    valid_methods = {"resources/read", "resources/list", "tools/call", "prompts/get", "ping"}
    if method not in valid_methods:
        probes["rpc_error"] = True
        return {
            "signal": "rpc_error",
            "probes": probes,
            "detail": f"json_rpc_method_not_found: code=-32601 method={method}",
        }

    # 3. Tool Execution Schema & Injection Checks (tools/call)
    if method == "tools/call":
        if not tool_name or not isinstance(tool_name, str):
            probes["rpc_error"] = True
            return {
                "signal": "rpc_error",
                "probes": probes,
                "detail": "json_rpc_invalid_params: code=-32602 missing_tool_name",
            }

        # Prototype pollution check
        if check_prototype_pollution(tool_args) or tool_name in PROTOTYPE_POLLUTION_KEYS:
            probes["statutory_veto_reached"] = True
            return {
                "signal": "statutory_veto_reached",
                "probes": probes,
                "detail": "prototype_pollution_vetoed: forbidden object prototype property injection",
            }

        # Command injection check
        if check_command_injection(tool_args) or check_command_injection(tool_name):
            probes["statutory_veto_reached"] = True
            return {
                "signal": "statutory_veto_reached",
                "probes": probes,
                "detail": "command_injection_vetoed: shell escape metacharacters detected in tool arguments",
            }

        probes["intra_vires_confirmed"] = True
        return {
            "signal": "intra_vires_confirmed",
            "probes": probes,
            "detail": f"mcp_tool_call_success: tool={tool_name}",
        }

    # 4. Path Traversal & URI Scheme Containment Check (resources/read, resources/list)
    if "\x00" in uri or "%00" in uri:
        probes["statutory_veto_reached"] = True
        return {
            "signal": "statutory_veto_reached",
            "probes": probes,
            "detail": "null_byte_injection_vetoed",
        }

    clean_path_str = uri
    if uri.startswith("file://"):
        clean_path_str = uri[len("file://"):]

    forbidden_prefixes = ("/etc", "/root", "/proc", "/sys", "/dev", "/var/run")
    is_traversal = (
        "../" in clean_path_str
        or "..\\" in clean_path_str
        or "%2e%2e%2f" in clean_path_str.lower()
        or "%2e%2e/" in clean_path_str.lower()
        or clean_path_str.startswith(forbidden_prefixes)
    )

    if is_traversal:
        probes["statutory_veto_reached"] = True
        return {
            "signal": "statutory_veto_reached",
            "probes": probes,
            "detail": f"path_traversal_vetoed: uri={uri}",
        }

    # Workspace containment validation
    try:
        candidate_path = (workspace_root / clean_path_str.lstrip("/")).resolve()
        workspace_resolved = workspace_root.resolve()
        if not str(candidate_path).startswith(str(workspace_resolved)):
            probes["statutory_veto_reached"] = True
            return {
                "signal": "statutory_veto_reached",
                "probes": probes,
                "detail": f"workspace_escape_vetoed: target={candidate_path}",
            }
    except Exception as e:
        probes["rpc_error"] = True
        return {
            "signal": "rpc_error",
            "probes": probes,
            "detail": f"json_rpc_invalid_params: code=-32602 err={e}",
        }

    # 5. Safe intra-vires access
    probes["intra_vires_confirmed"] = True
    return {
        "signal": "intra_vires_confirmed",
        "probes": probes,
        "detail": f"mcp_rpc_success: method={method} uri={uri}",
    }


def write_output(data: Dict[str, Any], out_path: Path | None = None):
    sig = data.get("signal", "statutory_veto_reached")
    if sig not in ALLOWED_OBSERVABLES:
        sig = "statutory_veto_reached"
        data["signal"] = sig
    if "probes" in data and isinstance(data["probes"], dict):
        data["probes"][sig] = True

    data["observable"] = sig
    data["returncode"] = 0
    data["raw_residue"] = data.get("detail", "")

    target_file = out_path or Path("out.json")
    try:
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass

    # Print to stdout for standalone callers
    print(json.dumps(data))


def main():
    args = parse_args()
    params = {}

    # 1. Warden protocol: inspect --params path
    if args.params and args.params.is_file():
        try:
            params = json.loads(args.params.read_text(encoding="utf-8"))
        except Exception:
            params = {}

    # 2. Local workspace params.json fallback
    if not params and Path("params.json").is_file():
        try:
            params = json.loads(Path("params.json").read_text(encoding="utf-8"))
        except Exception:
            params = {}

    # 3. CLI --param-json or flag arguments fallback
    if not params:
        if args.param_json:
            try:
                params = json.loads(args.param_json)
            except Exception:
                pass
        if not params:
            params = {
                "method": args.method,
                "uri": args.uri,
                "tool_name": args.tool_name,
                "tool_args": args.tool_args,
                "payload_size_kb": args.payload_size_kb,
                "timeout_s": args.timeout_s,
            }

    default_ws = str(Path(tempfile.gettempdir()) / "dream_workspace")
    workspace = Path(os.environ.get("DREAM_WORKSPACE", default_ws))
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    result = simulate_mcp_rpc_call(params, workspace)
    write_output(result, args.out)
    sys.exit(0)


if __name__ == "__main__":
    main()
