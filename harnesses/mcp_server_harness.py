#!/usr/bin/env python3
"""
harnesses/mcp_server_harness.py
Fuzzes Model Context Protocol (MCP) JSON-RPC endpoints against path traversal,
URI scheme escapes, null-byte injections, and resource exhaustion within quarantine cells.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict


def parse_args():
    parser = argparse.ArgumentParser(description="MCP JSON-RPC Server Security Fuzzing Harness")
    parser.add_argument("--param-json", type=str, default=None, help="JSON-encoded parameters")
    parser.add_argument("--method", type=str, default="resources/read", help="MCP JSON-RPC method")
    parser.add_argument("--uri", type=str, default="file:///app/safe.txt", help="Resource URI or target path")
    parser.add_argument("--payload-size-kb", type=int, default=1, help="Simulated payload / buffer size in KB")
    parser.add_argument("--timeout-s", type=float, default=0.1, help="Method execution timeout limit in seconds")
    return parser.parse_args()


def simulate_mcp_rpc_call(params: Dict[str, Any], workspace_root: Path) -> Dict[str, Any]:
    method = params.get("method", "resources/read")
    uri = str(params.get("uri", ""))
    payload_size_kb = int(params.get("payload_size_kb", 1))
    timeout_s = float(params.get("timeout_s", 0.1))

    # 1. Resource Exhaustion / Memory Ceiling Check (> 2048 KB or timeout trip)
    if payload_size_kb > 2048:
        return {
            "observable": "statutory_veto_reached",
            "returncode": 0,
            "raw_residue": f"buffer_exhaustion_veto: payload_size_kb={payload_size_kb} exceeds 2048KB ceiling",
        }

    if timeout_s <= 0.005:
        return {
            "observable": "admission_timeout",
            "returncode": 0,
            "raw_residue": f"timeout_budget_exhausted: timeout_s={timeout_s}s",
        }

    # 2. JSON-RPC Protocol Method Check
    valid_methods = {"resources/read", "resources/list", "tools/call", "prompts/get", "ping"}
    if method not in valid_methods:
        return {
            "observable": "rpc_error",
            "returncode": 0,
            "raw_residue": f"json_rpc_method_not_found: code=-32601 method={method}",
        }

    # 3. Path Traversal & URI Scheme Containment Check
    # Check for null byte injection
    if "\x00" in uri or "%00" in uri:
        return {
            "observable": "statutory_veto_reached",
            "returncode": 0,
            "raw_residue": "null_byte_injection_vetoed",
        }

    # Normalize URI scheme
    clean_path_str = uri
    if uri.startswith("file://"):
        clean_path_str = uri[len("file://"):]

    # Check for path traversal indicators or absolute root escapes
    forbidden_prefixes = ("/etc", "/root", "/proc", "/sys", "/dev", "/var/run")
    is_traversal = (
        "../" in clean_path_str
        or "..\\" in clean_path_str
        or "%2e%2e%2f" in clean_path_str.lower()
        or "%2e%2e/" in clean_path_str.lower()
        or clean_path_str.startswith(forbidden_prefixes)
    )

    if is_traversal:
        return {
            "observable": "statutory_veto_reached",
            "returncode": 0,
            "raw_residue": f"path_traversal_vetoed: uri={uri}",
        }

    # Check resolution against workspace root
    try:
        candidate_path = (workspace_root / clean_path_str.lstrip("/")).resolve()
        workspace_resolved = workspace_root.resolve()
        if not str(candidate_path).startswith(str(workspace_resolved)):
            return {
                "observable": "statutory_veto_reached",
                "returncode": 0,
                "raw_residue": f"workspace_escape_vetoed: target={candidate_path}",
            }
    except Exception as e:
        return {
            "observable": "rpc_error",
            "returncode": 0,
            "raw_residue": f"json_rpc_invalid_params: code=-32602 err={e}",
        }

    # 4. Safe intra-vires access
    return {
        "observable": "intra_vires_confirmed",
        "returncode": 0,
        "raw_residue": f"mcp_rpc_success: method={method} uri={uri}",
    }


def main():
    args = parse_args()
    params = {}
    if args.param_json:
        try:
            params = json.loads(args.param_json)
        except Exception:
            pass

    if not params:
        params = {
            "method": args.method,
            "uri": args.uri,
            "payload_size_kb": args.payload_size_kb,
            "timeout_s": args.timeout_s,
        }

    import tempfile
    default_ws = str(Path(tempfile.gettempdir()) / "dream_workspace")
    workspace = Path(os.environ.get("DREAM_WORKSPACE", default_ws))
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    result = simulate_mcp_rpc_call(params, workspace)
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
