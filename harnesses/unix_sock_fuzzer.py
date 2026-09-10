#!/usr/bin/env python3
"""UNIX Domain Socket & Descriptor Passing Boundary Harness.

Stresses UNIX socket creation, abstract namespace scoping, ancillary data
passing (SCM_RIGHTS / file descriptor transmission), and message truncation.
"""

from __future__ import annotations

import array
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

VALID_OBSERVABLES = {
    "socket_bound",
    "ancillary_passed",
    "abstract_leaked",
    "descriptor_vetoed",
    "socket_truncated",
    "connection_refused",
    "permission_denied",
    "protocol_error",
}


def run_harness(params: dict[str, Any]) -> dict[str, Any]:
    probes = {obs: False for obs in VALID_OBSERVABLES}
    sock_type_str = params.get("sock_type", "dgram").lower()
    sock_family = socket.AF_UNIX
    sock_type = socket.SOCK_DGRAM if sock_type_str == "dgram" else socket.SOCK_STREAM

    use_abstract = bool(params.get("use_abstract", False))
    pass_descriptor = bool(params.get("pass_descriptor", False))
    socket_name = params.get("socket_name", "dream_fuzz.sock")
    payload_len = int(params.get("payload_len", 64))

    if use_abstract:
        sock_addr = "\0" + socket_name
    else:
        sock_dir = Path(os.environ.get("DREAM_WORKSPACE", ".")).resolve()
        sock_path = sock_dir / socket_name
        if sock_path.exists():
            try:
                sock_path.unlink()
            except OSError:
                pass
        sock_addr = str(sock_path)

    server = None
    client = None
    try:
        server = socket.socket(sock_family, sock_type)
        try:
            server.bind(sock_addr)
            probes["socket_bound"] = True
            if use_abstract:
                probes["abstract_leaked"] = True
        except PermissionError:
            probes["permission_denied"] = True
            return {"exit_code": 0, "signal": 0, "probes": probes}
        except OSError:
            probes["descriptor_vetoed"] = True
            return {"exit_code": 0, "signal": 0, "probes": probes}

        if sock_type == socket.SOCK_STREAM:
            server.listen(1)

        client = socket.socket(sock_family, sock_type)

        try:
            client.connect(sock_addr)
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            probes["connection_refused"] = True
            return {"exit_code": 0, "signal": 0, "probes": probes}

        payload = b"A" * min(payload_len, 65536)

        if pass_descriptor:
            r_fd, w_fd = os.pipe()
            try:
                msg = [payload[:32]]
                ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [r_fd]).tobytes())]
                try:
                    client.sendmsg(msg, ancdata)
                    probes["ancillary_passed"] = True
                except (OSError, ValueError):
                    probes["descriptor_vetoed"] = True
            finally:
                os.close(r_fd)
                os.close(w_fd)
        else:
            try:
                sent = client.send(payload)
                if sent < len(payload):
                    probes["socket_truncated"] = True
            except OSError:
                probes["protocol_error"] = True

        return {"exit_code": 0, "signal": 0, "probes": probes}

    except Exception:
        probes["protocol_error"] = True
        return {"exit_code": 1, "signal": 0, "probes": probes}
    finally:
        if client:
            try:
                client.close()
            except OSError:
                pass
        if server:
            try:
                server.close()
            except OSError:
                pass
        if not use_abstract and isinstance(sock_addr, str) and not sock_addr.startswith("\0"):
            p = Path(sock_addr)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass


def main() -> None:
    raw_input = sys.stdin.read()
    params = json.loads(raw_input) if raw_input.strip() else {}
    result = run_harness(params)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
