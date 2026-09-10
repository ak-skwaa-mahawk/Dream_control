#!/usr/bin/env python3
import asyncio
import tempfile
import unittest
from pathlib import Path

from core.dream_contract import DEFAULT_CATALOG
from core.warden import async_execute_in_cell, async_execute_replicates


class TestAsyncWarden(unittest.IsolatedAsyncioTestCase):
    async def test_async_execute_in_cell_basic(self):
        spec = DEFAULT_CATALOG["mcp_server_fuzzer"]
        params = {
            "method": "ping",
            "uri": "file:///app/safe.txt",
            "tool_name": "echo",
            "tool_args": "{}",
            "payload_size_kb": 1,
            "timeout_s": 0.5,
        }
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            trace = await async_execute_in_cell(
                spec=spec,
                validated_params=params,
                budget_ms=1000,
                workspace_root=ws,
                harness_tree=Path("harnesses").resolve(),
                require_isolation=False,
            )
            self.assertEqual(trace.exit_code, 0)
            self.assertTrue(trace.probes.get("intra_vires_confirmed", False))

    async def test_async_execute_replicates_parallel_k3(self):
        spec = DEFAULT_CATALOG["mcp_server_fuzzer"]
        params = {
            "method": "tools/call",
            "uri": "file:///app/safe.txt",
            "tool_name": "exec",
            "tool_args": "{\"__proto__\": {\"polluted\": true}}",
            "payload_size_kb": 1,
            "timeout_s": 0.5,
        }
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            traces = await async_execute_replicates(
                spec=spec,
                validated_params=params,
                budget_ms=1000,
                workspace_root=ws,
                harness_tree=Path("harnesses").resolve(),
                k=3,
                require_isolation=False,
            )
            self.assertEqual(len(traces), 3)
            for t in traces:
                self.assertEqual(t.exit_code, 0)
                self.assertTrue(t.probes.get("statutory_veto_reached", False))


if __name__ == "__main__":
    unittest.main()
