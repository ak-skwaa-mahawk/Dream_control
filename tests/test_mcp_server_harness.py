import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harnesses.mcp_server_harness import simulate_mcp_rpc_call


class TestMCPServerHarness(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp_dir.name) / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_intra_vires_safe_resource(self):
        params = {
            "method": "resources/read",
            "uri": "file://safe/data.json",
            "payload_size_kb": 10,
            "timeout_s": 0.5,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "intra_vires_confirmed")
        self.assertTrue(res["probes"]["intra_vires_confirmed"])

    def test_path_traversal_triggers_statutory_veto(self):
        traversals = [
            "file:///app/../../etc/passwd",
            "file://../secret.key",
            "/etc/shadow",
            "file://resource/%2e%2e%2fconfig.json",
        ]
        for t in traversals:
            params = {"method": "resources/read", "uri": t, "payload_size_kb": 1, "timeout_s": 0.5}
            res = simulate_mcp_rpc_call(params, self.workspace)
            self.assertEqual(res["signal"], "statutory_veto_reached", f"Failed for {t}")
            self.assertTrue(res["probes"]["statutory_veto_reached"])

    def test_null_byte_injection_triggers_statutory_veto(self):
        params = {
            "method": "resources/read",
            "uri": "file://safe.txt\x00/../../etc/passwd",
            "payload_size_kb": 1,
            "timeout_s": 0.5,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "statutory_veto_reached")

    def test_prototype_pollution_triggers_statutory_veto(self):
        payloads = [
            {"method": "tools/call", "tool_name": "exec_cmd", "tool_args": {"__proto__": {"isAdmin": True}}},
            {"method": "tools/call", "tool_name": "exec_cmd", "tool_args": {"options": {"constructor": {"prototype": {"polluted": 1}}}}},
            {"method": "tools/call", "tool_name": "__proto__", "tool_args": {"input": "safe"}},
        ]
        for p in payloads:
            res = simulate_mcp_rpc_call(p, self.workspace)
            self.assertEqual(res["signal"], "statutory_veto_reached", f"Failed for {p}")
            self.assertIn("prototype_pollution_vetoed", res["detail"])

    def test_command_injection_triggers_statutory_veto(self):
        payloads = [
            {"method": "tools/call", "tool_name": "build", "tool_args": {"target": "all; rm -rf /"}},
            {"method": "tools/call", "tool_name": "build", "tool_args": {"target": "all | id"}},
            {"method": "tools/call", "tool_name": "build", "tool_args": {"cmd": "$(cat /etc/passwd)"}},
            {"method": "tools/call", "tool_name": "build", "tool_args": {"env": "prod`id`"}},
        ]
        for p in payloads:
            res = simulate_mcp_rpc_call(p, self.workspace)
            self.assertEqual(res["signal"], "statutory_veto_reached", f"Failed for {p}")
            self.assertIn("command_injection_vetoed", res["detail"])

    def test_safe_tool_call_confirms_intra_vires(self):
        params = {
            "method": "tools/call",
            "tool_name": "echo",
            "tool_args": {"message": "hello world", "format": "json"},
            "payload_size_kb": 1,
            "timeout_s": 0.5,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "intra_vires_confirmed")
        self.assertTrue(res["probes"]["intra_vires_confirmed"])

    def test_payload_exhaustion_triggers_statutory_veto(self):
        params = {
            "method": "tools/call",
            "tool_name": "echo",
            "uri": "file://tool",
            "payload_size_kb": 4096,
            "timeout_s": 0.5,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "statutory_veto_reached")

    def test_tight_timeout_triggers_admission_timeout(self):
        params = {
            "method": "resources/read",
            "uri": "file://data",
            "payload_size_kb": 1,
            "timeout_s": 0.001,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "admission_timeout")

    def test_unknown_rpc_method_triggers_rpc_error(self):
        params = {
            "method": "system/exec",
            "uri": "file://data",
            "payload_size_kb": 1,
            "timeout_s": 0.5,
        }
        res = simulate_mcp_rpc_call(params, self.workspace)
        self.assertEqual(res["signal"], "rpc_error")

    def test_cli_execution_integration(self):
        harness_path = Path(__file__).resolve().parents[1] / "harnesses" / "mcp_server_harness.py"
        payload = json.dumps({"method": "resources/read", "uri": "/etc/passwd", "payload_size_kb": 1, "timeout_s": 0.1})
        proc = subprocess.run(
            [sys.executable, str(harness_path), "--param-json", payload],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout.strip())
        self.assertEqual(data["signal"], "statutory_veto_reached")


if __name__ == "__main__":
    unittest.main()
