#!/usr/bin/env python3
import json
import unittest
import tempfile
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec
from core.warden import execute_in_cell


class TestAdmissionGateIntegration(unittest.TestCase):

    def setUp(self):
        self.runner = Path("harnesses/gate_fuzz_runner.py").resolve()
        self.spec = HarnessSpec(
            harness_id="admission_gate_policy",
            target_subsystem="admission_gate",
            params={
                "target_path": ParamSpec(kind="str", lo=1, hi=256),
                "action_type": ParamSpec(kind="str", lo=1, hi=64),
                "charter_path": ParamSpec(kind="str", lo=1, hi=512),
                "sock_path": ParamSpec(kind="str", lo=1, hi=512),
            },
            allowed_observables=frozenset([
                "statutory_veto_reached",
                "ultra_vires_detected",
                "intra_vires_confirmed",
            ]),
            runner_binary=self.runner,
        )

    def test_prohibited_resource_triggers_statutory_veto(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            charter_file = tmp_path / "charter.json"
            charter_file.write_text(json.dumps({
                "prohibited_resource_patterns": [r"^/etc/.*"],
                "authorized_actions": ["SHELL_EXEC"],
            }), encoding="utf-8")

            trace = execute_in_cell(
                spec=self.spec,
                validated_params={
                    "target_path": "/etc/shadow",
                    "action_type": "SHELL_EXEC",
                    "charter_path": str(charter_file),
                    "sock_path": "/nonexistent.sock",
                },
                budget_ms=2000,
                workspace_root=tmp_path / "workspace",
                harness_tree=self.runner.parent.parent,
            )

            self.assertEqual(trace.exit_code, 0)
            self.assertTrue(trace.probes.get("statutory_veto_reached"))
            self.assertTrue(trace.probes.get("ultra_vires_detected"))
            self.assertFalse(trace.probes.get("intra_vires_confirmed"))

    def test_authorized_resource_confirms_intra_vires(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            charter_file = tmp_path / "charter.json"
            charter_file.write_text(json.dumps({
                "prohibited_resource_patterns": [r"^/etc/.*"],
                "authorized_actions": ["SHELL_EXEC"],
            }), encoding="utf-8")

            trace = execute_in_cell(
                spec=self.spec,
                validated_params={
                    "target_path": "/var/log/app.log",
                    "action_type": "SHELL_EXEC",
                    "charter_path": str(charter_file),
                    "sock_path": "/nonexistent.sock",
                },
                budget_ms=2000,
                workspace_root=tmp_path / "workspace",
                harness_tree=self.runner.parent.parent,
            )

            self.assertEqual(trace.exit_code, 0)
            self.assertFalse(trace.probes.get("statutory_veto_reached"))
            self.assertFalse(trace.probes.get("ultra_vires_detected"))
            self.assertTrue(trace.probes.get("intra_vires_confirmed"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
