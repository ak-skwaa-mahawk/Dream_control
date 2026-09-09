#!/usr/bin/env python3
import os
import json
import tempfile
import unittest
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec
from core.warden import execute_in_cell


class TestAdmissionGateIntegration(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.runner = self.root / "harnesses" / "gate_fuzz_runner.py"
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

            fd = os.open(str(charter_file), os.O_RDONLY)
            try:
                trace = execute_in_cell(
                    spec=self.spec,
                    validated_params={
                        "target_path": "/etc/shadow",
                        "action_type": "SHELL_EXEC",
                        "charter_path": "charter.json",
                        "sock_path": "/nonexistent.sock",
                    },
                    budget_ms=2000,
                    workspace_root=tmp_path / "workspace",
                    harness_tree=self.runner.parent,
                    pass_fds=(fd,),
                    extra_env={"ADMISSION_GATE_CHARTER_FD": str(fd)},
                )
            finally:
                os.close(fd)

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

            fd = os.open(str(charter_file), os.O_RDONLY)
            try:
                trace = execute_in_cell(
                    spec=self.spec,
                    validated_params={
                        "target_path": "/workspace/safe.txt",
                        "action_type": "SHELL_EXEC",
                        "charter_path": "charter.json",
                        "sock_path": "/nonexistent.sock",
                    },
                    budget_ms=2000,
                    workspace_root=tmp_path / "workspace",
                    harness_tree=self.runner.parent,
                    pass_fds=(fd,),
                    extra_env={"ADMISSION_GATE_CHARTER_FD": str(fd)},
                )
            finally:
                os.close(fd)

            self.assertEqual(trace.exit_code, 0)
            self.assertFalse(trace.probes.get("statutory_veto_reached"))
            self.assertFalse(trace.probes.get("ultra_vires_detected"))
            self.assertTrue(trace.probes.get("intra_vires_confirmed"))


if __name__ == "__main__":
    unittest.main()
