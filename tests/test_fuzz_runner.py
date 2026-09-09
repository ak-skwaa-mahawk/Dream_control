#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec
from core.warden import execute_in_cell


class TestFuzzRunner(unittest.TestCase):

    def setUp(self):
        self.runner = Path("harnesses/fuzz_runner.py").resolve()
        self.spec = HarnessSpec(
            harness_id="fuzz_gate_buffer",
            target_subsystem="admission_gate",
            params={
                "timeout_s": ParamSpec(kind="float", lo=0.001, hi=5.0),
                "concurrency": ParamSpec(kind="int", lo=1, hi=128),
            },
            allowed_observables=frozenset(["admission_timeout", "statutory_veto_reached"]),
            runner_binary=self.runner,
        )

    def test_low_concurrency_no_veto(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            trace = execute_in_cell(
                spec=self.spec,
                validated_params={"timeout_s": 0.5, "concurrency": 2},
                budget_ms=2000,
                workspace_root=workspace,
                harness_tree=self.runner.parent.parent,
            )
            self.assertEqual(trace.exit_code, 0)
            self.assertFalse(trace.probes.get("statutory_veto_reached", False))
            self.assertNotIn("injected_fake_leak", trace.probes)

    def test_high_concurrency_tight_timeout_triggers_veto(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            trace = execute_in_cell(
                spec=self.spec,
                validated_params={"timeout_s": 0.002, "concurrency": 24},
                budget_ms=2000,
                workspace_root=workspace,
                harness_tree=self.runner.parent.parent,
            )
            self.assertEqual(trace.exit_code, 0)
            self.assertTrue(trace.probes.get("admission_timeout", False))
            self.assertTrue(trace.probes.get("statutory_veto_reached", False))
            self.assertNotIn("injected_fake_leak", trace.probes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
