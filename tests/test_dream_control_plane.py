#!/usr/bin/env python3
import unittest
import tempfile
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec, SecurityViolation
from core.experiment_validator import decode_params, ParameterValidationError
from core.warden import execute_in_cell
from core.dream_evaluator import SignatureCorpus
from core.dream_scheduler import schedule_next_dream

class TestDreamControlPlane(unittest.TestCase):

    def setUp(self):
        self.spec = HarnessSpec(
            harness_id="fuzz_gate",
            target_subsystem="admission_gate",
            params={
                "timeout_s": ParamSpec(kind="float", lo=0.001, hi=5.0),
                "concurrency": ParamSpec(kind="int", lo=1, hi=128),
            },
            allowed_observables=frozenset(["admission_timeout", "statutory_veto_reached"]),
            runner_binary=Path("/bin/true"),
        )
        self.catalog = {self.spec.harness_id: self.spec}

    def test_decoder_rejects_bool_and_bounds(self):
        with self.assertRaises(ParameterValidationError):
            decode_params(self.spec, {"timeout_s": 0.5, "concurrency": True})
        with self.assertRaises(ParameterValidationError):
            decode_params(self.spec, {"timeout_s": 10.0, "concurrency": 10})
        with self.assertRaises(ParameterValidationError):
            decode_params(self.spec, {"timeout_s": 0.5})

        valid = decode_params(self.spec, {"timeout_s": 0.5, "concurrency": 10})
        self.assertEqual(valid["concurrency"], 10)
        self.assertEqual(valid["timeout_s"], 0.5)

    def test_probe_allowlist_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            runner = tmp_path / "runner.py"

            runner_code = (
                "import argparse, json\n"
                "from pathlib import Path\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument(\"--params\", type=Path)\n"
                "parser.add_argument(\"--out\", type=Path)\n"
                "args = parser.parse_args()\n"
                "payload = {\"probes\": {\"statutory_veto_reached\": True, \"unregistered_leak\": True}}\n"
                "args.out.write_text(json.dumps(payload))\n"
            )
            runner.write_text(runner_code, encoding="utf-8")

            spec = HarnessSpec(
                harness_id="probe_test",
                target_subsystem="test",
                params={"concurrency": ParamSpec(kind="int", lo=1, hi=10)},
                allowed_observables=frozenset(["statutory_veto_reached"]),
                runner_binary=runner,
            )

            trace = execute_in_cell(
                spec=spec,
                validated_params={"concurrency": 5},
                budget_ms=1000,
                workspace_root=workspace,
                harness_tree=tmp_path,
            )

            self.assertIn("statutory_veto_reached", trace.probes)
            self.assertNotIn("unregistered_leak", trace.probes)

    def test_warden_timeout_exit_124(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            sleep_runner = tmp_path / "sleep_runner.py"
            sleep_runner.write_text("import time, sys\ntime.sleep(2.0)\nsys.exit(0)\n", encoding="utf-8")

            spec = HarnessSpec(
                harness_id="sleep_harness",
                target_subsystem="test",
                params={"concurrency": ParamSpec(kind="int", lo=1, hi=10)},
                allowed_observables=frozenset(["admission_timeout"]),
                runner_binary=sleep_runner,
            )

            trace = execute_in_cell(
                spec=spec,
                validated_params={"concurrency": 1},
                budget_ms=50,
                workspace_root=workspace,
                harness_tree=tmp_path,
            )
            self.assertEqual(trace.exit_code, 124)

    def test_harness_tree_security_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            tree_dir = tmp_path / "tree"
            tree_dir.mkdir()
            rogue_binary = tmp_path / "rogue.py"
            rogue_binary.write_text("exit(0)", encoding="utf-8")

            spec = HarnessSpec(
                harness_id="rogue",
                target_subsystem="test",
                params={},
                allowed_observables=frozenset(),
                runner_binary=rogue_binary,
            )

            with self.assertRaises(SecurityViolation):
                execute_in_cell(
                    spec=spec,
                    validated_params={},
                    budget_ms=100,
                    workspace_root=workspace,
                    harness_tree=tree_dir,
                )

    def test_novelty_decay(self):
        corpus = SignatureCorpus()
        harness = "fuzz_gate"
        sig_a = "signature_alpha"

        n0 = corpus.get_novelty(harness, sig_a)
        self.assertEqual(n0, 1.0)
        corpus.record(harness, sig_a)

        n1 = corpus.get_novelty(harness, sig_a)
        self.assertEqual(n1, 0.5)

    def test_scheduler_fallback(self):
        plan = schedule_next_dream([], self.catalog, [])
        self.assertEqual(plan["mode"], "cold_uniform")
        self.assertEqual(plan["harness_id"], "fuzz_gate")

if __name__ == "__main__":
    unittest.main(verbosity=2)
