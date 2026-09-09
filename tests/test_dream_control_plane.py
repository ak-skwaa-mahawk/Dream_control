#!/usr/bin/env python3
import sys
import unittest
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.dream_contract import HarnessSpec, ParamSpec, Experiment, RawTrace
from core.experiment_validator import decode_params, ParameterValidationError
from core.dream_evaluator import SignatureCorpus, evaluate_traces, compute_signature
from core.dream_scheduler import schedule_next_dream
from core.warden import execute_in_cell, _read_probes


class TestDreamControlPlane(unittest.TestCase):

    def setUp(self):
        self.spec = HarnessSpec(
            harness_id="fuzz_gate_buffer",
            target_subsystem="admission_gate",
            params={
                "timeout_s": ParamSpec(kind="float", lo=0.001, hi=5.0),
                "concurrency": ParamSpec(kind="int", lo=1, hi=128),
            },
            allowed_observables=frozenset(["admission_timeout", "statutory_veto_reached"]),
            runner_binary=PROJECT_ROOT / "harnesses" / "fuzz_runner.py",
        )
        self.corpus = SignatureCorpus()

    def test_decoder_rejects_bool_and_bounds(self):
        # Python bool passed as int must fail
        with self.assertRaises(ParameterValidationError):
            decode_params(self.spec, {"timeout_s": 0.5, "concurrency": True})

        # Out of bounds float
        with self.assertRaises(ParameterValidationError):
            decode_params(self.spec, {"timeout_s": 10.0, "concurrency": 16})

        # Valid params pass cleanly
        valid = decode_params(self.spec, {"timeout_s": 0.5, "concurrency": 16})
        self.assertEqual(valid["concurrency"], 16)

    def test_probe_allowlist_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "trace.json"
            # Runner attempts to claim an unauthorized probe
            trace_path.write_text(
                '{"probes": {"admission_timeout": true, "cross_tenant_leak": true}}'
            )
            probes = _read_probes(self.spec, trace_path)
            self.assertIn("admission_timeout", probes)
            self.assertNotIn("cross_tenant_leak", probes)

    def test_novelty_decay(self):
        exp = Experiment(
            dream_id="d1",
            harness_id="fuzz_gate_buffer",
            parameters={"timeout_s": 0.05, "concurrency": 32},
            expected="admission_timeout",
            unexpected=("cross_tenant_leak",),
            budget_ms=1000,
        )
        trace = RawTrace(
            exit_code=0,
            signal=None,
            wall_ms=10,
            max_rss_kb=100,
            stdout_sha256="",
            stderr_sha256="",
            probes={"admission_timeout": True},
        )
        sig = compute_signature(trace)

        # Run 1: Empty corpus -> Novelty = 1.0 -> Promoted
        n1 = self.corpus.get_novelty(exp.harness_id, sig)
        v1 = evaluate_traces(exp, [trace], novelty=n1, tau=2.0)
        self.assertEqual(v1.decision, "promote_candidate")
        self.corpus.record(exp.harness_id, sig)

        # Run 2: Exact same trace -> Novelty drops to 0.5 -> Discarded
        n2 = self.corpus.get_novelty(exp.harness_id, sig)
        v2 = evaluate_traces(exp, [trace], novelty=n2, tau=2.0)
        self.assertEqual(v2.decision, "discard")

    def test_scheduler_fallback(self):
        catalog = {self.spec.harness_id: self.spec}
        # Zero seeds, zero outliers -> must strictly produce cold_uniform
        res = schedule_next_dream([], catalog, [])
        self.assertEqual(res["mode"], "cold_uniform")

    def test_warden_timeout_exit_124(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Runner with 10ms budget executing sleep command
            spec_sleep = HarnessSpec(
                harness_id="sleep_harness",
                target_subsystem="test",
                params={},
                allowed_observables=frozenset(),
                runner_binary=Path("/bin/sleep"),
            )
            # Sleep 1s with 10ms budget
            trace = execute_in_cell(
                spec_sleep,
                {},
                budget_ms=10,
                workspace_root=Path(tmp),
                harness_tree=Path("/bin"),
            )
            self.assertEqual(trace.exit_code, 124)


if __name__ == "__main__":
    unittest.main(verbosity=2)
