#!/usr/bin/env python3
import unittest
import tempfile
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec, SecurityViolation, Experiment, RawTrace
from core.experiment_validator import decode_params, ParameterValidationError
from core.warden import execute_in_cell
from core.dream_evaluator import evaluate_traces,  SignatureCorpus
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

    def test_signature_corpus_novelty_decay_formula(self):
        from core.dream_evaluator import evaluate_traces,  SignatureCorpus
        corpus = SignatureCorpus()
        harness = "admission_gate_policy"
        sig_a = "sig_nominal_001"
        sig_b = "sig_anomaly_002"

        # Baseline empty corpus: m=0, |C|=0 -> N = 1.0 - 0/1 = 1.0
        self.assertAlmostEqual(corpus.get_novelty(harness, sig_a), 1.0)

        # Record 10 instances of sig_a
        for _ in range(10):
            corpus.record(harness, sig_a)

        # Total history |C|=10, matches for sig_a m=10
        # Expected N = 1.0 - (10 / (1.0 + 10)) = 1.0 - (10/11) = 1/11 ~= 0.0909
        expected_decay = 1.0 - (10.0 / 11.0)
        self.assertAlmostEqual(corpus.get_novelty(harness, sig_a), expected_decay, places=4)

        # Fresh signature sig_b against |C|=10, m=0 -> N = 1.0 - 0/11 = 1.0
        self.assertAlmostEqual(corpus.get_novelty(harness, sig_b), 1.0)



    def test_soft_consensus_promotes_with_jaccard_above_threshold(self):
        exp = Experiment(
            dream_id="d_soft",
            harness_id="fuzz_target",
            parameters={"concurrency": 2},
            expected="timeout",
            unexpected=("statutory_veto_reached",),
            budget_ms=500,
        )
        t1 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True, "p1": True}, stdout_hash="h1", stderr_hash="e1", signal=None, max_rss_kb=100, isolation={})
        t2 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True, "p1": True}, stdout_hash="h2", stderr_hash="e2", signal=None, max_rss_kb=100, isolation={})
        t3 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True, "p2": True}, stdout_hash="h3", stderr_hash="e3", signal=None, max_rss_kb=100, isolation={})

        verdict = evaluate_traces(exp, [t1, t2, t3], novelty=1.0, tau=1.0, consensus_threshold=0.50)
        self.assertEqual(verdict.decision, "promote_soft")
        self.assertGreater(verdict.score, 0.0)

    def test_soft_consensus_strictly_vetoed_by_unexpected_observable(self):
        exp = Experiment(
            dream_id="d_veto",
            harness_id="admission_gate",
            parameters={"target_path": "/etc/shadow"},
            expected="timeout",
            unexpected=("statutory_veto_reached",),
            budget_ms=500,
        )
        t1 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True}, stdout_hash="h1", stderr_hash="e1", signal=None, max_rss_kb=100, isolation={})
        t2 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True, "statutory_veto_reached": True}, stdout_hash="h2", stderr_hash="e2", signal=None, max_rss_kb=100, isolation={})
        t3 = RawTrace(exit_code=124, wall_ms=10, probes={"timeout": True}, stdout_hash="h3", stderr_hash="e3", signal=None, max_rss_kb=100, isolation={})

        verdict = evaluate_traces(exp, [t1, t2, t3], novelty=1.0, tau=1.5)
        self.assertEqual(verdict.decision, "discard")
        self.assertTrue(any("unexpected_observable_triggered" in r for r in verdict.reasons))

    def test_signature_corpus_steep_exponential_decay(self):
        import math
        from core.dream_evaluator import SignatureCorpus
        corpus = SignatureCorpus(decay_mode="steep_exponential", alpha=0.8)
        harness = "path_escape_fuzzer"
        sig_frequent = "sig_veto_frequent"

        self.assertEqual(corpus.get_novelty(harness, sig_frequent), 1.0)

        # Record 5 occurrences of the same rejection signature
        for _ in range(5):
            corpus.record(harness, sig_frequent)

        # Should decay exponentially: exp(-0.8 * 5) = exp(-4.0) ~= 0.0183
        expected = math.exp(-0.8 * 5)
        novelty = corpus.get_novelty(harness, sig_frequent)
        self.assertAlmostEqual(novelty, expected, places=4)
        self.assertLess(novelty, 0.05)

    def test_evaluator_penalizes_throttled_traces(self):
        from core.dream_evaluator import evaluate_traces
        from core.dream_contract import RawTrace, Experiment

        exp = Experiment(
            dream_id="d_throttle_test",
            harness_id="admission_gate_policy",
            parameters={},
            expected="intra_vires_confirmed",
            unexpected=("panic",),
            budget_ms=1000,
        )
        t_normal = RawTrace(
            exit_code=0,
            wall_ms=50,
            probes={"intra_vires_confirmed": True},
            stdout_hash="hash0",
            stderr_hash="hash0",
            signal=None,
            max_rss_kb=1024,
            isolation={"memory_throttled": False},
        )
        t_throttled = RawTrace(
            exit_code=0,
            wall_ms=50,
            probes={"intra_vires_confirmed": True},
            stdout_hash="hash0",
            stderr_hash="hash0",
            signal=None,
            max_rss_kb=1024,
            isolation={"memory_throttled": True},
        )

        v_norm = evaluate_traces(exp, [t_normal, t_normal, t_normal], novelty=1.0)
        v_throt = evaluate_traces(exp, [t_normal, t_throttled, t_normal], novelty=1.0)

        self.assertAlmostEqual(v_throt.score, v_norm.score * 0.5, places=3)

    def test_scheduler_adaptive_budget_backoff_on_throttling(self):
        from core.dream_scheduler import compute_adaptive_budget
        base = 2000
        b1 = compute_adaptive_budget(base, throttle_occurrences=0)
        b2 = compute_adaptive_budget(base, throttle_occurrences=1)
        b3 = compute_adaptive_budget(base, throttle_occurrences=3)
        b_floor = compute_adaptive_budget(base, throttle_occurrences=20, min_budget_ms=250)

        self.assertEqual(b1, 2000)
        self.assertLess(b2, b1)
        self.assertLess(b3, b2)
        self.assertEqual(b_floor, 250)

if __name__ == "__main__":
    unittest.main(verbosity=2)

    def test_timeout_does_not_infer_panic(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            harness = tmp_p / "hang.py"
            harness.write_text("import time; time.sleep(10)", encoding="utf-8")
            spec = HarnessSpec(
                harness_id="hang",
                target_subsystem="test",
                params={},
                allowed_observables=frozenset(["timeout", "panic"]),
                runner_binary=harness,
            )
            trace = execute_in_cell(spec, {}, 100, tmp_p / "ws", tmp_p)
            self.assertEqual(trace.exit_code, 124)
            self.assertIsNone(trace.signal)
            from core.dream_evaluator import evaluate_traces,  evaluate_traces
            from core.dream_contract import Experiment
            exp = Experiment("d1", "hang", {}, "timeout", ("panic",), 100)
            verdict = evaluate_traces(exp, [trace], 1.0)
            self.assertFalse(verdict.surprise)
            self.assertTrue(verdict.match)
