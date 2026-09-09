mkdir -p tests
cat << 'EOF' > tests/test_dream_control_plane.py
#!/usr/bin/env python3
import unittest
from pathlib import Path
from core.dream_contract import HarnessSpec, ParamSpec, Experiment, RawTrace
from core.dream_evaluator import SignatureCorpus, evaluate_traces, compute_signature
from core.dream_scheduler import schedule_next_dream


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
            runner_binary=Path("/opt/sovereign/harnesses/fuzz_runner.py")
        )
        self.corpus = SignatureCorpus()

    def test_probe_injection_and_novelty_decay(self):
        exp = Experiment(
            dream_id="dream_001",
            harness_id="fuzz_gate_buffer",
            parameters={"timeout_s": 0.05, "concurrency": 32},
            expected="admission_timeout",
            unexpected=("cross_tenant_leak",),
            budget_ms=1000
        )

        # Trace simulating an attempt to claim cross_tenant_leak via un-allowed probe
        raw_trace_1 = RawTrace(
            exit_code=0,
            signal=None,
            wall_ms=150,
            max_rss_kb=1024,
            stdout_sha256="abc",
            stderr_sha256="def",
            probes={"admission_timeout": True} # Allowed probe
        )

        # First run: Novelty should be 1.0 (empty corpus)
        verdict_1 = evaluate_traces(exp, [raw_trace_1], self.corpus, tau=2.0)
        self.assertEqual(verdict_1.novelty, 1.0)
        self.assertTrue(verdict_1.match)
        self.assertFalse(verdict_1.surprise)
        # Score = 1.0 (match) + 0.0 (no surprise) + 1.0 (novelty) = 2.0 -> Promoted
        self.assertEqual(verdict_1.decision, "promote_candidate")

        # Second run with exact identical signature: Novelty drops to 1 - (1 / 2) = 0.5
        verdict_2 = evaluate_traces(exp, [raw_trace_1], self.corpus, tau=2.0)
        self.assertEqual(verdict_2.novelty, 0.5)
        # Score = 1.0 + 0.0 + 0.5 = 1.5 < 2.0 -> Discard
        self.assertEqual(verdict_2.decision, "discard")

    def test_scheduler_preserves_cold_exploration(self):
        catalog = {self.spec.harness_id: self.spec}
        # Run 100 iterations with empty pools
        decisions = [
            schedule_next_dream([], catalog, [])["mode"]
            for _ in range(100)
        ]
        self.assertTrue(all(d == "cold_uniform" for d in decisions))


if __name__ == "__main__":
    unittest.main()
EOF
