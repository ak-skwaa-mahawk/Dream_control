#!/usr/bin/env python3
import json
import unittest
from pathlib import Path
from core.dream_contract import HarnessSpec, ParamSpec, Experiment
from core.dreamer import generate_experiment
from core.experiment_validator import ParameterValidationError

class TestDreamer(unittest.TestCase):

    def setUp(self):
        self.spec = HarnessSpec(
            harness_id="fuzz_gate_buffer",
            target_subsystem="admission_gate",
            params={
                "timeout_s": ParamSpec(kind="float", lo=0.001, hi=5.0),
                "concurrency": ParamSpec(kind="int", lo=1, hi=128),
            },
            allowed_observables=frozenset(["admission_timeout", "statutory_veto_reached"]),
            runner_binary=Path("/bin/true"),
        )
        self.catalog = {self.spec.harness_id: self.spec}
        self.seed = {"seed_type": "telemetry_outlier", "raw_residue": "timeout after 50ms"}

    def test_nominal_two_phase_generation(self):
        def mock_llm(prompt: str, temp: float) -> str:
            if temp > 1.0:
                return "The buffer cascaded into an unanchored state under concurrent load."
            return json.dumps({
                "dream_id": "dream_test_001",
                "harness_id": "fuzz_gate_buffer",
                "parameters": {"timeout_s": 0.05, "concurrency": 64},
                "expected": "admission_timeout",
                "unexpected": ["statutory_veto_reached"],
                "budget_ms": 1500
            })

        exp = generate_experiment(self.seed, self.catalog, mock_llm)
        self.assertEqual(exp.dream_id, "dream_test_001")
        self.assertEqual(exp.parameters["concurrency"], 64)
        self.assertEqual(exp.expected, "admission_timeout")

    def test_compiler_type_injection_fails(self):
        def mock_llm(prompt: str, temp: float) -> str:
            if temp > 1.0:
                return "Speculative prose."
            return json.dumps({
                "dream_id": "dream_bad",
                "harness_id": "fuzz_gate_buffer",
                "parameters": {"timeout_s": 0.05, "concurrency": True},
                "expected": "admission_timeout",
            })

        with self.assertRaises(ParameterValidationError):
            generate_experiment(self.seed, self.catalog, mock_llm)

if __name__ == "__main__":
    unittest.main(verbosity=2)
