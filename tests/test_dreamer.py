#!/usr/bin/env python3
import json
import unittest
from pathlib import Path
from core.dream_contract import HarnessSpec, ParamSpec
from core.dreamer import generate_experiment, Dreamer, MockInferenceBackend, RemoteHttpBackend
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
                "budget_ms": 1500,
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

    def test_extract_markdown_fenced_payload(self):
        fenced_output = """Here is the compiled experiment:
```json
{
  \"dream_id\": \"dream_fenced\",
  \"harness_id\": \"fuzz_gate_buffer\",
  \"parameters\": {\"timeout_s\": 0.1, \"concurrency\": 16},
  \"expected\": \"admission_timeout\",
  \"unexpected\": [],
  \"budget_ms\": 1000
}
```
Hope this helps!"""
        def mock_llm(prompt: str, temp: float) -> str:
            return "speculative scenario" if temp > 1.0 else fenced_output
        exp = generate_experiment(self.seed, self.catalog, mock_llm)
        self.assertEqual(exp.dream_id, "dream_fenced")
        self.assertEqual(exp.parameters["concurrency"], 16)


    def test_dreamer_with_custom_mock_inference_backend(self):
        backend = MockInferenceBackend(
            responder=lambda prompt, schema: {"concurrency": 8, "timeout_s": 0.5}
        )
        dreamer = Dreamer(self.catalog, backend=backend)
        exp = dreamer.dream("fuzz_gate_buffer", dream_id="d_custom")
        self.assertEqual(exp.parameters["concurrency"], 8)
        self.assertAlmostEqual(exp.parameters["timeout_s"], 0.5)

    def test_remote_http_backend_success(self):
        from unittest.mock import MagicMock, patch
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": """```json
{"concurrency": 4, "timeout_s": 0.2}
```"""}}]
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_response):
            backend = RemoteHttpBackend(endpoint_url="http://localhost:8000/v1/chat", api_key="secret")
            dreamer = Dreamer(self.catalog, backend=backend)
            exp = dreamer.dream("fuzz_gate_buffer", dream_id="d_remote")
            self.assertEqual(exp.parameters["concurrency"], 4)
            self.assertAlmostEqual(exp.parameters["timeout_s"], 0.2)

    def test_remote_http_backend_fails_closed_on_http_error(self):
        from unittest.mock import patch
        import urllib.error
        err = urllib.error.URLError("connection refused")
        with patch("urllib.request.urlopen", side_effect=err):
            backend = RemoteHttpBackend(endpoint_url="http://localhost:8000/v1/chat")
            dreamer = Dreamer(self.catalog, backend=backend)
            from core.dream_contract import SecurityViolation
            with self.assertRaises(SecurityViolation):
                dreamer.dream("fuzz_gate_buffer")

if __name__ == "__main__":
    unittest.main(verbosity=2)
