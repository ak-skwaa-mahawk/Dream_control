#!/usr/bin/env python3
"""
core/dreamer.py
Experiment synthesis engine with InferenceBackend abstraction, schema enforcement,
and production-ready RemoteHttpBackend.
"""

import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Protocol

from core.dream_contract import Experiment, HarnessSpec, SecurityViolation
from core.experiment_validator import ParameterValidationError, decode_params


def extract_markdown_json(text: str) -> str:
    """Extracts JSON content from optional Markdown code fences."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return text


class InferenceBackend(Protocol):
    """Protocol for generative inference backends."""

    def generate(
        self,
        prompt: str,
        system_instruction: str,
        expected_schema: Mapping[str, Any],
        timeout_s: float = 15.0,
    ) -> dict[str, Any]:
        ...


class MockInferenceBackend:
    """Deterministic offline backend for test fixtures and hermetic environments."""

    def __init__(self, responder: Callable[[str, Mapping[str, Any]], dict[str, Any]] | None = None):
        self._responder = responder

    def generate(
        self,
        prompt: str,
        system_instruction: str,
        expected_schema: Mapping[str, Any],
        timeout_s: float = 15.0,
    ) -> dict[str, Any]:
        if self._responder is not None:
            return self._responder(prompt, expected_schema)
        out: dict[str, Any] = {}
        for k, p in expected_schema.items():
            ptype = getattr(p, "param_type", getattr(p, "kind", "str"))
            if ptype == "int":
                out[k] = getattr(p, "default", getattr(p, "lo", 1))
            elif ptype == "float":
                out[k] = float(getattr(p, "default", getattr(p, "lo", 0.1)))
            elif ptype == "str":
                out[k] = getattr(p, "default", "/tmp")
            elif ptype == "bool":
                out[k] = getattr(p, "default", False)
            else:
                out[k] = getattr(p, "default", None)
        return out


class RemoteHttpBackend:
    """Production HTTP inference client with strict timeouts and schema validation."""

    def __init__(
        self,
        endpoint_url: str,
        api_key: str | None = None,
        model: str = "default-fuzz-generator",
        extra_headers: Mapping[str, str] | None = None,
    ):
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.model = model
        self.extra_headers = dict(extra_headers or {})

    def generate(
        self,
        prompt: str,
        system_instruction: str,
        expected_schema: Mapping[str, Any],
        timeout_s: float = 15.0,
    ) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.extra_headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(self.endpoint_url, data=body_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status != 200:
                    raise SecurityViolation(f"Remote inference HTTP {resp.status}")
                resp_bytes = resp.read()
        except urllib.error.URLError as e:
            raise SecurityViolation(f"Remote inference connection failure: {e}") from e

        try:
            resp_data = json.loads(resp_bytes.decode("utf-8"))
        except Exception as e:
            raise SecurityViolation(f"Remote inference response is not valid JSON: {e}") from e

        content_text = ""
        if isinstance(resp_data, dict):
            if "choices" in resp_data and len(resp_data["choices"]) > 0:
                choice = resp_data["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    content_text = choice["message"]["content"]
            elif "content" in resp_data:
                content_text = resp_data["content"]
            elif "output" in resp_data:
                content_text = resp_data["output"]

        if not content_text:
            if isinstance(resp_data, dict) and "parameters" in resp_data:
                return resp_data["parameters"]
            raise SecurityViolation("Empty content returned from remote inference backend")

        clean_json = extract_markdown_json(content_text)
        try:
            parsed = json.loads(clean_json)
        except json.JSONDecodeError as e:
            raise SecurityViolation(f"Generated text could not be decoded as JSON: {e}") from e

        if not isinstance(parsed, dict):
            raise SecurityViolation("Generated parameters must be a JSON object")

        return parsed


class Dreamer:
    """Synthesizes hardened experiment parameters using swappable inference backends."""

    def __init__(
        self,
        catalog: Mapping[str, HarnessSpec],
        backend: InferenceBackend | None = None,
    ):
        self.catalog = catalog
        self.backend: InferenceBackend = backend or MockInferenceBackend()

    def dream(
        self,
        harness_id: str,
        hypothesis: str = "explore boundary states",
        budget_ms: int = 1000,
        expected_signal: str = "intra_vires_confirmed",
        unexpected_signals: tuple[str, ...] = ("statutory_veto_reached", "ultra_vires_detected"),
        dream_id: str = "dream_0",
    ) -> Experiment:
        if harness_id not in self.catalog:
            raise SecurityViolation(f"Unregistered harness_id: {harness_id}")

        spec: HarnessSpec = self.catalog[harness_id]

        system_instruction = (
            f"You are an adversarial fuzzer generator targeting harness '{harness_id}'. "
            "Output strictly valid JSON parameter maps adhering to the specified schema."
        )
        prompt = (
            f"Generate concrete parameter assignments for target subsystem: {spec.target_subsystem}.\n"
            f"Hypothesis: {hypothesis}\n"
            f"Target parameter specifications: {list(spec.params.keys())}"
        )

        generated_raw = self.backend.generate(
            prompt=prompt,
            system_instruction=system_instruction,
            expected_schema=spec.params,
        )

        validated_params = decode_params(spec, generated_raw)

        return Experiment(
            dream_id=dream_id,
            harness_id=harness_id,
            parameters=validated_params,
            expected=expected_signal,
            unexpected=unexpected_signals,
            budget_ms=budget_ms,
        )


def generate_experiment(
    seed: dict[str, Any],
    catalog: Mapping[str, HarnessSpec],
    llm_fn: Callable[[str, float], str],
) -> Experiment:
    """Two-phase generation entry point preserving backwards compatibility with daemon and existing tests."""
    phase1_prompt = f"Analyze seed anomaly and propose speculative scenario:\n{seed.get('raw_residue', '')}"
    _ = llm_fn(phase1_prompt, 1.2)

    harness_keys = list(catalog.keys())
    phase2_prompt = (
        f"Synthesize structured JSON fuzzer experiment for catalog targets: {harness_keys}.\n"
        "Must adhere to target schema types and bounds."
    )
    raw_output = llm_fn(phase2_prompt, 0.2)
    cleaned = extract_markdown_json(raw_output)

    try:
        data = json.loads(cleaned)
    except Exception as e:
        raise ParameterValidationError(f"Invalid JSON from generator: {e}") from e

    harness_id = data.get("harness_id")
    if not harness_id or harness_id not in catalog:
        raise ParameterValidationError(f"Unknown or missing harness_id: {harness_id}")

    spec = catalog[harness_id]
    validated_params = decode_params(spec, data.get("parameters", {}))

    return Experiment(
        dream_id=str(data.get("dream_id", "dream_auto")),
        harness_id=harness_id,
        parameters=validated_params,
        expected=str(data.get("expected", "intra_vires_confirmed")),
        unexpected=tuple(data.get("unexpected", ("statutory_veto_reached",))),
        budget_ms=int(data.get("budget_ms", 1000)),
    )
