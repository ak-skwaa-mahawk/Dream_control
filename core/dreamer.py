#!/usr/bin/env python3
"""
core/dreamer.py
Two-phase hypothesis generation:
1. High-entropy perturbation from telemetry residue or invariants.
2. Low-entropy compilation into validated Experiment contracts.
"""

import re
import json
from typing import Any, Callable, Mapping
from core.dream_contract import HarnessSpec, Experiment, Observable
from core.experiment_validator import decode_params, ParameterValidationError


def extract_json_payload(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    if not (text.startswith("{") and text.endswith("}")):
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    return json.loads(text)


PERTURB_PROMPT_TEMPLATE = """[SYSTEM: PERTURBATION ENGINE - STAGE 1]
You are a fault-injection researcher testing system invariants.
Telemetry Residue / Seed:
{seed_context}

Explore an edge-case scenario where an invariant fails or drifts under load.
Output raw, high-entropy narrative describing the hypothesized failure mode.
Do not output code or JSON. Focus on the failure mechanics.
"""

COMPILE_PROMPT_TEMPLATE = """[SYSTEM: EXPERIMENT COMPILER - STAGE 2]
Map the following speculative failure scenario onto an executable experiment specification.

Available Harnesses and Parameters:
{catalog_summary}

Hypothesis Scenario:
{premise}

Emit strictly valid JSON matching this schema:
{{
  "dream_id": "dream_<unique_id>",
  "harness_id": "<must be in available harnesses>",
  "parameters": {{ <typed parameters within bounds> }},
  "expected": "<single expected Observable>",
  "unexpected": ["<unexpected Observables>"],
  "budget_ms": <integer wall clock budget in ms>
}}
"""


def format_catalog_summary(catalog: Mapping[str, HarnessSpec]) -> str:
    summary = {}
    for hid, spec in catalog.items():
        summary[hid] = {
            "target": spec.target_subsystem,
            "params": {
                name: {"kind": ps.kind, "bounds": [ps.lo, ps.hi]}
                for name, ps in spec.params.items()
            },
            "allowed_observables": sorted(list(spec.allowed_observables)),
        }
    return json.dumps(summary, indent=2)


def generate_experiment(
    seed: dict[str, Any],
    catalog: Mapping[str, HarnessSpec],
    llm_callable: Callable[[str, float], str],
) -> Experiment:
    """
    Runs the two-phase generation pipeline.
    llm_callable(prompt: str, temperature: float) -> str
    """
    # Phase 1: High-entropy perturbation
    seed_context = json.dumps(seed, sort_keys=True)
    perturb_prompt = PERTURB_PROMPT_TEMPLATE.format(seed_context=seed_context)
    premise = llm_callable(perturb_prompt, 1.1)

    # Phase 2: Low-entropy compilation
    catalog_summary = format_catalog_summary(catalog)
    compile_prompt = COMPILE_PROMPT_TEMPLATE.format(
        catalog_summary=catalog_summary,
        premise=premise.strip(),
    )
    compiled_raw = llm_callable(compile_prompt, 0.2)

    try:
        raw_payload = extract_json_payload(compiled_raw)
    except (json.JSONDecodeError, AttributeError) as err:
        raise ParameterValidationError(f"Compiler produced invalid JSON: {err}") from err

    harness_id = raw_payload.get("harness_id")
    if harness_id not in catalog:
        raise ParameterValidationError(f"Unknown harness_id selected: {harness_id}")

    spec = catalog[harness_id]
    validated_params = decode_params(spec, raw_payload.get("parameters", {}))

    expected: Observable = raw_payload.get("expected", "")
    if expected not in spec.allowed_observables and expected not in ("timeout", "panic"):
        raise ParameterValidationError(f"Disallowed expected observable: {expected}")

    unexpected = tuple(
        u for u in raw_payload.get("unexpected", [])
        if u in spec.allowed_observables or u in ("timeout", "panic")
    )

    budget_ms = raw_payload.get("budget_ms", 1000)
    if not isinstance(budget_ms, int) or isinstance(budget_ms, bool) or budget_ms <= 0:
        budget_ms = 1000

    return Experiment(
        dream_id=str(raw_payload.get("dream_id", "dream_anon")),
        harness_id=harness_id,
        parameters=validated_params,
        expected=expected,
        unexpected=unexpected,
        budget_ms=min(budget_ms, 5000),  # Hard upper bound
    )
