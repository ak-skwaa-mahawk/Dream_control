#!/usr/bin/env python3
"""
core/dream_scheduler.py
Proportional dispatch engine that preserves the 10% cold exploration term
regardless of whether the seed or outlier pools are empty.
"""

import random
from typing import Mapping, Any
from core.dream_contract import HarnessSpec


def dispatch_cold_uniform(catalog: Mapping[str, HarnessSpec]) -> dict[str, Any]:
    cold_id = random.choice(list(catalog.keys()))
    spec = catalog[cold_id]
    uniform_params = {}
    for name, ps in spec.params.items():
        if ps.kind == "int":
            uniform_params[name] = random.randint(int(ps.lo), int(ps.hi))
        else:
            uniform_params[name] = round(random.uniform(ps.lo, ps.hi), 4)
    return {
        "mode": "cold_uniform",
        "harness_id": cold_id,
        "parameters": uniform_params,
    }


def schedule_next_dream(
    promoted_seeds: list[dict[str, Any]],
    catalog: Mapping[str, HarnessSpec],
    telemetry_outliers: list[dict[str, Any]],
) -> dict[str, Any]:
    modes = []
    if promoted_seeds:
        modes.append(("seed_mutation", 0.70))
    if telemetry_outliers:
        modes.append(("telemetry_perturbation", 0.20))
    modes.append(("cold_uniform", 0.10))

    total = sum(w for _, w in modes)
    r = random.random() * total
    acc = 0.0

    selected_mode = "cold_uniform"
    for mode, w in modes:
        acc += w
        if r <= acc:
            selected_mode = mode
            break

    if selected_mode == "seed_mutation":
        seed = random.choice(promoted_seeds)
        spec = catalog[seed["harness_id"]]
        # Mutate single parameter
        mutated = dict(seed["parameters"])
        t_key = random.choice(list(spec.params.keys()))
        ps = spec.params[t_key]
        if ps.kind == "int":
            delta = random.choice([-1, 1]) * max(1, int((ps.hi - ps.lo) * 0.05))
            mutated[t_key] = max(int(ps.lo), min(int(ps.hi), int(mutated[t_key]) + delta))
        else:
            delta = (random.random() - 0.5) * (ps.hi - ps.lo) * 0.1
            mutated[t_key] = round(max(ps.lo, min(ps.hi, float(mutated[t_key]) + delta)), 4)
        return {
            "mode": "seed_mutation",
            "harness_id": seed["harness_id"],
            "parameters": mutated,
        }

    elif selected_mode == "telemetry_perturbation":
        return {
            "mode": "telemetry_perturbation",
            "seed_data": random.choice(telemetry_outliers),
        }

    return dispatch_cold_uniform(catalog)
