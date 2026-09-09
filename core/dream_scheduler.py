#!/usr/bin/env python3
"""
core/dream_scheduler.py
Proportional dispatch engine that preserves the 10% cold exploration term
regardless of whether the seed or outlier pools are empty.
"""

import random
import string
from typing import Mapping, Any
from core.dream_contract import HarnessSpec


def _generate_random_string(min_len: int, max_len: int) -> str:
    candidates = [
        "/etc/shadow",
        "/etc/passwd",
        "/workspace/test.txt",
        "/repo/manifest.json",
        "/var/log/audit.log",
        "/bin/sh",
    ]
    pick = random.choice(candidates)
    if min_len <= len(pick) <= max_len:
        return pick
    length = max(min_len, min(max_len, 16))
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def dispatch_cold_uniform(catalog: Mapping[str, HarnessSpec]) -> dict[str, Any]:
    cold_id = random.choice(list(catalog.keys()))
    spec = catalog[cold_id]
    uniform_params = {}
    for name, ps in spec.params.items():
        if ps.kind == "int":
            uniform_params[name] = random.randint(int(ps.lo), int(ps.hi))
        elif ps.kind == "str":
            if name == "charter_path":
                uniform_params[name] = "charter.json"
            elif name == "sock_path":
                uniform_params[name] = "/nonexistent.sock"
            elif name == "action_type":
                uniform_params[name] = random.choice(["SHELL_EXEC", "SHELL_READ", "MESH_LOG"])
            else:
                uniform_params[name] = _generate_random_string(int(ps.lo), int(ps.hi))
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
        mutated = dict(seed["parameters"])
        t_key = random.choice(list(spec.params.keys()))
        ps = spec.params[t_key]
        if ps.kind == "int":
            delta = random.choice([-1, 1]) * max(1, int((ps.hi - ps.lo) * 0.05))
            mutated[t_key] = max(int(ps.lo), min(int(ps.hi), int(mutated.get(t_key, ps.lo)) + delta))
        elif ps.kind == "str":
            mutated[t_key] = _generate_random_string(int(ps.lo), int(ps.hi))
        else:
            delta = random.choice([-1.0, 1.0]) * ((ps.hi - ps.lo) * 0.05)
            mutated[t_key] = round(max(ps.lo, min(ps.hi, float(mutated.get(t_key, ps.lo)) + delta)), 4)
        return {
            "mode": "seed_mutation",
            "harness_id": seed["harness_id"],
            "parameters": mutated,
        }

    if selected_mode == "telemetry_perturbation":
        outlier = random.choice(telemetry_outliers)
        return {
            "mode": "telemetry_perturbation",
            "seed_data": outlier,
        }

    return dispatch_cold_uniform(catalog)
