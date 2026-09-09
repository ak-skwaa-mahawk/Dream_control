#!/usr/bin/env python3
"""
core/experiment_validator.py
Decodes and validates raw dictionary payloads against strict HarnessSpec schemas.
"""

from core.dream_contract import HarnessSpec


class ParameterValidationError(Exception):
    pass


def decode_params(spec: HarnessSpec, raw: dict) -> dict[str, int | float]:
    out: dict[str, int | float] = {}
    extra = set(raw) - set(spec.params)
    if extra:
        raise ParameterValidationError(f"unknown params: {sorted(extra)}")

    for name, ps in spec.params.items():
        if name not in raw:
            raise ParameterValidationError(f"missing parameter: {name}")
        val = raw[name]

        # Explicit bool check: isinstance(True, int) is True in Python
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ParameterValidationError(f"parameter '{name}' is not numeric")

        if ps.kind == "int":
            if not isinstance(val, int) or isinstance(val, bool):
                raise ParameterValidationError(f"parameter '{name}' must be int")
            decoded: int | float = val
        else:
            decoded = float(val)

        if not (ps.lo <= decoded <= ps.hi):
            raise ParameterValidationError(
                f"parameter '{name}' value {decoded} out of bounds [{ps.lo}, {ps.hi}]"
            )
        out[name] = decoded

    return out
