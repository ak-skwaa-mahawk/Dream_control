#!/usr/bin/env python3
"""
core/experiment_validator.py
Validates raw experiment parameter mappings against HarnessSpec bounds and strict types.
"""

from typing import Any
from core.dream_contract import HarnessSpec


class ParameterValidationError(Exception):
    pass


def decode_params(spec: HarnessSpec, raw: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    extra = set(raw) - set(spec.params)
    if extra:
        raise ParameterValidationError(f"unknown params: {sorted(extra)}")

    for name, ps in spec.params.items():
        if name not in raw:
            raise ParameterValidationError(f"missing param: {name}")
        val = raw[name]

        if ps.kind == "str":
            if not isinstance(val, str):
                raise ParameterValidationError(f"parameter '{name}' is not string")
            if not (ps.lo <= len(val) <= ps.hi):
                raise ParameterValidationError(
                    f"parameter '{name}' length {len(val)} out of bounds [{ps.lo}, {ps.hi}]"
                )
            out[name] = val
        elif ps.kind == "int":
            # Strict int check: reject bools, floats, and numeric strings
            if isinstance(val, bool) or not isinstance(val, int):
                raise ParameterValidationError(f"parameter '{name}' must be strict int, got {type(val).__name__}")
            if not (ps.lo <= val <= ps.hi):
                raise ParameterValidationError(
                    f"parameter '{name}' value {val} out of bounds [{ps.lo}, {ps.hi}]"
                )
            out[name] = val
        elif ps.kind == "float":
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ParameterValidationError(f"parameter '{name}' must be numeric")
            val_f = float(val)
            if not (ps.lo <= val_f <= ps.hi):
                raise ParameterValidationError(
                    f"parameter '{name}' value {val_f} out of bounds [{ps.lo}, {ps.hi}]"
                )
            out[name] = val_f

    return out
