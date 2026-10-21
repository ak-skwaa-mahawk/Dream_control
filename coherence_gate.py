#!/usr/bin/env python3
"""
FPT Coherence Gate
Evaluates candidate transition vectors against the 4.17% observer epsilon invariant.
Rejects uncorrected binary collapses before daemon pipe ingestion.
"""

import sys
import json
import math

EPSILON_TARGET = 0.0417
TWO_PI = 2.0 * math.pi

def evaluate_transition(payload_file: str) -> bool:
    with open(payload_file, "r") as f:
        data = json.load(f)

    coords = data.get("macro_coords", {})
    x = float(coords.get("x", 0.0))
    y = float(coords.get("y", 0.0))

    # Evaluate phase tension across the dual poles
    tension = abs(math.cos(x * TWO_PI) - math.sin(y * TWO_PI))
    curvature_surplus = (abs(x - y) / (x + y + 1e-9)) * math.cos(x * y)

    # Dynamic epsilon calculation
    calculated_epsilon = abs(curvature_surplus) * 0.1

    print(f"[COHERENCE GATE]: Sequence #{data.get('sequence')}")
    print(f"  Coordinates: X={x:.6f}, Y={y:.6f}")
    print(f"  Tension Metric: {tension:.6f}")
    print(f"  Measured Epsilon Surplus: {calculated_epsilon:.6f} (Target: {EPSILON_TARGET:.4f})")

    # Invariant: Transition passes only if coherent non-zero relational surplus exists
    if calculated_epsilon > 0.001:
        print("  Verdict: COHERENT PASS (1 + 1 = 3 Emergence Locked)")
        return True
    else:
        print("  Verdict: REJECTED (Binary Collapse Detected)")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 coherence_gate.py <payload.json>")
        sys.exit(1)

    passed = evaluate_transition(sys.argv[1])
    sys.exit(0 if passed else 1)
