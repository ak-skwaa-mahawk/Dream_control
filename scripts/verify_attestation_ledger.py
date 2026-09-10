#!/usr/bin/env python3
"""
scripts/verify_attestation_ledger.py
Cryptographic verification tool for Dream_control attestation ledger artifacts.
Validates canonical SHA-256 payload digests and HMAC-SHA256 signatures against
a secret key using constant-time comparison.
"""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def canonical_encode_payload(payload: Dict[str, Any]) -> bytes:
    """Produces the deterministic canonical JSON byte representation of a payload."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_entry(
    entry: Dict[str, Any],
    secret_key: bytes,
    line_no: int,
) -> Tuple[bool, str]:
    """
    Validates an individual attestation entry:
    1. Schema presence (payload, digest_sha256, signature_hmac_sha256).
    2. Recalculates and matches SHA-256 digest of canonical payload.
    3. Recomputes and matches HMAC-SHA256 signature using constant-time comparison.
    """
    required_keys = {"payload", "digest_sha256", "signature_hmac_sha256"}
    if not required_keys.issubset(entry.keys()):
        missing = required_keys - set(entry.keys())
        return False, f"Line {line_no}: Missing required schema fields: {sorted(missing)}"

    payload = entry["payload"]
    if not isinstance(payload, dict):
        return False, f"Line {line_no}: Payload field must be a JSON object"

    canonical_bytes = canonical_encode_payload(payload)

    # 1. Verify SHA-256 digest
    computed_digest = hashlib.sha256(canonical_bytes).hexdigest()
    recorded_digest = entry["digest_sha256"]
    if not hmac.compare_digest(computed_digest, recorded_digest):
        return False, (
            f"Line {line_no}: SHA-256 digest mismatch (payload altered). "
            f"Expected: {computed_digest}, Found: {recorded_digest}"
        )

    # 2. Verify HMAC-SHA256 signature
    computed_sig = hmac.new(secret_key, canonical_bytes, hashlib.sha256).hexdigest()
    recorded_sig = entry["signature_hmac_sha256"]
    if not hmac.compare_digest(computed_sig, recorded_sig):
        return False, (
            f"Line {line_no}: HMAC-SHA256 signature invalid (key mismatch or signature forged). "
            f"Found: {recorded_sig}"
        )

    return True, f"Line {line_no}: OK (dream_id={payload.get('dream_id', 'unknown')})"


def verify_ledger(ledger_path: Path, secret_key: bytes) -> Tuple[bool, List[str]]:
    """Reads and validates all entries in an attestation ledger file."""
    if not ledger_path.is_file():
        return False, [f"Ledger file not found: {ledger_path}"]

    errors: List[str] = []
    total_entries = 0

    with ledger_path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            total_entries += 1
            try:
                entry = json.loads(line_str)
            except json.JSONDecodeError as err:
                errors.append(f"Line {idx}: Corrupted JSON record: {err}")
                continue

            valid, msg = verify_entry(entry, secret_key, idx)
            if not valid:
                errors.append(msg)

    if errors:
        return False, errors
    if total_entries == 0:
        return False, ["Ledger file contains no entries"]

    return True, [f"Verified {total_entries} ledger entries successfully."]


def parse_args():
    parser = argparse.ArgumentParser(description="Verify Dream_control HMAC-SHA256 attestation ledger")
    parser.add_argument("--ledger", type=Path, required=True, help="Path to attestation_ledger.jsonl")
    parser.add_argument("--key", type=str, default=None, help="Secret key as string")
    parser.add_argument("--key-file", type=Path, default=None, help="Path to file containing raw secret key")
    return parser.parse_args()


def main():
    args = parse_args()
    key_bytes: bytes

    if args.key_file and args.key_file.is_file():
        key_bytes = args.key_file.read_bytes().strip()
    elif args.key:
        key_bytes = args.key.encode("utf-8")
    else:
        print("Error: Either --key or --key-file must be provided", file=sys.stderr)
        sys.exit(2)

    valid, messages = verify_ledger(args.ledger, key_bytes)
    for msg in messages:
        if valid:
            print(f"[VERIFIED] {msg}")
        else:
            print(f"[REJECTED] {msg}", file=sys.stderr)

    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
