#!/usr/bin/env python3
"""
Notarizer Triad Quorum Signer for Sovereign Appliance Admission Gate.

- Evaluates Phase 1 challenge holding state (status=0xE007, challenge nonce).
- Collects / applies Ed25519 multi-signatures for Triad witness quorum (0x07 = Signers 0, 1, 2).
- Formats deterministic Phase 2 approval block for dataport injection (offset 0x400).
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    ed25519 = None


# Fixed 4 KB dataport layout specification:
# Offset 0x400: struct gate_approval (440 bytes)
#   uint32_t seq_id               (4 bytes)
#   uint8_t  witness_mask         (1 byte)   -> 0x07 (bits 0, 1, 2 set)
#   uint8_t  reserved[3]          (3 bytes)  -> canonical zero-padding
#   uint8_t  challenge_nonce[32]  (32 bytes) -> matches verdict at 0x600
#   uint8_t  signatures[6][64]    (384 bytes)-> up to 6 witness sigs, 64-byte Ed25519
APPROVAL_FORMAT = "<IB3s32s384s"
APPROVAL_SIZE = 424  # struct size matching C definition


def generate_dev_triad_keys(keys_dir: Path) -> List[Tuple[Path, Path]]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_pairs = []
    
    if ed25519 is None:
        raise RuntimeError("cryptography library required for Ed25519 operations")

    for idx in range(3):
        priv_path = keys_dir / f"notary_signer_{idx}.key"
        pub_path = keys_dir / f"notary_signer_{idx}.pub"
        
        if not priv_path.exists() or not pub_path.exists():
            priv_key = ed25519.Ed25519PrivateKey.generate()
            pub_key = priv_key.public_key()
            
            with open(priv_path, "wb") as f:
                f.write(priv_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_path, "wb") as f:
                f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ))
        key_pairs.append((priv_path, pub_path))
    return key_pairs


def sign_challenge(
    seq_id: int,
    challenge_nonce: bytes,
    key_paths: List[Path]
) -> bytes:
    """Signs (seq_id || challenge_nonce) with up to 6 signers and packs the 384-byte array."""
    if len(challenge_nonce) != 32:
        raise ValueError("challenge_nonce must be exactly 32 bytes")
        
    sign_message = struct.pack("<I", seq_id) + challenge_nonce
    packed_signatures = bytearray(384)  # 6 * 64

    for idx, key_path in enumerate(key_paths[:6]):
        with open(key_path, "rb") as f:
            raw_priv = f.read()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
        sig = priv_key.sign(sign_message)
        packed_signatures[idx * 64:(idx + 1) * 64] = sig

    return bytes(packed_signatures)


def build_approval_block(
    seq_id: int,
    challenge_nonce: bytes,
    witness_mask: int,
    packed_signatures: bytes
) -> bytes:
    reserved = b"\x00\x00\x00"
    return struct.pack(
        APPROVAL_FORMAT,
        seq_id,
        witness_mask,
        reserved,
        challenge_nonce,
        packed_signatures
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Notarizer Triad Quorum Signer for Admission Gate")
    parser.add_argument("--keys-dir", default="./workspace/notary_keys", help="Directory storing notary keys")
    parser.add_argument("--gen-keys", action="store_true", help="Generate 3-of-3 Triad test keys")
    parser.add_argument("--seq-id", type=int, default=1, help="Proposal sequence ID")
    parser.add_argument("--nonce-hex", help="32-byte challenge nonce in hex (emitted during status=0xE007)")
    parser.add_argument("--out-bin", help="Output path for packed 424-byte approval binary block")
    parser.add_argument("--out-hex", action="store_true", help="Print approval block as hex to stdout")
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)

    if args.gen_keys:
        pairs = generate_dev_triad_keys(keys_dir)
        print(f"[Notarizer] Triad keys initialized in {keys_dir}:")
        for priv, pub in pairs:
            print(f"  Signer: {priv.name} | {pub.name}")
        return 0

    if not args.nonce_hex:
        print("[Error] --nonce-hex is required to notarize a challenge hold.", file=sys.stderr)
        return 1

    try:
        challenge_nonce = bytes.fromhex(args.nonce_hex.strip())
    except ValueError:
        print("[Error] Invalid hex string for --nonce-hex", file=sys.stderr)
        return 1

    if len(challenge_nonce) != 32:
        print(f"[Error] Nonce must be 32 bytes (got {len(challenge_nonce)}).", file=sys.stderr)
        return 1

    # Ensure keys exist
    key_pairs = generate_dev_triad_keys(keys_dir)
    priv_keys = [pair[0] for pair in key_pairs]

    # Quorum mask for 3 signers = 0b00000111 = 0x07
    witness_mask = 0x07
    packed_sigs = sign_challenge(args.seq_id, challenge_nonce, priv_keys)
    approval_block = build_approval_block(args.seq_id, challenge_nonce, witness_mask, packed_sigs)

    if args.out_bin:
        out_path = Path(args.out_bin)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(approval_block)
        print(f"[Notarizer] Approval block written to {out_path} ({len(approval_block)} bytes)")

    if args.out_hex or not args.out_bin:
        print(approval_block.hex())

    return 0


if __name__ == "__main__":
    sys.exit(main())
