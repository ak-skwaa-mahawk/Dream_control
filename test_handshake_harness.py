#!/usr/bin/env python3
import hashlib
import subprocess
import sys
from pathlib import Path
from ingress_firewall import inspect_ingress

def run_cmd(cmd, input_data=None):
    res = subprocess.run(
        cmd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True if isinstance(input_data, str) or input_data is None else False
    )
    stdout_txt = res.stdout if isinstance(res.stdout, str) else res.stdout.decode('utf-8', errors='replace')
    stderr_txt = res.stderr if isinstance(res.stderr, str) else res.stderr.decode('utf-8', errors='replace')

    if res.returncode != 0:
        print(f"[-] Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(f"[-] Exit code: {res.returncode}", file=sys.stderr)
        print(f"[-] STDOUT:\n{stdout_txt}", file=sys.stderr)
        print(f"[-] STDERR:\n{stderr_txt}", file=sys.stderr)
        sys.exit(res.returncode)
    return stdout_txt

def main():
    mock_payload = b'{"url": "https://sovereign.local/audit", "content": "admission test telemetry", "depth": 1}'

    # Ingress Security Firewall Pre-Flight Evaluation
    if not inspect_ingress("CI Pre-Flight", mock_payload.decode("utf-8"), {"frame_size": 424, "seq_id_bits": 32}):
        print("[-] Ingress firewall rejection: Payload or frame layout violation", file=sys.stderr)
        return 1

    print("[1/3] Testing Firecrawl Ingress & Gate Policy...")
    ingress_out = run_cmd([
        sys.executable,
        "firecrawl_ingress.py",
        "--source-id", "harness_run_01"
    ], input_data=mock_payload)
    print(ingress_out.strip())

    print("\n[2/3] Generating Triad Notarizer Approval Vector...")
    tip_nonce = hashlib.sha256(b"harness_run_01_tip_nonce").hexdigest()
    keys_dir = Path("workspace/notary_keys")
    keys_dir.mkdir(parents=True, exist_ok=True)

    if not (keys_dir / "notary_signer_0.key").exists():
        run_cmd([
            sys.executable,
            "notarizer_signer.py",
            "--gen-keys",
            "--keys-dir", str(keys_dir)
        ])

    notary_out = run_cmd([
        sys.executable,
        "notarizer_signer.py",
        "--keys-dir", str(keys_dir),
        "--seq-id", "42",
        "--nonce-hex", tip_nonce,
        "--out-bin", "workspace/harness_approval.bin"
    ])
    print(notary_out.strip())

    print("\n[3/3] Verifying Dataport Layout Binary Size...")
    approval_bin = Path("workspace/harness_approval.bin")
    if not approval_bin.exists():
        print(f"[-] Error: {approval_bin} was not created", file=sys.stderr)
        return 1

    size = approval_bin.stat().st_size
    if size != 424:
        print(f"[-] Error: expected 424 bytes, got {size}", file=sys.stderr)
        return 1

    print(f"Validation successful: Approval vector is {size} bytes, linked to tip {tip_nonce[:16]}...")
    return 0

if __name__ == "__main__":
    sys.exit(main())
