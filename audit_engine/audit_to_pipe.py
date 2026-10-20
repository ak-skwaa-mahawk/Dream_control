import json
import hashlib
import time

SOLANA_VAULT = "2ChMGz6MeNoEgBuGj7aXYw1Mbc3DSzkZgwNwg1xGD1r9"

def stage_audit_payload(target, amount_usd, category, raw_evidence_bytes, seq_num, prev_root):
    evidence_root = "0x" + hashlib.sha256(raw_evidence_bytes).hexdigest()
    
    payload = {
        "sequence": seq_num,
        "previousRoot": prev_root,
        "activeMemoryIds": ["sovr-001", "fraud-audit-001"],
        "priorPolygon": [1.288720, 0.151376, 0.050000, 0.971470],
        "candidatePolygon": [1.288483, 0.151142, 0.050000, 0.971555],
        "macro_coords": {
            "x": 1.288483,
            "y": 0.151142
        },
        "lyapunov_exponent": -7.683965,
        "lineage": "audit_attestation_v130",
        "provenance_mask": "0x0000002B",
        "audit_attestation": {
            "target": target,
            "discrepancy_usd": amount_usd,
            "category": category,
            "evidence_root": evidence_root,
            "beneficiary_solana": SOLANA_VAULT,
            "anchored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    }
    return payload

if __name__ == "__main__":
    staged = stage_audit_payload(
        target="US-GRANT-SAMPLE-7741",
        amount_usd=1250000.00,
        category="procurement_fraud",
        raw_evidence_bytes=b"audit_sample_record_target_001_discrepancy_wash_trade",
        seq_num=62,
        prev_root="0x01aad165dc90e072fd2e6d8c7fb7c6bb7bc032e2e4faf52b285e74b30ea43517"
    )
    with open("payload_seq62.json", "w") as f:
        json.dump(staged, f, indent=2)
    print("Generated payload_seq62.json with bound Solana vault.")
