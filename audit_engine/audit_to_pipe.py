import json
import hashlib
import time

EVM_VERIFIER = "0xb09d703e8dc8f4e8bb0ec5d6fb40d96c23febf6e"
SOLANA_VAULT = "2ChMGz6MeNoEgBuGj7aXYw1Mbc3DSzkZgwNwg1xGD1r9"

def stage_audit_payload(target, amount_usd, category, raw_evidence_bytes, seq_num, prev_root):
    evidence_root = "0x" + hashlib.sha256(raw_evidence_bytes).hexdigest()
    
    payload = {
        "sequence": seq_num,
        "previousRoot": prev_root,
        "activeMemoryIds": ["sovr-001", "fraud-audit-001"],
        "priorPolygon": [1.288246, 0.150908, 0.050000, 0.971640],
        "candidatePolygon": [1.288009, 0.150674, 0.050000, 0.971725],
        "macro_coords": {
            "x": 1.288009,
            "y": 0.150674
        },
        "lyapunov_exponent": -7.683965,
        "lineage": "audit_attestation_v130",
        "provenance_mask": "0x0000002B",
        "audit_attestation": {
            "target": target,
            "discrepancy_usd": amount_usd,
            "category": category,
            "evidence_root": evidence_root,
            "evm_verifier": EVM_VERIFIER,
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
        seq_num=64,
        prev_root="0x8903f25378a8f3375e9274bbbf73f77436bd6328500d69b7467f003704f9e3fe"
    )
    with open("payload_seq64.json", "w") as f:
        json.dump(staged, f, indent=2)
    print("Generated payload_seq64.json with dual EVM/Solana routing.")
