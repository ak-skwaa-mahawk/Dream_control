import json
import hashlib
import time
import sys

def stage_audit_payload(target, amount_usd, category, raw_evidence_bytes, seq_num, prev_root):
    evidence_root = "0x" + hashlib.sha256(raw_evidence_bytes).hexdigest()
    
    payload = {
        "sequence": seq_num,
        "previousRoot": prev_root,
        "activeMemoryIds": ["sovr-001", "fraud-audit-001"],
        "priorPolygon": [1.290142, 0.152780, 0.050000, 0.970960],
        "candidatePolygon": [1.289905, 0.152546, 0.050000, 0.971045],
        "macro_coords": {
            "x": 1.289905,
            "y": 0.152546
        },
        "lyapunov_exponent": -7.683965,
        "lineage": "audit_attestation_v130",
        "provenance_mask": "0x0000002B",
        "audit_attestation": {
            "target": target,
            "discrepancy_usd": amount_usd,
            "category": category,
            "evidence_root": evidence_root,
            "anchored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    }
    return payload

if __name__ == "__main__":
    sample_data = b"audit_sample_record_target_001_discrepancy_wash_trade"
    staged = stage_audit_payload(
        target="US-GRANT-SAMPLE-7741",
        amount_usd=1250000.00,
        category="procurement_fraud",
        raw_evidence_bytes=sample_data,
        seq_num=56,
        prev_root="0x45b8967d824a22c70dce8f185935bd09cda51b138bdf3dd5f32b13f4d797bda9"
    )
    with open("payload_seq56_audit.json", "w") as f:
        json.dump(staged, f, indent=2)
    print("Generated payload_seq56_audit.json successfully.")
