import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.verify_attestation_ledger import (
    canonical_encode_payload,
    verify_entry,
    verify_ledger,
)


class TestVerifyAttestationLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.secret_key = b"super_secret_audit_key_123"

    def tearDown(self):
        self.tmp.cleanup()

    def _generate_record(self, payload: dict, key: bytes = None) -> dict:
        key_to_use = key or self.secret_key
        canonical = canonical_encode_payload(payload)
        digest = hashlib.sha256(canonical).hexdigest()
        sig = hmac.new(key_to_use, canonical, hashlib.sha256).hexdigest()
        return {
            "payload": payload,
            "digest_sha256": digest,
            "signature_hmac_sha256": sig,
        }

    def test_valid_ledger_passes(self):
        ledger = self.tmp_path / "ledger.jsonl"
        records = [
            self._generate_record({"dream_id": "dream_001", "decision": "promote_candidate", "score": 2.0}),
            self._generate_record({"dream_id": "dream_002", "decision": "promote_candidate", "score": 2.5}),
        ]
        with ledger.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        valid, msgs = verify_ledger(ledger, self.secret_key)
        self.assertTrue(valid)
        self.assertIn("Verified 2 ledger entries successfully", msgs[0])

    def test_tampered_payload_fails_digest_check(self):
        record = self._generate_record({"dream_id": "dream_001", "decision": "promote_candidate", "score": 2.0})
        # Tamper payload without updating digest
        record["payload"]["score"] = 9.99

        valid, msg = verify_entry(record, self.secret_key, line_no=1)
        self.assertFalse(valid)
        self.assertIn("SHA-256 digest mismatch", msg)

    def test_key_mismatch_fails_signature_check(self):
        wrong_key = b"wrong_key_456"
        record = self._generate_record(
            {"dream_id": "dream_001", "decision": "promote_candidate"},
            key=wrong_key,
        )
        valid, msg = verify_entry(record, self.secret_key, line_no=1)
        self.assertFalse(valid)
        self.assertIn("HMAC-SHA256 signature invalid", msg)

    def test_missing_fields_fails_schema_check(self):
        record = {"payload": {"dream_id": "test"}}
        valid, msg = verify_entry(record, self.secret_key, line_no=1)
        self.assertFalse(valid)
        self.assertIn("Missing required schema fields", msg)

    def test_empty_ledger_fails(self):
        ledger = self.tmp_path / "empty.jsonl"
        ledger.write_text("", encoding="utf-8")
        valid, msgs = verify_ledger(ledger, self.secret_key)
        self.assertFalse(valid)
        self.assertIn("contains no entries", msgs[0])

    def test_cli_execution_verification(self):
        ledger = self.tmp_path / "cli_ledger.jsonl"
        record = self._generate_record({"dream_id": "dream_cli", "decision": "promote_candidate"})
        ledger.write_text(json.dumps(record) + "\n", encoding="utf-8")

        script_path = Path(__file__).resolve().parents[1] / "scripts" / "verify_attestation_ledger.py"
        res = subprocess.run(
            [sys.executable, str(script_path), "--ledger", str(ledger), "--key", "super_secret_audit_key_123"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("[VERIFIED]", res.stdout)


if __name__ == "__main__":
    unittest.main()
