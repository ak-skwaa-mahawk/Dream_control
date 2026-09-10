import datetime
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec
from core.dream_daemon import DreamDaemon


class TestAttestationSigning(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)
        self.workspace_root = self.base_dir / "workspace"
        self.seed_bank = self.base_dir / "seeds.json"
        self.seed_bank.write_text("[]", encoding="utf-8")
        self.ledger_path = self.base_dir / "ledger.jsonl"
        self.secret_key = b"super_secret_audit_key_1234"

        self.runner = self.base_dir / "runner.py"
        self.runner.write_text(
            "import argparse, json, sys\n"
            "from pathlib import Path\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_argument('--params', type=Path)\n"
            "parser.add_argument('--out', type=Path)\n"
            "args = parser.parse_args()\n"
            "args.out.write_text(json.dumps({'probes': {'statutory_veto_reached': True}}))\n",
            encoding="utf-8",
        )

        self.spec = HarnessSpec(
            harness_id="test_harness",
            target_subsystem="core",
            params={"count": ParamSpec(kind="int", lo=1, hi=10)},
            allowed_observables=frozenset(["statutory_veto_reached"]),
            runner_binary=self.runner,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_promotion_generates_valid_signed_attestation(self):
        def mock_llm(prompt: str, temp: float) -> str:
            return json.dumps({
                "dream_id": "dream_mock",
                "harness_id": "test_harness",
                "parameters": {"count": 5},
                "expected": "statutory_veto_reached",
                "unexpected": [],
                "budget_ms": 500,
            })

        daemon = DreamDaemon(
            catalog={"test_harness": self.spec},
            workspace_root=self.workspace_root,
            seed_bank_path=self.seed_bank,
            llm_callable=mock_llm,
            harness_tree=self.base_dir,
            attestation_ledger_path=self.ledger_path,
            attestation_key=self.secret_key,
            k_replicates=3,
        )
        try:
            res = daemon.run_cycle()
            self.assertIsNotNone(res)
            self.assertEqual(res["decision"], "promote_candidate")
            attestation = res.get("attestation")
            self.assertIsNotNone(attestation)

            self.assertTrue(self.ledger_path.is_file())
            lines = self.ledger_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)

            entry = json.loads(lines[0])
            self.assertEqual(entry["version"], "1.0")

            canonical_bytes = json.dumps(entry["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected_digest = hashlib.sha256(canonical_bytes).hexdigest()
            self.assertEqual(entry["digest_sha256"], expected_digest)

            expected_sig = hmac.new(self.secret_key, canonical_bytes, hashlib.sha256).hexdigest()
            self.assertEqual(entry["signature_hmac_sha256"], expected_sig)

            tampered_bytes = canonical_bytes.replace(b"promote_candidate", b"vetoed_rejection")
            tampered_sig = hmac.new(self.secret_key, tampered_bytes, hashlib.sha256).hexdigest()
            self.assertNotEqual(entry["signature_hmac_sha256"], tampered_sig)
        finally:
            daemon.close()


if __name__ == "__main__":
    unittest.main()
