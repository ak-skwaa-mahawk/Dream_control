#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest

from core.telemetry_seed import extract_audit_rejections, write_seed_bank


class TestAuditWatcherIngestion(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.seed_bank = self.root / "seed_bank.json"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_rejection_record_converts_to_seed(self):
        record = {
            "timestamp": "2026-09-09T16:00:00Z",
            "decision": "DENY",
            "reason": "statutory_veto: Landlock path escape attempted",
            "attempted_command": "cat /etc/shadow",
            "subsystem": "admission_gate",
        }

        seeds = extract_audit_rejections([record])
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["seed_type"], "audit_rejection")
        self.assertIn("statutory_veto", seeds[0]["raw_residue"])

        write_seed_bank(seeds, self.seed_bank)
        self.assertTrue(self.seed_bank.exists())

        loaded = json.loads(self.seed_bank.read_text(encoding="utf-8"))
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["seed_type"], "audit_rejection")


if __name__ == "__main__":
    unittest.main(verbosity=2)
