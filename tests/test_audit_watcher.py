#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest

from core.telemetry_seed import extract_audit_seeds, write_seed_bank
from scripts.watch_admission_log import parse_audit_entry_to_seed, tail_audit_log


class TestAuditWatcher(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.log_path = self.root / "audit_log.jsonl"
        self.seed_bank = self.root / "seed_bank.json"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_parse_audit_entry_to_seed(self):
        record = {
            "timestamp": "2026-09-09T16:00:00Z",
            "decision": "DENY",
            "reason": "statutory_veto: Landlock path escape attempted",
            "proposal": {"command": "cat /etc/shadow"},
        }
        seed = parse_audit_entry_to_seed(record, line_no=1)
        self.assertIsNotNone(seed)
        self.assertEqual(seed["seed_type"], "audit_rejection")
        self.assertIn("statutory_veto", seed["raw_residue"])

    def test_extract_audit_seeds_integration(self):
        records = [
            {"policy_passed": True, "command": "ls"},
            {"policy_passed": False, "reason": "veto_triggered", "proposal": {"target": "/sys"}},
        ]
        with self.log_path.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        seeds = extract_audit_seeds(self.log_path)
        self.assertEqual(len(seeds), 1)
        write_seed_bank(seeds, self.seed_bank)
        self.assertTrue(self.seed_bank.exists())

    def test_tail_audit_log_live_stream(self):
        self.log_path.write_text(
            json.dumps({"policy_passed": True, "command": "echo baseline"}) + "\n",
            encoding="utf-8",
        )

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "policy_passed": False,
                "reason": "buffer_boundary_exceeded",
                "proposal": {"command": "fuzz_input_overrun"},
            }) + "\n")
            f.flush()

        tail_audit_log(
            log_path=self.log_path,
            seed_bank_path=self.seed_bank,
            poll_interval_s=0.01,
            max_iterations=2,
            seek_to_end=False,
        )

        self.assertTrue(self.seed_bank.exists())
        seeds = json.loads(self.seed_bank.read_text(encoding="utf-8"))
        self.assertEqual(len(seeds), 1)
        self.assertIn("buffer_boundary_exceeded", seeds[0]["raw_residue"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
