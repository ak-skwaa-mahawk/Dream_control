#!/usr/bin/env python3
import unittest
import tempfile
from pathlib import Path
from core.telemetry_seed import extract_log_seeds, write_seed_bank

class TestTelemetrySeed(unittest.TestCase):

    def test_extract_anomalies(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            log_file = log_dir / "consensus.log"
            log_file.write_text(
                "INFO: cycle started\n"
                "WARN: admission timeout detected after 50ms\n"
                "INFO: status ok\n"
                "ERROR: Execution vetoed by statutory charter policy (exit 126)\n"
                "DEBUG: memory drift inside bounds\n"
            )
            seeds = extract_log_seeds(log_dir=log_dir, max_seeds=10)
            self.assertEqual(len(seeds), 3)
            
            # Check schema
            self.assertEqual(seeds[0]["seed_type"], "telemetry_outlier")
            self.assertEqual(seeds[0]["line_no"], 2)
            self.assertIn("timeout", seeds[0]["raw_residue"].lower())
            
            # Verify file serialization
            out_bank = log_dir / "seeds.json"
            write_seed_bank(seeds, out_bank)
            self.assertTrue(out_bank.is_file())

    def test_missing_directory_returns_empty(self):
        seeds = extract_log_seeds(log_dir=Path("/nonexistent/path"))
        self.assertEqual(seeds, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
