#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestAsyncDaemonCLI(unittest.TestCase):
    def test_daemon_cli_runs_in_async_mode(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            seed_bank = ws / "seeds.json"
            seed_bank.write_text("[]", encoding="utf-8")
            ledger = ws / "ledger.jsonl"

            res = subprocess.run(
                [
                    sys.executable,
                    "core/dream_daemon.py",
                    "--async",
                    "--max-cycles", "1",
                    "--workspace", str(ws / "run"),
                    "--seed-bank", str(seed_bank),
                    "--attestation-ledger", str(ledger),
                    "--sleep-interval", "0",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, msg=f"STDERR:\n{res.stderr}\nSTDOUT:\n{res.stdout}")
            self.assertIn("Async cycle #1 execution complete", res.stdout)


if __name__ == "__main__":
    unittest.main()
