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


    def test_concurrent_watcher_ingestion_and_daemon_scheduling(self):
        import time
        import subprocess
        import json
        from pathlib import Path

        base_dir = Path(self.tmp_dir.name)
        log_file = base_dir / "live_audit_stream.jsonl"
        seed_bank = base_dir / "live_seed_bank.json"
        ws = base_dir / "daemon_ws"
        log_file.touch()

        # Seed initial bank from template if available, else empty list
        tmpl = Path("seeds/seed_bank_template.json")
        initial_seeds = json.loads(tmpl.read_text(encoding="utf-8")) if tmpl.exists() else []
        seed_bank.write_text(json.dumps(initial_seeds), encoding="utf-8")
        base_count = len(initial_seeds)

        # Start live watcher
        watcher = subprocess.Popen(
            [
                "python3", "scripts/watch_admission_log.py",
                "--audit-log", str(log_file),
                "--seed-bank", str(seed_bank),
                "--poll-interval", "0.05",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.15)

            # Emit denial anomaly
            entry = {
                "timestamp": time.time(),
                "decision": "DENY",
                "policy_passed": False,
                "reason": "buffer_boundary_exceeded",
                "harness_id": "unix_sock_fuzzer",
                "parameters": {"payload_len": 65536, "use_abstract": 0, "pass_descriptor": 0},
            }
            with log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            # Let watcher ingest
            time.sleep(0.25)

            # Run 2 daemon cycles concurrently
            daemon = subprocess.run(
                [
                    "python3", "core/dream_daemon.py",
                    "--max-cycles", "2",
                    "--sleep-interval", "0.01",
                    "--workspace", str(ws),
                    "--seed-bank", str(seed_bank),
                    "--decay-mode", "steep_exponential",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(daemon.returncode, 0, f"Daemon failed: {daemon.stderr}")

            # Verify seed bank received new anomaly
            updated = json.loads(seed_bank.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(updated), base_count + 1)
            self.assertTrue(any(s.get("raw_residue") == "buffer_boundary_exceeded" for s in updated))
        finally:
            watcher.terminate()
            try:
                watcher.wait(timeout=2.0)
            except Exception:
                watcher.kill()
            if watcher.stdout:
                watcher.stdout.close()
            if watcher.stderr:
                watcher.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
