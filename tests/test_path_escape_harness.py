#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class TestPathEscapeHarness(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp_dir.name)
        self.harness_path = Path("harnesses/path_escape_fuzzer.py").resolve()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_intra_vires_when_path_inside_workspace(self):
        inside_file = self.workspace / "local_test.txt"
        inside_file.write_text("safe_local_data\n", encoding="utf-8")

        params = {
            "target_path": str(inside_file),
            "mode": "read",
            "use_symlink": False,
        }
        (self.workspace / "params.json").write_text(json.dumps(params), encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(self.harness_path)],
            cwd=str(self.workspace),
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0)
        out_file = self.workspace / "out.json"
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["signal"], "intra_vires_confirmed")
        self.assertEqual(data["probes"]["sandbox_enforced"], 1)

    def test_statutory_veto_on_unreadable_system_path(self):
        params = {
            "target_path": "/nonexistent_sandbox_escape/forbidden/path",
            "mode": "read",
            "use_symlink": False,
        }
        (self.workspace / "params.json").write_text(json.dumps(params), encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(self.harness_path)],
            cwd=str(self.workspace),
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0)
        out_file = self.workspace / "out.json"
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["signal"], "statutory_veto_reached")

    def test_symlink_escape_detection(self):
        params = {
            "target_path": "/dev/null",
            "mode": "read",
            "use_symlink": True,
        }
        (self.workspace / "params.json").write_text(json.dumps(params), encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(self.harness_path)],
            cwd=str(self.workspace),
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0)
        out_file = self.workspace / "out.json"
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertIn(data["signal"], {"statutory_veto_reached", "ultra_vires_detected"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
