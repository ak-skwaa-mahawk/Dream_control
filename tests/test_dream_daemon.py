#!/usr/bin/env python3
import json
import unittest
import tempfile
from pathlib import Path
from core.dream_contract import HarnessSpec, ParamSpec
from core.dream_daemon import DreamDaemon

class TestDreamDaemon(unittest.TestCase):

    def test_daemon_cycle_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            seed_bank = tmp_path / "seeds.json"
            runner = tmp_path / "runner.py"

            runner.write_text(
                "import argparse, json, sys\n"
                "from pathlib import Path\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--params', type=Path)\n"
                "parser.add_argument('--out', type=Path)\n"
                "args = parser.parse_args()\n"
                "args.out.write_text(json.dumps({'probes': {'statutory_veto_reached': True}}))\n"
            )

            spec = HarnessSpec(
                harness_id="test_harness",
                target_subsystem="core",
                params={"count": ParamSpec(kind="int", lo=1, hi=10)},
                allowed_observables=frozenset(["statutory_veto_reached"]),
                runner_binary=runner,
            )

            def mock_llm(prompt, temp):
                return json.dumps({
                    "dream_id": "dream_mock",
                    "harness_id": "test_harness",
                    "parameters": {"count": 5},
                    "expected": "statutory_veto_reached",
                    "unexpected": [],
                    "budget_ms": 500,
                })

            daemon = DreamDaemon(
                catalog={"test_harness": spec},
                workspace_root=workspace,
                seed_bank_path=seed_bank,
                llm_callable=mock_llm,
                harness_tree=tmp_path,
            )

            result = daemon.run_cycle()
            self.assertIsNotNone(result)
            self.assertIn("decision", result)
            self.assertTrue(seed_bank.is_file())

if __name__ == "__main__":
    unittest.main(verbosity=2)
