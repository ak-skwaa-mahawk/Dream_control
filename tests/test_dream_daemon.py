#!/usr/bin/env python3
import json
import unittest
import tempfile
from pathlib import Path

from core.dream_contract import HarnessSpec, ParamSpec
from core.dream_daemon import DreamDaemon

class TestDreamDaemon(unittest.TestCase):

    def test_daemon_cycle_and_corpus_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            seed_bank = tmp_path / "seeds.json"
            flaky_bank = tmp_path / "flaky_seeds.json"
            corpus_file = tmp_path / "corpus.json"
            runner = tmp_path / "runner.py"

            runner.write_text(
                "import argparse, json, sys\n"
                "from pathlib import Path\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--params', type=Path)\n"
                "parser.add_argument('--out', type=Path)\n"
                "args = parser.parse_args()\n"
                "args.out.write_text(json.dumps({'probes': {'statutory_veto_reached': True}}))\n",
                encoding="utf-8",
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
                flaky_bank_path=flaky_bank,
                corpus_path=corpus_file,
                llm_callable=mock_llm,
                harness_tree=tmp_path,
                k_replicates=3,
            )

            res1 = daemon.run_cycle()
            self.assertIsNotNone(res1)
            self.assertEqual(res1["decision"], "promote_candidate")
            self.assertEqual(res1["k_replicates"], 3)
            self.assertTrue(seed_bank.is_file())
            self.assertTrue(corpus_file.is_file())

            daemon2 = DreamDaemon(
                catalog={"test_harness": spec},
                workspace_root=workspace,
                seed_bank_path=seed_bank,
                flaky_bank_path=flaky_bank,
                corpus_path=corpus_file,
                llm_callable=mock_llm,
                harness_tree=tmp_path,
                k_replicates=3,
            )
            self.assertIn("test_harness", daemon2.corpus._corpus)
            self.assertEqual(len(daemon2.corpus._corpus["test_harness"]), 1)

    def test_flaky_seeds_isolated_to_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            seed_bank = tmp_path / "seeds.json"
            flaky_bank = tmp_path / "flaky_seeds.json"
            runner = tmp_path / "flaky_runner.py"

            counter_file = tmp_path / ".counter"
            counter_file.write_text("0", encoding="utf-8")

            runner_code = (
                "import argparse, json, sys\n"
                "from pathlib import Path\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--params', type=Path)\n"
                "parser.add_argument('--out', type=Path)\n"
                "args = parser.parse_args()\n"
                f"counter_p = Path('{counter_file}')\n"
                "val = int(counter_p.read_text().strip())\n"
                "counter_p.write_text(str(val + 1))\n"
                "is_even = (val % 2 == 0)\n"
                "args.out.write_text(json.dumps({'probes': {'statutory_veto_reached': is_even}}))\n"
            )
            runner.write_text(runner_code, encoding="utf-8")

            spec = HarnessSpec(
                harness_id="flaky_harness",
                target_subsystem="core",
                params={"count": ParamSpec(kind="int", lo=1, hi=10)},
                allowed_observables=frozenset(["statutory_veto_reached"]),
                runner_binary=runner,
            )

            daemon = DreamDaemon(
                catalog={"flaky_harness": spec},
                workspace_root=workspace,
                seed_bank_path=seed_bank,
                flaky_bank_path=flaky_bank,
                llm_callable=lambda p, t: "{}",
                harness_tree=tmp_path,
                k_replicates=3,
            )

            res = daemon.run_cycle()
            self.assertIsNotNone(res)
            self.assertEqual(res["decision"], "flaky")
            self.assertTrue(flaky_bank.is_file())
            self.assertFalse(seed_bank.is_file())


    def test_hyperparameter_tuning_honored(self):
        catalog = {self.spec.harness_id: self.spec} if hasattr(self, "spec") else getattr(self, "catalog", {})
        workspace = getattr(self, "workspace_root", getattr(self, "workspace", Path("/tmp")))
        seed_bank = getattr(self, "seed_bank_path", getattr(self, "seed_bank", Path("/tmp/seed.json")))
        harness_tree = getattr(self, "harness_tree", Path("/tmp/harnesses"))
        daemon = DreamDaemon(
            catalog=catalog,
            workspace_root=workspace,
            seed_bank_path=seed_bank,
            llm_callable=lambda prompt, temp: "{}",
            harness_tree=harness_tree,
            k_replicates=5,
            tau=3.5,
            consensus_threshold=0.90,
            phase1_temp=1.3,
            phase2_temp=0.1,
        )
        self.assertEqual(daemon.k_replicates, 5)
        self.assertEqual(daemon.tau, 3.5)
        self.assertEqual(daemon.consensus_threshold, 0.90)
        self.assertEqual(daemon.phase1_temp, 1.3)
        self.assertEqual(daemon.phase2_temp, 0.1)

    def test_decay_mode_and_alpha_honored(self):
        from core.dream_contract import DEFAULT_CATALOG
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = Path(tmpdir) / "ws"
            sb = Path(tmpdir) / "seed_bank.json"
            daemon = DreamDaemon(
                catalog=DEFAULT_CATALOG,
                workspace_root=ws,
                seed_bank_path=sb,
                decay_mode="steep_exponential",
                decay_alpha=0.75,
            )
            self.assertEqual(daemon.decay_mode, "steep_exponential")
            self.assertEqual(daemon.decay_alpha, 0.75)
            self.assertEqual(daemon.corpus.decay_mode, "steep_exponential")
            self.assertEqual(daemon.corpus.alpha, 0.75)

    def test_parse_args_decay_parameters(self):
        from core.dream_daemon import parse_args
        import sys
        orig_argv = sys.argv
        try:
            sys.argv = [
                "dream_daemon.py",
                "--decay-mode", "steep_exponential",
                "--decay-alpha", "1.2",
            ]
            args = parse_args()
            self.assertEqual(args.decay_mode, "steep_exponential")
            self.assertEqual(args.decay_alpha, 1.2)
        finally:
            sys.argv = orig_argv

    def test_unix_dgram_telemetry_listener_high_frequency_ingestion(self):
        import socket
        import json
        import tempfile
        from pathlib import Path
        from core.dream_contract import DEFAULT_CATALOG

        def mock_llm(prompt: str, temp: float) -> str:
            return json.dumps({"target_path": "/tmp/sandbox", "mode": "read"})

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            sock_path = str(base / "test_telemetry.sock")
            ws_root = base / "daemon_ws"
            sbank = base / "seeds.json"
            sbank.write_text("[]", encoding="utf-8")

            daemon = DreamDaemon(
                catalog=DEFAULT_CATALOG,
                workspace_root=ws_root,
                seed_bank_path=sbank,
                llm_callable=mock_llm,
                telemetry_sock=sock_path,
            )
            try:
                client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                for i in range(79):
                    pkt = {
                        "decision": "DENY",
                        "policy_passed": False,
                        "reason": f"stream_anomaly_{i % 5}",
                        "seq": i,
                    }
                    client_sock.sendto(json.dumps(pkt).encode("utf-8"), sock_path)
                client_sock.close()

                # Execute run_cycle which drains socket non-blockingly
                cycle_res = daemon.run_cycle()
                self.assertIsNotNone(cycle_res)
                self.assertGreaterEqual(len(daemon.live_telemetry_seeds), 79)

                # Verify seed bank received the 79 datagram seeds
                bank_data = json.loads(sbank.read_text(encoding="utf-8"))
                self.assertGreaterEqual(len(bank_data), 79)
            finally:
                daemon.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
