#!/usr/bin/env python3
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.async_ingress import AsyncTelemetryServer
from core.dream_contract import DEFAULT_CATALOG
from core.dream_daemon import DreamDaemon


class TestAsyncPipelineIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_full_async_ingress_to_replicate_dispatch_and_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            seed_bank = ws / "seeds.json"
            seed_bank.write_text("[]", encoding="utf-8")
            ledger = ws / "attestation_ledger.jsonl"
            corpus_file = ws / "corpus.json"
            corpus_file.write_text("{}", encoding="utf-8")
            sock_path = ws / "telemetry_pipeline.sock"
            key = b"async_pipeline_secret_key_2026"

            server = AsyncTelemetryServer(socket_path=sock_path)
            await server.start()

            def mock_llm(prompt: str, temp: float) -> str:
                return json.dumps({
                    "dream_id": "dream_async_pipeline_01",
                    "harness_id": "mcp_server_fuzzer",
                    "parameters": {
                        "method": "tools/call",
                        "uri": "file:///app/safe.txt",
                        "tool_name": "malicious_cmd",
                        "tool_args": json.dumps({"__proto__": {"injected": True}}),
                        "payload_size_kb": 1,
                        "timeout_s": 0.5,
                    },
                    "expected": "statutory_veto_reached",
                    "unexpected": ["panic"],
                    "budget_ms": 1000,
                })

            daemon = DreamDaemon(
                catalog={"mcp_server_fuzzer": DEFAULT_CATALOG["mcp_server_fuzzer"]},
                workspace_root=ws / "work",
                seed_bank_path=seed_bank,
                corpus_path=corpus_file,
                llm_callable=mock_llm,
                harness_tree=Path("harnesses").resolve(),
                attestation_ledger_path=ledger,
                attestation_key=key,
                k_replicates=3,
                tau=2.0,
            )

            try:
                # Transmit telemetry datagram packet
                client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                client.sendto(
                    json.dumps({
                        "harness_id": "mcp_server_fuzzer",
                        "reason": "buffer_boundary_exceeded",
                        "residue": "proto_escape",
                    }).encode("utf-8"),
                    str(sock_path),
                )
                client.close()

                # Let event loop drain datagram into async queue
                await asyncio.sleep(0.05)

                with mock.patch("core.dream_daemon.schedule_next_dream", return_value={
                    "mode": "telemetry_perturbation",
                    "seed_data": {"harness_id": "mcp_server_fuzzer", "raw_residue": "proto_escape"},
                }):
                    result = await daemon.async_run_cycle(async_server=server)

                self.assertIsNotNone(result)
                self.assertEqual(result["decision"], "promote_candidate")
                self.assertEqual(result["replicates"], 3)
                self.assertGreaterEqual(result["score"], 2.0)
            finally:
                server.close()
                daemon.close()

            # Verify cryptographic ledger
            script_path = Path("scripts/verify_attestation_ledger.py").resolve()
            v_res = subprocess.run(
                [sys.executable, str(script_path), "--ledger", str(ledger), "--key", "async_pipeline_secret_key_2026"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(v_res.returncode, 0)
            self.assertIn("[VERIFIED]", v_res.stdout)


if __name__ == "__main__":
    unittest.main()
