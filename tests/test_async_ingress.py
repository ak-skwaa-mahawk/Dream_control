#!/usr/bin/env python3
import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path

from core.async_ingress import AsyncTelemetryServer


class TestAsyncIngress(unittest.IsolatedAsyncioTestCase):
    async def test_socket_lifecycle_and_batch_drain(self):
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "telemetry.sock"
            server = AsyncTelemetryServer(socket_path=sock_path, queue_capacity=100)
            await server.start()

            try:
                self.assertTrue(sock_path.is_socket())

                # Transmit datagram packets using standard synchronous socket client
                client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                for i in range(10):
                    payload = json.dumps({"client_id": f"agent_{i}", "metric": i * 1.5}).encode("utf-8")
                    client.sendto(payload, str(sock_path))
                client.close()

                # Drain batch from server
                batch = await server.drain_batch(max_items=15, timeout_s=0.2)
                self.assertEqual(len(batch), 10)
                self.assertEqual(batch[0]["client_id"], "agent_0")
                self.assertEqual(batch[9]["metric"], 13.5)
            finally:
                server.close()
                self.assertFalse(sock_path.exists())

    async def test_queue_backpressure_drop(self):
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "burst.sock"
            # Strict bounded queue of capacity 5
            server = AsyncTelemetryServer(socket_path=sock_path, queue_capacity=5)
            await server.start()

            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                for i in range(20):
                    payload = json.dumps({"seq": i}).encode("utf-8")
                    client.sendto(payload, str(sock_path))
                client.close()

                # Allow async event loop ticks to process socket reads
                await asyncio.sleep(0.05)

                batch = await server.drain_batch(max_items=20, timeout_s=0.1)
                self.assertLessEqual(len(batch), 5)
                self.assertGreater(server.protocol.dropped_packets, 0)
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
