#!/usr/bin/env python3
"""
core/async_ingress.py
High-throughput non-blocking UNIX datagram telemetry listener for Dream_control.
"""

import asyncio
import json
import logging
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

logger = logging.getLogger("async_ingress")
DEFAULT_QUEUE_CAPACITY = 10_000
MAX_DATAGRAM_BYTES = 65_536


class TelemetryDatagramProtocol(asyncio.DatagramProtocol):
    """Event-driven datagram listener draining kernel UDP/UNIX buffers into an asyncio queue."""

    def __init__(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self.queue = queue
        self.transport: asyncio.DatagramTransport | None = None
        self.dropped_packets: int = 0
        self.received_packets: int = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.received_packets += 1
        if len(data) > MAX_DATAGRAM_BYTES:
            self.dropped_packets += 1
            return

        try:
            record = json.loads(data.decode("utf-8"))
            if not isinstance(record, dict):
                self.dropped_packets += 1
                return

            self.queue.put_nowait(record)
        except asyncio.QueueFull:
            self.dropped_packets += 1
            if self.dropped_packets % 500 == 1:
                logger.warning(
                    f"Telemetry ingress queue saturated (capacity={self.queue.maxsize}). Dropping packets."
                )
        except Exception:
            self.dropped_packets += 1

    def error_received(self, exc: Exception) -> None:
        logger.error(f"Datagram socket transport error: {exc}")

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning(f"Datagram connection terminated with exception: {exc}")


class AsyncTelemetryServer:
    """Manages the socket lifecycle and non-blocking batch stream consumption."""

    def __init__(
        self,
        socket_path: Path,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
    ) -> None:
        self.socket_path = socket_path.resolve()
        self.queue_capacity = queue_capacity
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_capacity)
        self.transport: asyncio.DatagramTransport | None = None
        self.protocol: TelemetryDatagramProtocol | None = None
        self._raw_sock: socket.socket | None = None

    async def start(self) -> None:
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        raw_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        raw_sock.bind(str(self.socket_path))
        raw_sock.setblocking(False)
        self._raw_sock = raw_sock

        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: TelemetryDatagramProtocol(self.queue),
            sock=raw_sock,
        )
        self.transport = transport
        self.protocol = protocol  # type: ignore[assignment]
        logger.info(f"Async telemetry socket listening on {self.socket_path}")

    async def drain_batch(self, max_items: int = 128, timeout_s: float = 0.05) -> list[dict[str, Any]]:
        """Collects available buffered records up to max_items within a timeout window."""
        items: list[dict[str, Any]] = []
        deadline = asyncio.get_running_loop().time() + timeout_s

        while len(items) < max_items:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=max(0.001, remaining))
                items.append(item)
                self.queue.task_done()
            except asyncio.TimeoutError:
                break

        return items

    async def stream_batches(
        self, max_items: int = 128, timeout_s: float = 0.05
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Yields continuous batches for ingestion loops."""
        while self.transport and not self.transport.is_closing():
            batch = await self.drain_batch(max_items=max_items, timeout_s=timeout_s)
            if batch:
                yield batch
            else:
                await asyncio.sleep(0.01)

    def close(self) -> None:
        if self.transport and not self.transport.is_closing():
            self.transport.close()
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except OSError:
                pass
            self._raw_sock = None
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass
