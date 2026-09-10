#!/usr/bin/env python3
"""
benchmarks/bench_async_pipeline.py
Performance benchmark for Dream_control asynchronous datagram ingestion and parallel cell replicates.
"""

import argparse
import asyncio
import json
import socket
import statistics
import tempfile
import time
from pathlib import Path

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.async_ingress import AsyncTelemetryServer
from core.dream_contract import DEFAULT_CATALOG
from core.warden import async_execute_replicates, execute_in_cell


async def benchmark_ingestion_throughput(
    packet_count: int = 20_000,
    burst_size: int = 128,
    queue_capacity: int = 50_000,
) -> dict[str, float]:
    """Measures peak sustained UDP/UNIX datagram throughput and batch drainage latency."""
    with tempfile.TemporaryDirectory() as td:
        sock_path = Path(td) / "bench_telemetry.sock"
        server = AsyncTelemetryServer(socket_path=sock_path, queue_capacity=queue_capacity)
        await server.start()

        payload = json.dumps({
            "harness_id": "mcp_server_fuzzer",
            "reason": "buffer_boundary_exceeded",
            "residue": "x" * 128,
            "metric": 42.0,
        }).encode("utf-8")

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        client_sock.setblocking(False)

        t_send_start = time.perf_counter()
        sent = 0
        for _ in range(packet_count):
            try:
                client_sock.sendto(payload, str(sock_path))
                sent += 1
            except BlockingIOError:
                await asyncio.sleep(0.0001)
                try:
                    client_sock.sendto(payload, str(sock_path))
                    sent += 1
                except BlockingIOError:
                    pass
        client_sock.close()
        t_send_end = time.perf_counter()

        # Drain the server queue
        drained = 0
        t_drain_start = time.perf_counter()
        while drained < sent:
            batch = await server.drain_batch(max_items=burst_size, timeout_s=0.01)
            if not batch:
                break
            drained += len(batch)
        t_drain_end = time.perf_counter()

        server.close()

        send_duration = max(1e-6, t_send_end - t_send_start)
        drain_duration = max(1e-6, t_drain_end - t_drain_start)

        return {
            "packets_sent": sent,
            "packets_drained": drained,
            "packets_dropped": server.protocol.dropped_packets if server.protocol else 0,
            "send_rate_pps": sent / send_duration,
            "drain_rate_pps": drained / drain_duration,
            "send_duration_s": send_duration,
            "drain_duration_s": drain_duration,
        }


async def benchmark_replicate_concurrency(
    iterations: int = 5,
    k_replicates: int = 3,
) -> dict[str, float]:
    """Benchmarks parallel asyncio.gather replicate execution against sequential execution."""
    spec = DEFAULT_CATALOG["mcp_server_fuzzer"]
    params = {
        "method": "ping",
        "uri": "file:///app/safe.txt",
        "tool_name": "echo",
        "tool_args": "{}",
        "payload_size_kb": 1,
        "timeout_s": 0.5,
    }

    harness_tree = Path("harnesses").resolve()

    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)

        # 1. Warm-up
        await async_execute_replicates(
            spec=spec,
            validated_params=params,
            budget_ms=1000,
            workspace_root=ws / "warmup",
            harness_tree=harness_tree,
            k=1,
            require_isolation=False,
        )

        # 2. Parallel benchmark
        parallel_latencies: list[float] = []
        for i in range(iterations):
            t0 = time.perf_counter()
            traces = await async_execute_replicates(
                spec=spec,
                validated_params=params,
                budget_ms=1000,
                workspace_root=ws / f"par_{i}",
                harness_tree=harness_tree,
                k=k_replicates,
                require_isolation=False,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert len(traces) == k_replicates
            parallel_latencies.append(elapsed_ms)

        # 3. Sequential baseline benchmark
        sequential_latencies: list[float] = []
        for i in range(iterations):
            t0 = time.perf_counter()
            for _ in range(k_replicates):
                execute_in_cell(
                    spec=spec,
                    validated_params=params,
                    budget_ms=1000,
                    workspace_root=ws / f"seq_{i}",
                    harness_tree=harness_tree,
                    require_isolation=False,
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            sequential_latencies.append(elapsed_ms)

    avg_par = statistics.mean(parallel_latencies)
    avg_seq = statistics.mean(sequential_latencies)
    speedup = avg_seq / avg_par if avg_par > 0 else 1.0

    return {
        "k_replicates": k_replicates,
        "iterations": iterations,
        "parallel_avg_ms": avg_par,
        "parallel_min_ms": min(parallel_latencies),
        "parallel_max_ms": max(parallel_latencies),
        "sequential_avg_ms": avg_seq,
        "speedup_factor": speedup,
    }


def main():
    parser = argparse.ArgumentParser(description="Dream_control Pipeline Benchmark")
    parser.add_argument("--packets", type=int, default=10_000, help="Total packets for datagram ingress test")
    parser.add_argument("--burst-size", type=int, default=256, help="Batch drain chunk size")
    parser.add_argument("--k", type=int, default=3, help="Replicate factor K for concurrency test")
    parser.add_argument("--replicate-runs", type=int, default=5, help="Number of iteration runs for replicate latency")
    args = parser.parse_args()

    print("==================================================================")
    print("      DREAM_CONTROL ASYNC PIPELINE PERFORMANCE BENCHMARK          ")
    print("==================================================================")

    print(f"\n[1/2] Benchmarking Ingress Datagram Ingestion ({args.packets:,} packets)...")
    ingres_stats = asyncio.run(benchmark_ingestion_throughput(
        packet_count=args.packets,
        burst_size=args.burst_size,
    ))
    print(f"  - Packets Transmitted : {ingres_stats['packets_sent']:,}")
    print(f"  - Packets Drained     : {ingres_stats['packets_drained']:,}")
    print(f"  - Packets Dropped     : {ingres_stats['packets_dropped']:,}")
    print(f"  - Send Throughput     : {ingres_stats['send_rate_pps']:,.1f} packets/sec")
    print(f"  - Drain Throughput    : {ingres_stats['drain_rate_pps']:,.1f} packets/sec")
    print(f"  - Batch Drain Time    : {ingres_stats['drain_duration_s'] * 1000:.2f} ms")

    print(f"\n[2/2] Benchmarking Cell Replicates Latency (K={args.k}, Runs={args.replicate_runs})...")
    concur_stats = asyncio.run(benchmark_replicate_concurrency(
        iterations=args.replicate_runs,
        k_replicates=args.k,
    ))
    print(f"  - Sequential Mean Latency : {concur_stats['sequential_avg_ms']:.2f} ms")
    print(f"  - Parallel Mean Latency   : {concur_stats['parallel_avg_ms']:.2f} ms")
    print(f"  - Parallel Min Latency    : {concur_stats['parallel_min_ms']:.2f} ms")
    print(f"  - Parallel Max Latency    : {concur_stats['parallel_max_ms']:.2f} ms")
    print(f"  - Concurrency Speedup     : {concur_stats['speedup_factor']:.2f}x")
    print("\n==================================================================")


if __name__ == "__main__":
    main()
