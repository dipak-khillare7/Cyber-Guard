#!/usr/bin/env python3
"""
Performance & Latency Benchmark Script: Measures average end-to-end detection pipeline latency (in milliseconds) over 100 flow analysis iterations.
"""
import os
import sys

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

import time
import statistics
from fastapi.testclient import TestClient
from app.main import app
from app.database.init_db import init_db
from app.core.config import settings

def run_latency_benchmark(num_requests: int = 100):
    init_db()
    client = TestClient(app)
    latencies = []
    if not settings.ADMIN_INITIAL_PASSWORD:
        raise RuntimeError("Configure ADMIN_INITIAL_PASSWORD before running the benchmark.")
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.ADMIN_USERNAME,
            "password": settings.ADMIN_INITIAL_PASSWORD,
        },
    )
    if login_response.status_code != 200:
        raise RuntimeError("Benchmark authentication failed.")
    headers = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

    print("=" * 70)
    print(f" BENCHMARK: Measuring Detection Engine Latency ({num_requests} requests)")
    print("=" * 70)

    sample_event = {
        "source_ip": "192.168.1.150",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 150000.0,
        "packet_count": 500,
        "byte_count": 250000,
        "syn_flag_count": 1,
        "ack_flag_count": 1
    }

    # Warmup
    client.post("/api/v1/detection/analyze", json=sample_event, headers=headers)

    for _ in range(num_requests):
        while True:
            t0 = time.perf_counter()
            response = client.post(
                "/api/v1/detection/analyze",
                json=sample_event,
                headers=headers,
            )
            t_elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if response.status_code != 429:
                break
            time.sleep(int(response.headers.get("Retry-After", "1")))
        assert response.status_code == 200
        latencies.append(t_elapsed_ms)

    avg_lat = statistics.mean(latencies)
    median_lat = statistics.median(latencies)
    min_lat = min(latencies)
    max_lat = max(latencies)

    print(f"\n[Benchmark Results over {num_requests} requests]:")
    print(f"  - Average End-to-End Latency : {avg_lat:.2f} ms")
    print(f"  - Median Latency             : {median_lat:.2f} ms")
    print(f"  - Minimum Latency            : {min_lat:.2f} ms")
    print(f"  - Maximum Latency            : {max_lat:.2f} ms")
    print("=" * 70)

if __name__ == "__main__":
    run_latency_benchmark()
