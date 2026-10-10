"""Repeatable load, stress, and bounded memory tests for EdgeSentinel."""

import os
import tempfile
import time
import pytest
import psutil

from edgesentinel.analysis.pipeline import EventPipeline
from edgesentinel.config import AppConfig
from edgesentinel.simulation.generator import SyntheticTrafficGenerator
from edgesentinel.storage.database import Database


def test_sustained_load_and_memory_boundedness():
    """Verify that processing 1,000+ events maintains bounded queues and memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "stress_test.db")
        config = AppConfig(
            storage={"database_path": db_path, "batch_size": 100},
            monitoring={"max_queue_size": 2000}
        )
        db = Database(db_path=db_path)
        pipeline = EventPipeline(config=config, db=db)

        gen = SyntheticTrafficGenerator(seed=999)
        process = psutil.Process(os.getpid())
        rss_start_mb = process.memory_info().rss / (1024 * 1024)

        # Generate 1,000 heterogeneous network events
        events = []
        for i in range(20):
            events.extend(gen.generate_normal_tcp(src_ip=f"10.0.0.{i+1}", count=20))
            events.extend(gen.generate_normal_udp(src_ip=f"10.0.0.{i+1}", count=10))
            events.extend(gen.generate_port_scan(src_ip=f"10.1.0.{i+1}", ports=range(20, 35)))

        total_events = len(events)
        assert total_events >= 1000

        # Ingest and benchmark
        t_start = time.perf_counter()
        alerts = pipeline.ingest_events(events)
        t_elapsed = time.perf_counter() - t_start

        throughput = total_events / max(t_elapsed, 0.001)
        rss_end_mb = process.memory_info().rss / (1024 * 1024)
        rss_growth_mb = rss_end_mb - rss_start_mb

        # 1. Performance checks
        assert throughput > 500.0, f"Throughput {throughput:.1f} ev/s is below acceptable benchmark"
        assert rss_end_mb < 350.0, f"Process RSS {rss_end_mb:.1f} MB exceeded 350 MB target budget"
        assert len(alerts) >= 20  # Port scan alerts generated

        # 2. Database persistence check
        stats = db.get_stats()
        assert stats["total_events"] == total_events
        assert stats["total_alerts"] >= 20

        # 3. Clean restart test
        db.close()
        db_reopened = Database(db_path=db_path)
        stats_reopened = db_reopened.get_stats()
        assert stats_reopened["total_events"] == total_events
        assert stats_reopened["total_alerts"] == stats["total_alerts"]
        db_reopened.close()
