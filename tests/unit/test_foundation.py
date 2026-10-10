"""Unit tests for EdgeSentinel foundation components."""

import os
import tempfile
import time
import pytest

from edgesentinel.config import AppConfig, load_config
from edgesentinel.models import Alert, AlertStatus, Device, FlowRecord, NetworkEvent, Severity
from edgesentinel.platform_info import get_platform_info
from edgesentinel.storage.database import Database
from edgesentinel.monitoring.health import ResourceMonitor


def test_config_defaults():
    config = AppConfig()
    assert config.environment == "development"
    assert config.dashboard.port == 8080
    assert config.detection.port_scan.threshold_ports == 15
    assert config.detection.port_scan.enabled is True
    assert config.response.mode == "dry_run"


def test_config_invalid_rejection():
    with pytest.raises(Exception):
        AppConfig(dashboard={"port": 999999})

    with pytest.raises(Exception):
        AppConfig(response={"mode": "aggressive_hack"})


def test_network_event_model():
    event = NetworkEvent(
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        tcp_flags="SYN",
        packet_len=60,
        is_synthetic=True
    )
    assert event.src_ip == "192.168.1.50"
    assert event.dst_port == 80
    assert event.is_synthetic is True
    assert event.id is not None


def test_platform_info():
    info = get_platform_info()
    assert "os" in info
    assert "architecture" in info
    assert "total_ram_mb" in info
    assert info["is_windows"] is True or info["is_linux"] is True or info["os"] == "Darwin"


def test_database_crud_and_retention():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = Database(db_path=db_path)

        # 1. Insert and query events
        e1 = NetworkEvent(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, is_synthetic=True
        )
        e2 = NetworkEvent(
            src_ip="10.0.0.3", dst_ip="10.0.0.2", src_port=1001, dst_port=443, is_synthetic=True
        )
        db.insert_events_batch([e1, e2])

        events = db.get_events(limit=10)
        assert len(events) == 2

        # 2. Insert and query alert
        alert = Alert(
            detector_id="DET-TEST",
            severity=Severity.HIGH,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            title="Test Port Scan",
            description="Testing alert storage",
            evidence={"ports": [80, 443, 8080]},
            is_synthetic=True
        )
        db.insert_alert(alert)

        alerts = db.get_alerts(limit=10, severity="HIGH")
        assert len(alerts) == 1
        assert alerts[0].title == "Test Port Scan"
        assert alerts[0].evidence["ports"] == [80, 443, 8080]

        # 3. Update alert status
        db.update_alert_status(alert.id, AlertStatus.ACKNOWLEDGED)
        fetched = db.get_alert_by_id(alert.id)
        assert fetched is not None
        assert fetched.status == AlertStatus.ACKNOWLEDGED

        # 4. Upsert device
        dev = Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", observation_source="test")
        db.upsert_device(dev)
        devices = db.get_devices()
        assert len(devices) == 1
        assert devices[0].ip == "10.0.0.1"

        # 5. Stats
        stats = db.get_stats()
        assert stats["total_events"] == 2
        assert stats["total_alerts"] == 1
        assert stats["total_devices"] == 1

        # 6. Retention cleanup
        # Artificially insert old event
        old_event = NetworkEvent(
            timestamp=time.time() - (10 * 86400),
            src_ip="10.0.0.9", dst_ip="10.0.0.2", is_synthetic=True
        )
        db.insert_event(old_event)
        assert len(db.get_events(limit=10)) == 3
        purged = db.cleanup_retention(retention_days=7)
        assert purged >= 1
        assert len(db.get_events(limit=10)) == 2


def test_resource_monitor():
    monitor = ResourceMonitor()
    metrics = monitor.get_metrics(queue_size=5, events_processed=100)
    assert metrics.memory_used_mb > 0
    assert metrics.queue_size == 5
    assert metrics.events_processed == 100
    assert monitor.is_memory_critical(threshold_mb=10000.0) is False
