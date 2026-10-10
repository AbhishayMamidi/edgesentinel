"""End-to-End integration tests for EdgeSentinel pipeline, storage, and dashboard API."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from edgesentinel.analysis.pipeline import EventPipeline
from edgesentinel.config import AppConfig
from edgesentinel.dashboard.app import create_app
from edgesentinel.models import AlertStatus, Severity
from edgesentinel.simulation.scenarios import get_scenario_events
from edgesentinel.storage.database import Database


def test_end_to_end_port_scan_pipeline_and_sqlite():
    """Verify primary acceptance criteria: synthetic port scan detected and persisted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "edgesentinel_test.db")
        config = AppConfig(
            storage={"database_path": db_path, "batch_size": 10},
            detection={"port_scan": {"threshold_ports": 12, "window_seconds": 10.0}}
        )
        db = Database(db_path=db_path)
        pipeline = EventPipeline(config=config, db=db)

        # 1. Generate and ingest port-scan scenario
        events = get_scenario_events("port-scan")
        assert len(events) >= 15
        alerts = pipeline.ingest_events(events)

        # 2. Check alert generation
        port_scan_alerts = [a for a in alerts if a.detector_id == "DET-PORT-SCAN"]
        assert len(port_scan_alerts) >= 1
        port_scan_alert = port_scan_alerts[0]
        assert port_scan_alert.detector_id == "DET-PORT-SCAN"
        assert port_scan_alert.severity == Severity.HIGH
        assert port_scan_alert.is_synthetic is True
        assert "distinct_ports_count" in port_scan_alert.evidence

        # 3. Verify SQLite persistence
        db_alerts = db.get_alerts(limit=10)
        assert len(db_alerts) >= 1
        stored_alert = db_alerts[0]
        assert stored_alert.id == port_scan_alert.id
        assert stored_alert.detector_id == "DET-PORT-SCAN"
        assert stored_alert.evidence["distinct_ports_count"] >= 12
        assert stored_alert.is_synthetic is True
        assert stored_alert.status == AlertStatus.NEW

        # 4. Verify device inventory tracked the source IP
        devices = db.get_devices()
        attacker_ip = port_scan_alert.src_ip
        assert any(d.ip == attacker_ip for d in devices)

        # 5. Verify flow records persisted
        flows = db.get_flows(limit=50, active_only=False)
        assert len(flows) >= 1


def test_benign_traffic_false_positive_evaluation():
    """Verify normal traffic produces no false positive high-severity alerts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "benign_test.db")
        config = AppConfig(storage={"database_path": db_path})
        db = Database(db_path=db_path)
        pipeline = EventPipeline(config=config, db=db)

        benign_events = get_scenario_events("normal-traffic")
        alerts = pipeline.ingest_events(benign_events)

        # Normal traffic should NOT trigger PortScan, SYN Flood, or SSH Brute
        critical_alerts = [
            a for a in alerts if a.detector_id in {"DET-PORT-SCAN", "DET-SYN-FLOOD", "DET-SSH-BRUTE"}
        ]
        assert len(critical_alerts) == 0


def test_dashboard_api_with_persisted_data():
    """Verify REST API correctly reflects persisted alerts, devices, and metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "api_test.db")
        config = AppConfig(storage={"database_path": db_path})
        db = Database(db_path=db_path)

        app = create_app(config)
        client = TestClient(app)

        # 1. Status endpoint
        resp_status = client.get("/api/status")
        assert resp_status.status_code == 200
        data_status = resp_status.json()
        assert "platform" in data_status
        assert "stats" in data_status
        assert data_status["stats"]["total_alerts"] == 0

        # 2. Trigger simulation via API
        resp_sim = client.post("/api/simulate/port-scan")
        assert resp_sim.status_code == 200
        sim_data = resp_sim.json()
        assert sim_data["scenario"] == "port-scan"
        assert sim_data["alerts_triggered"] >= 1

        # 3. Query alerts endpoint
        resp_alerts = client.get("/api/alerts")
        assert resp_alerts.status_code == 200
        alerts_list = resp_alerts.json()
        assert len(alerts_list) >= 1
        assert alerts_list[0]["detector_id"] == "DET-PORT-SCAN"
        assert alerts_list[0]["is_synthetic"] is True

        # 4. Acknowledge alert
        alert_id = alerts_list[0]["id"]
        resp_ack = client.patch(f"/api/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"})
        assert resp_ack.status_code == 200
        assert resp_ack.json()["new_status"] == "ACKNOWLEDGED"

        # 5. Verify update in detail query
        resp_detail = client.get(f"/api/alerts/{alert_id}")
        assert resp_detail.status_code == 200
        assert resp_detail.json()["status"] == "ACKNOWLEDGED"

        # 6. Verify devices endpoint
        resp_dev = client.get("/api/devices")
        assert resp_dev.status_code == 200
        assert len(resp_dev.json()) >= 1
