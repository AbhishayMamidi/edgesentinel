"""SQLite persistence engine for EdgeSentinel with WAL mode and batched writes."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from edgesentinel.models import Alert, AlertStatus, Device, FlowRecord, NetworkEvent, Severity
from edgesentinel.storage.migrations import apply_migrations

logger = logging.getLogger("edgesentinel.storage")


class Database:
    """Thread-safe SQLite database manager with WAL mode and retention management."""

    def __init__(self, db_path: str = "data/edgesentinel.db", busy_timeout_ms: int = 5000):
        self.db_path = Path(db_path)
        self.busy_timeout_ms = busy_timeout_ms
        self._ensure_parent_dir()
        self._init_db()

    def _ensure_parent_dir(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self):
        """Context manager that creates and guarantees closing of a configured SQLite connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.busy_timeout_ms / 1000.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms};")
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database tables and run migrations."""
        with self.get_connection() as conn:
            apply_migrations(conn)
        logger.info("Database initialized successfully at %s", self.db_path)

    def close(self) -> None:
        """Close any lingering handles and checkpoint WAL."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            finally:
                conn.close()
        except Exception:
            pass

    # --- Event Methods ---

    def insert_event(self, event: NetworkEvent) -> None:
        self.insert_events_batch([event])

    def insert_events_batch(self, events: List[NetworkEvent]) -> None:
        if not events:
            return
        query = """
            INSERT INTO events (
                id, timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, tcp_flags, packet_len, interface,
                capture_source, dns_query, arp_op, is_synthetic, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                e.id,
                e.timestamp,
                e.src_ip,
                e.dst_ip,
                e.src_port,
                e.dst_port,
                e.protocol,
                e.tcp_flags,
                e.packet_len,
                e.interface,
                e.capture_source,
                e.dns_query,
                e.arp_op,
                1 if e.is_synthetic else 0,
                json.dumps(e.metadata)
            )
            for e in events
        ]
        with self.get_connection() as conn:
            conn.executemany(query, rows)

    def get_events(
        self,
        limit: int = 100,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None
    ) -> List[NetworkEvent]:
        query = "SELECT * FROM events"
        params: List[Any] = []
        conditions: List[str] = []

        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            conditions.append("dst_ip = ?")
            params.append(dst_ip)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = []
            for r in cursor.fetchall():
                results.append(NetworkEvent(
                    id=r["id"],
                    timestamp=r["timestamp"],
                    src_ip=r["src_ip"],
                    dst_ip=r["dst_ip"],
                    src_port=r["src_port"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    tcp_flags=r["tcp_flags"],
                    packet_len=r["packet_len"],
                    interface=r["interface"],
                    capture_source=r["capture_source"],
                    dns_query=r["dns_query"],
                    arp_op=r["arp_op"],
                    is_synthetic=bool(r["is_synthetic"]),
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {}
                ))
            return results

    # --- Alert Methods ---

    def insert_alert(self, alert: Alert) -> None:
        query = """
            INSERT INTO alerts (
                id, timestamp, detector_id, severity, src_ip, dst_ip,
                title, description, evidence, threshold_details,
                confidence, recommendations, is_synthetic, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert.id,
            alert.timestamp,
            alert.detector_id,
            alert.severity.value,
            alert.src_ip,
            alert.dst_ip,
            alert.title,
            alert.description,
            json.dumps(alert.evidence),
            alert.threshold_details,
            alert.confidence,
            json.dumps(alert.recommendations),
            1 if alert.is_synthetic else 0,
            alert.status.value
        )
        with self.get_connection() as conn:
            conn.execute(query, params)

    def insert_alerts_batch(self, alerts: List[Alert]) -> None:
        if not alerts:
            return
        query = """
            INSERT INTO alerts (
                id, timestamp, detector_id, severity, src_ip, dst_ip,
                title, description, evidence, threshold_details,
                confidence, recommendations, is_synthetic, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                a.id,
                a.timestamp,
                a.detector_id,
                a.severity.value,
                a.src_ip,
                a.dst_ip,
                a.title,
                a.description,
                json.dumps(a.evidence),
                a.threshold_details,
                a.confidence,
                json.dumps(a.recommendations),
                1 if a.is_synthetic else 0,
                a.status.value
            )
            for a in alerts
        ]
        with self.get_connection() as conn:
            conn.executemany(query, rows)


    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        detector_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Alert]:
        query = "SELECT * FROM alerts"
        conditions: List[str] = []
        params: List[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if detector_id:
            conditions.append("detector_id = ?")
            params.append(detector_id)
        if status:
            conditions.append("status = ?")
            params.append(status.upper())

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = []
            for r in cursor.fetchall():
                results.append(Alert(
                    id=r["id"],
                    timestamp=r["timestamp"],
                    detector_id=r["detector_id"],
                    severity=Severity(r["severity"]),
                    src_ip=r["src_ip"],
                    dst_ip=r["dst_ip"],
                    title=r["title"],
                    description=r["description"],
                    evidence=json.loads(r["evidence"]) if r["evidence"] else {},
                    threshold_details=r["threshold_details"],
                    confidence=r["confidence"],
                    recommendations=json.loads(r["recommendations"]) if r["recommendations"] else [],
                    is_synthetic=bool(r["is_synthetic"]),
                    status=AlertStatus(r["status"])
                ))
            return results

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        query = "SELECT * FROM alerts WHERE id = ?"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (alert_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return Alert(
                id=r["id"],
                timestamp=r["timestamp"],
                detector_id=r["detector_id"],
                severity=Severity(r["severity"]),
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                title=r["title"],
                description=r["description"],
                evidence=json.loads(r["evidence"]) if r["evidence"] else {},
                threshold_details=r["threshold_details"],
                confidence=r["confidence"],
                recommendations=json.loads(r["recommendations"]) if r["recommendations"] else [],
                is_synthetic=bool(r["is_synthetic"]),
                status=AlertStatus(r["status"])
            )

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        query = "UPDATE alerts SET status = ? WHERE id = ?"
        with self.get_connection() as conn:
            cursor = conn.execute(query, (status.value, alert_id))
            return cursor.rowcount > 0

    # --- Device Inventory Methods ---

    def upsert_device(self, device: Device) -> None:
        self.upsert_devices_batch([device])

    def upsert_devices_batch(self, devices: List[Device]) -> None:
        if not devices:
            return
        query = """
            INSERT INTO devices (
                ip, mac, hostname, first_seen, last_seen, observation_source, is_trusted, packet_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                mac = COALESCE(excluded.mac, devices.mac),
                hostname = COALESCE(excluded.hostname, devices.hostname),
                packet_count = devices.packet_count + excluded.packet_count
        """
        rows = [
            (
                d.ip,
                d.mac,
                d.hostname,
                d.first_seen,
                d.last_seen,
                d.observation_source,
                1 if d.is_trusted else 0,
                d.packet_count
            )
            for d in devices
        ]
        with self.get_connection() as conn:
            conn.executemany(query, rows)

    def get_devices(self) -> List[Device]:
        query = "SELECT * FROM devices ORDER BY last_seen DESC"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            devices = []
            for r in cursor.fetchall():
                devices.append(Device(
                    ip=r["ip"],
                    mac=r["mac"],
                    hostname=r["hostname"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    observation_source=r["observation_source"],
                    is_trusted=bool(r["is_trusted"]),
                    packet_count=r["packet_count"]
                ))
            return devices

    # --- Flow Methods ---

    def upsert_flows_batch(self, flows: List[FlowRecord]) -> None:
        if not flows:
            return
        query = """
            INSERT INTO flows (
                flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, last_seen, packet_count, byte_count, tcp_flags_seen, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                packet_count = excluded.packet_count,
                byte_count = excluded.byte_count,
                tcp_flags_seen = excluded.tcp_flags_seen,
                state = excluded.state
        """
        rows = [
            (
                f.flow_id,
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.protocol,
                f.start_time,
                f.last_seen,
                f.packet_count,
                f.byte_count,
                json.dumps(f.tcp_flags_seen),
                f.state
            )
            for f in flows
        ]
        with self.get_connection() as conn:
            conn.executemany(query, rows)

    def get_flows(self, limit: int = 100, active_only: bool = True) -> List[FlowRecord]:
        query = "SELECT * FROM flows"
        params: List[Any] = []
        if active_only:
            query += " WHERE state = 'ACTIVE'"
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            flows = []
            for r in cursor.fetchall():
                flows.append(FlowRecord(
                    flow_id=r["flow_id"],
                    src_ip=r["src_ip"],
                    dst_ip=r["dst_ip"],
                    src_port=r["src_port"],
                    dst_port=r["dst_port"],
                    protocol=r["protocol"],
                    start_time=r["start_time"],
                    last_seen=r["last_seen"],
                    packet_count=r["packet_count"],
                    byte_count=r["byte_count"],
                    tcp_flags_seen=json.loads(r["tcp_flags_seen"]) if r["tcp_flags_seen"] else [],
                    state=r["state"]
                ))
            return flows

    # --- Maintenance & Stats ---

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate database metrics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            alerts_by_severity = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM flows WHERE state = 'ACTIVE'")
            active_flows = cursor.fetchone()[0]

        file_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "alerts_by_severity": alerts_by_severity,
            "total_devices": total_devices,
            "active_flows": active_flows,
            "db_size_kb": round(file_size_bytes / 1024.0, 2),
            "db_path": str(self.db_path)
        }

    def cleanup_retention(self, retention_days: int) -> int:
        """Purge events and closed flows older than retention period."""
        cutoff = time.time() - (retention_days * 86400)
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            deleted_events = cursor.rowcount
            cursor2 = conn.execute("DELETE FROM flows WHERE last_seen < ? AND state != 'ACTIVE'", (cutoff,))
            deleted_flows = cursor2.rowcount
            logger.info("Retention cleanup: purged %d events, %d flows", deleted_events, deleted_flows)
            return deleted_events + deleted_flows
