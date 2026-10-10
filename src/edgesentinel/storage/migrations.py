"""Schema migrations for EdgeSentinel SQLite database."""

from __future__ import annotations

import sqlite3
import time
from typing import List, Tuple

MIGRATIONS: List[Tuple[int, str]] = [
    (
        1,
        """
        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at REAL NOT NULL
        );

        -- Network Events
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            tcp_flags TEXT,
            packet_len INTEGER DEFAULT 0,
            interface TEXT,
            capture_source TEXT NOT NULL,
            dns_query TEXT,
            arp_op TEXT,
            is_synthetic INTEGER NOT NULL DEFAULT 1,
            metadata TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);

        -- Alerts
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            detector_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            threshold_details TEXT,
            confidence REAL NOT NULL DEFAULT 1.0,
            recommendations TEXT,
            is_synthetic INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'NEW'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts(detector_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

        -- Device Inventory
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            observation_source TEXT NOT NULL,
            is_trusted INTEGER NOT NULL DEFAULT 0,
            packet_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

        -- Flow Tracking
        CREATE TABLE IF NOT EXISTS flows (
            flow_id TEXT PRIMARY KEY,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            start_time REAL NOT NULL,
            last_seen REAL NOT NULL,
            packet_count INTEGER NOT NULL DEFAULT 1,
            byte_count INTEGER NOT NULL DEFAULT 0,
            tcp_flags_seen TEXT,
            state TEXT NOT NULL DEFAULT 'ACTIVE'
        );
        CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen);
        CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows(start_time);

        -- Detector persistent state
        CREATE TABLE IF NOT EXISTS detector_state (
            detector_id TEXT PRIMARY KEY,
            state_data TEXT NOT NULL,
            updated_at REAL NOT NULL
        );

        -- Application metadata and settings
        CREATE TABLE IF NOT EXISTS app_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at REAL NOT NULL
        );
        """
    )
]


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply all pending migrations to the database and return latest version."""
    cursor = conn.cursor()

    # Ensure schema_version table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at REAL NOT NULL
        )
    """)
    conn.commit()

    cursor.execute("SELECT MAX(version) FROM schema_version")
    row = cursor.fetchone()
    current_version = row[0] if (row and row[0] is not None) else 0

    applied_count = 0
    for version, sql in MIGRATIONS:
        if version > current_version:
            cursor.executescript(sql)
            cursor.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, time.time())
            )
            conn.commit()
            applied_count += 1
            current_version = version

    return current_version
