"""Unified alert manager for deduplication, persistence, and dispatch."""

from __future__ import annotations

import logging
import time
from typing import Callable, Dict, List, Optional

from edgesentinel.models import Alert, AlertStatus, Severity
from edgesentinel.storage.database import Database

logger = logging.getLogger("edgesentinel.alerts")


class AlertManager:
    """Manages alert lifecycle, deduplication, SQLite persistence, and dispatch."""

    def __init__(self, db: Database, max_recent: int = 500, dedup_window_seconds: float = 30.0, auto_flush: bool = True):
        self.db = db
        self.max_recent = max_recent
        self.dedup_window_seconds = dedup_window_seconds
        self.auto_flush = auto_flush
        self._recent_alerts: List[Alert] = []
        self._last_alert_seen: Dict[str, float] = {}
        self._subscribers: List[Callable[[Alert], None]] = []
        self._pending_alerts: List[Alert] = []

    def subscribe(self, callback: Callable[[Alert], None]) -> None:
        """Register a subscriber callback for real-time alert dispatch."""
        self._subscribers.append(callback)

    def flush(self) -> None:
        """Persist staged alerts to database."""
        if self._pending_alerts:
            try:
                self.db.insert_alerts_batch(self._pending_alerts)
            except Exception as e:
                logger.error("Failed to store alerts batch in database: %s", e)
            self._pending_alerts.clear()

    def dispatch(self, alert: Alert) -> bool:
        """
        Process, deduplicate, store, and dispatch an alert.
        Returns True if accepted and stored, False if suppressed.
        """
        now = alert.timestamp or time.time()
        dedup_key = f"{alert.detector_id}:{alert.src_ip}:{alert.dst_ip}"

        last_time = self._last_alert_seen.get(dedup_key, 0.0)
        if now - last_time < self.dedup_window_seconds:
            logger.debug("Suppressing duplicate alert %s (key %s)", alert.id, dedup_key)
            return False

        self._last_alert_seen[dedup_key] = now

        # Prune dedup table if too large
        if len(self._last_alert_seen) > 2000:
            cutoff = now - (self.dedup_window_seconds * 2)
            self._last_alert_seen = {k: v for k, v in self._last_alert_seen.items() if v >= cutoff}

        # Persist to database
        if self.auto_flush:
            try:
                self.db.insert_alert(alert)
            except Exception as e:
                logger.error("Failed to store alert in database: %s", e)
        else:
            self._pending_alerts.append(alert)

        # In-memory bounded cache
        self._recent_alerts.insert(0, alert)
        if len(self._recent_alerts) > self.max_recent:
            self._recent_alerts.pop()


        logger.warning(
            "[%s] [%s] %s - %s",
            alert.severity.value,
            alert.detector_id,
            alert.title,
            alert.description
        )

        # Notify subscribers
        for sub in self._subscribers:
            try:
                sub(alert)
            except Exception as e:
                logger.error("Subscriber notification error: %s", e)

        return True

    def get_recent_alerts(self, limit: int = 50, severity: Optional[Severity] = None) -> List[Alert]:
        """Fetch alerts from in-memory cache or fallback to database."""
        if self._recent_alerts:
            alerts = self._recent_alerts
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            return alerts[:limit]
        return self.db.get_alerts(limit=limit, severity=severity.value if severity else None)

    def update_status(self, alert_id: str, status: AlertStatus) -> bool:
        """Update lifecycle status in memory and database."""
        for a in self._recent_alerts:
            if a.id == alert_id:
                a.status = status
        return self.db.update_alert_status(alert_id, status)
