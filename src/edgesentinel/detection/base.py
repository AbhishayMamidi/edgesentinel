"""Base detector abstract class and shared detector utilities."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from edgesentinel.models import Alert, NetworkEvent, Severity


class BaseDetector(ABC):
    """Abstract base class for all EdgeSentinel detection engines."""

    def __init__(self, detector_id: str, name: str, description: str, enabled: bool = True):
        self.detector_id = detector_id
        self.name = name
        self.description = description
        self.enabled = enabled
        self._last_alert_time: Dict[str, float] = {}

    @abstractmethod
    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        """Inspect a single event and return an Alert if threshold crossed."""
        pass

    def should_suppress_duplicate(self, deduplication_key: str, window_seconds: float = 30.0, current_time: Optional[float] = None) -> bool:
        """Rate limit alerts with the same key to avoid flooding."""
        now = current_time or time.time()
        last_time = self._last_alert_time.get(deduplication_key, 0.0)
        if now - last_time < window_seconds:
            return True
        self._last_alert_time[deduplication_key] = now
        # Bound deduplication table
        if len(self._last_alert_time) > 1000:
            cutoff = now - (window_seconds * 2)
            self._last_alert_time = {k: v for k, v in self._last_alert_time.items() if v >= cutoff}
        return False

    def reset(self) -> None:
        """Reset in-memory detector state."""
        self._last_alert_time.clear()
