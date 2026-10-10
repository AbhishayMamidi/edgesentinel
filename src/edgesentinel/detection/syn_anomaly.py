"""TCP SYN anomaly detector identifying elevated rates of unacknowledged SYN packets."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class SynAnomalyDetector(BaseDetector):
    """Detects elevated rates of SYN packets indicative of connection flooding or scans."""

    def __init__(self, threshold_syn_rate: float = 25.0, window_seconds: float = 5.0, enabled: bool = True):
        super().__init__(
            detector_id="DET-SYN-FLOOD",
            name="TCP SYN Flood / Rate Anomaly Detector",
            description="Identifies abnormal spikes in TCP SYN connection requests from a single source host.",
            enabled=enabled
        )
        self.threshold_syn_rate = threshold_syn_rate
        self.window_seconds = window_seconds
        # Mapping: src_ip -> list of timestamps
        self._syn_history: Dict[str, List[float]] = defaultdict(list)

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        if event.protocol != "TCP" or not event.tcp_flags or "SYN" not in event.tcp_flags:
            return None

        # Exclude legitimate SYN-ACK responses
        if "ACK" in event.tcp_flags:
            return None

        src_ip = event.src_ip
        if not src_ip:
            return None

        now = event.timestamp or time.time()
        self._syn_history[src_ip].append(now)

        cutoff = now - self.window_seconds
        self._syn_history[src_ip] = [t for t in self._syn_history[src_ip] if t >= cutoff]

        count = len(self._syn_history[src_ip])
        duration = max(now - self._syn_history[src_ip][0], 0.1)
        rate = count / duration if duration < self.window_seconds else count / self.window_seconds

        if count >= 5 and rate >= self.threshold_syn_rate:
            dedup_key = f"syn:{src_ip}"
            if self.should_suppress_duplicate(dedup_key, window_seconds=self.window_seconds * 2, current_time=now):
                return None

            return Alert(
                detector_id=self.detector_id,
                severity=Severity.HIGH,
                src_ip=src_ip,
                dst_ip=event.dst_ip,
                title="Elevated TCP SYN Rate (Possible SYN Flood Indicator)",
                description=(
                    f"Host {src_ip} generated {count} SYN packets ({rate:.1f} SYN/s) "
                    f"over {self.window_seconds:.1f}s, exceeding threshold of {self.threshold_syn_rate:.1f} SYN/s."
                ),
                evidence={
                    "syn_count": count,
                    "measured_rate_per_sec": round(rate, 2),
                    "threshold_rate_per_sec": self.threshold_syn_rate,
                    "window_seconds": self.window_seconds,
                    "target_host": event.dst_ip
                },
                threshold_details=f">= {self.threshold_syn_rate} SYN/s over {self.window_seconds}s",
                confidence=0.90,
                recommendations=[
                    f"Check host {src_ip} for automated network scanners or denial-of-service tools.",
                    "Verify if SYN cookies are active on target servers.",
                    "Inspect TCP connection table for half-open states."
                ],
                is_synthetic=event.is_synthetic
            )

        if len(self._syn_history) > 1000:
            self._syn_history = {k: v for k, v in self._syn_history.items() if v and v[-1] >= cutoff}

        return None

    def reset(self) -> None:
        super().reset()
        self._syn_history.clear()
