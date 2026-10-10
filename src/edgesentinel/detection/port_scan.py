"""Port scan detection engine tracking distinct destination ports."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class PortScanDetector(BaseDetector):
    """Detects sequential or distributed port scans against target hosts."""

    def __init__(self, threshold_ports: int = 15, window_seconds: float = 10.0, enabled: bool = True):
        super().__init__(
            detector_id="DET-PORT-SCAN",
            name="Port Scan Detector",
            description="Identifies connection attempts to multiple distinct destination ports on a host.",
            enabled=enabled
        )
        self.threshold_ports = threshold_ports
        self.window_seconds = window_seconds
        # Mapping: (src_ip, dst_ip) -> List of (timestamp, dst_port)
        self._history: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Port scans are typically TCP SYN or UDP probes with a destination port
        if not event.src_ip or not event.dst_ip or not event.dst_port:
            return None

        # Filter out established bidirectional data traffic (ACK without SYN), allowing SYN, FIN, NULL, or UDP probes
        if event.protocol == "TCP" and event.tcp_flags and "ACK" in event.tcp_flags and "SYN" not in event.tcp_flags:
            return None

        now = event.timestamp or time.time()
        pair = (event.src_ip, event.dst_ip)

        # Append probe
        self._history[pair].append((now, event.dst_port))

        # Evict probes outside window
        cutoff = now - self.window_seconds
        self._history[pair] = [p for p in self._history[pair] if p[0] >= cutoff]
        if not self._history[pair]:
            del self._history[pair]
            return None

        distinct_ports: Set[int] = {p[1] for p in self._history[pair]}

        if len(distinct_ports) >= self.threshold_ports:
            dedup_key = f"{event.src_ip}->{event.dst_ip}"
            if self.should_suppress_duplicate(dedup_key, window_seconds=self.window_seconds * 2, current_time=now):
                return None

            sorted_ports = sorted(list(distinct_ports))
            return Alert(
                detector_id=self.detector_id,
                severity=Severity.HIGH,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="Suspicious Port Scan Activity Detected",
                description=(
                    f"Host {event.src_ip} probed {len(distinct_ports)} distinct ports on {event.dst_ip} "
                    f"within {self.window_seconds:.1f}s."
                ),
                evidence={
                    "distinct_ports_count": len(distinct_ports),
                    "sampled_ports": sorted_ports[:30],
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold_ports,
                    "protocol": event.protocol
                },
                threshold_details=f">= {self.threshold_ports} distinct destination ports in {self.window_seconds}s",
                confidence=0.95,
                recommendations=[
                    f"Inspect host {event.src_ip} for unauthorized port-scanning or reconnaissance tools.",
                    f"Verify whether {event.dst_ip} has unnecessary exposed ports.",
                    "Review firewall access control rules."
                ],
                is_synthetic=event.is_synthetic
            )

        # Periodic cleanup of idle pairs
        if len(self._history) > 1000:
            self._history = {
                k: v for k, v in self._history.items() if v and v[-1][0] >= cutoff
            }

        return None

    def reset(self) -> None:
        super().reset()
        self._history.clear()
