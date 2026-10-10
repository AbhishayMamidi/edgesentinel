"""DNS anomaly detection engine for query bursts and abnormally long query names."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class DnsAnomalyDetector(BaseDetector):
    """Detects DNS query rate bursts and abnormally long domain names (DNS tunneling indicators)."""

    def __init__(
        self,
        query_rate_threshold: float = 20.0,
        max_query_len: int = 60,
        window_seconds: float = 10.0,
        enabled: bool = True
    ):
        super().__init__(
            detector_id="DET-DNS-ANOMALY",
            name="DNS Anomaly Detector",
            description="Identifies abnormal DNS query rates and excessively long query names indicating potential tunneling.",
            enabled=enabled
        )
        self.query_rate_threshold = query_rate_threshold
        self.max_query_len = max_query_len
        self.window_seconds = window_seconds
        # Mapping: src_ip -> list of timestamps
        self._query_history: Dict[str, List[float]] = defaultdict(list)

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Check if DNS event (either UDP/TCP port 53 or explicit dns_query)
        if not event.dns_query and event.dst_port != 53 and event.src_port != 53:
            return None

        src_ip = event.src_ip
        if not src_ip:
            return None

        now = event.timestamp or time.time()

        # 1. Check for abnormally long query name (tunneling indicator)
        if event.dns_query and len(event.dns_query) >= self.max_query_len:
            dedup_key = f"dns_len:{src_ip}:{event.dns_query[:30]}"
            if not self.should_suppress_duplicate(dedup_key, window_seconds=60.0, current_time=now):
                return Alert(
                    detector_id=self.detector_id,
                    severity=Severity.HIGH,
                    src_ip=src_ip,
                    dst_ip=event.dst_ip,
                    title="Suspiciously Long DNS Query (Potential Tunneling/Exfiltration)",
                    description=(
                        f"Host {src_ip} queried an unusually long domain name ({len(event.dns_query)} chars), "
                        f"exceeding threshold of {self.max_query_len} characters."
                    ),
                    evidence={
                        "query": event.dns_query,
                        "query_length": len(event.dns_query),
                        "max_length_threshold": self.max_query_len,
                        "dns_server": event.dst_ip
                    },
                    threshold_details=f"Query length >= {self.max_query_len} characters",
                    confidence=0.85,
                    recommendations=[
                        "Inspect process making this query for DNS tunneling utilities (e.g. dnscat2, iodine).",
                        "Verify whether domain is associated with dynamic DNS or data exfiltration.",
                        "Block suspicious domain at local DNS resolver if confirmed unauthorized."
                    ],
                    is_synthetic=event.is_synthetic
                )

        # 2. Check for query rate burst
        self._query_history[src_ip].append(now)
        cutoff = now - self.window_seconds
        self._query_history[src_ip] = [t for t in self._query_history[src_ip] if t >= cutoff]

        query_count = len(self._query_history[src_ip])
        duration = max(now - self._query_history[src_ip][0], 0.1)
        rate = query_count / duration if duration < self.window_seconds else query_count / self.window_seconds

        if query_count >= 5 and rate >= self.query_rate_threshold:
            dedup_key = f"dns_rate:{src_ip}"
            if self.should_suppress_duplicate(dedup_key, window_seconds=self.window_seconds * 2, current_time=now):
                return None

            return Alert(
                detector_id=self.detector_id,
                severity=Severity.MEDIUM,
                src_ip=src_ip,
                dst_ip=event.dst_ip,
                title="Elevated DNS Query Rate Detected",
                description=(
                    f"Host {src_ip} issued {query_count} DNS queries ({rate:.1f} queries/s) "
                    f"in {self.window_seconds:.1f}s, exceeding threshold of {self.query_rate_threshold:.1f} q/s."
                ),
                evidence={
                    "query_count": query_count,
                    "query_rate_per_sec": round(rate, 2),
                    "threshold_rate": self.query_rate_threshold,
                    "window_seconds": self.window_seconds
                },
                threshold_details=f">= {self.query_rate_threshold} DNS queries/s in {self.window_seconds}s",
                confidence=0.80,
                recommendations=[
                    f"Inspect host {src_ip} for malware performing domain generation algorithm (DGA) lookups.",
                    "Review queried domains in local DNS logs for fast-flux activity."
                ],
                is_synthetic=event.is_synthetic
            )

        if len(self._query_history) > 1000:
            self._query_history = {k: v for k, v in self._query_history.items() if v and v[-1] >= cutoff}

        return None

    def reset(self) -> None:
        super().reset()
        self._query_history.clear()
