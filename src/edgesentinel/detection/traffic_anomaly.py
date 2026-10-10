"""Traffic volume anomaly detection tracking rolling packet rates and byte throughput."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class TrafficAnomalyDetector(BaseDetector):
    """Detects sudden traffic volume spikes and rate anomalies."""

    def __init__(self, threshold_multiplier: float = 3.0, window_seconds: float = 15.0, enabled: bool = True):
        super().__init__(
            detector_id="DET-TRAFFIC-SPIKE",
            name="Traffic Volume Anomaly Detector",
            description="Tracks rolling per-host packet and byte rates to detect abnormal traffic volume surges.",
            enabled=enabled
        )
        self.threshold_multiplier = threshold_multiplier
        self.window_seconds = window_seconds
        # Mapping: src_ip -> list of (timestamp, packet_len)
        self._host_history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        # Baseline average packets per window: src_ip -> float
        self._baseline_pps: Dict[str, float] = {}

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        src_ip = event.src_ip
        if not src_ip:
            return None

        now = event.timestamp or time.time()
        self._host_history[src_ip].append((now, event.packet_len or 0))

        cutoff = now - self.window_seconds
        self._host_history[src_ip] = [entry for entry in self._host_history[src_ip] if entry[0] >= cutoff]

        history = self._host_history[src_ip]
        packet_count = len(history)
        current_pps = packet_count / max(self.window_seconds, 1.0)
        total_bytes = sum(entry[1] for entry in history)
        current_bps = total_bytes / max(self.window_seconds, 1.0)

        # Baseline updating with EWMA
        if src_ip not in self._baseline_pps:
            self._baseline_pps[src_ip] = max(current_pps, 2.0)
        else:
            # Update baseline slowly
            self._baseline_pps[src_ip] = 0.95 * self._baseline_pps[src_ip] + 0.05 * current_pps

        baseline = self._baseline_pps[src_ip]

        # Trigger if current PPS is >= threshold_multiplier * baseline AND above a practical minimum (e.g. 20 PPS)
        if current_pps >= (baseline * self.threshold_multiplier) and current_pps >= 20.0:
            dedup_key = f"traffic_spike:{src_ip}"
            if self.should_suppress_duplicate(dedup_key, window_seconds=self.window_seconds * 2, current_time=now):
                return None

            return Alert(
                detector_id=self.detector_id,
                severity=Severity.MEDIUM,
                src_ip=src_ip,
                dst_ip=event.dst_ip,
                title="Statistical Traffic Volume Spike Detected",
                description=(
                    f"Host {src_ip} surged to {current_pps:.1f} packets/s ({current_bps / 1024:.1f} KB/s), "
                    f"which is {current_pps / max(baseline, 0.1):.1f}x higher than baseline ({baseline:.1f} PPS)."
                ),
                evidence={
                    "current_pps": round(current_pps, 2),
                    "baseline_pps": round(baseline, 2),
                    "current_kb_per_sec": round(current_bps / 1024.0, 2),
                    "total_packets_in_window": packet_count,
                    "window_seconds": self.window_seconds,
                    "spike_factor": round(current_pps / max(baseline, 0.1), 2)
                },
                threshold_details=f">= {self.threshold_multiplier}x baseline and >= 20 PPS over {self.window_seconds}s",
                confidence=0.75,
                recommendations=[
                    f"Verify whether host {src_ip} is running a high-bandwidth task (file transfer, backup, streaming).",
                    "Check network interface utilization on switch/router."
                ],
                is_synthetic=event.is_synthetic
            )

        if len(self._host_history) > 1000:
            self._host_history = {k: v for k, v in self._host_history.items() if v and v[-1][0] >= cutoff}

        return None

    def reset(self) -> None:
        super().reset()
        self._host_history.clear()
        self._baseline_pps.clear()
