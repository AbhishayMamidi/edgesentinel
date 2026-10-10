"""SSH brute-force and repeated authentication failure detector."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class SshBruteforceDetector(BaseDetector):
    """Detects repeated SSH connection attempts or authentication failure patterns."""

    def __init__(self, threshold_attempts: int = 5, window_seconds: float = 60.0, enabled: bool = True):
        super().__init__(
            detector_id="DET-SSH-BRUTE",
            name="SSH Brute-Force Indicator Detector",
            description="Identifies repeated connection attempts or authentication failures directed at SSH port 22.",
            enabled=enabled
        )
        self.threshold_attempts = threshold_attempts
        self.window_seconds = window_seconds
        # Mapping: (src_ip, dst_ip) -> list of timestamps
        self._history: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Check for SSH port or metadata flag
        is_ssh_target = event.dst_port == 22 or (event.protocol == "TCP" and event.dst_port == 22)
        has_auth_fail = event.metadata.get("auth_failure", False) is True

        if not (is_ssh_target or has_auth_fail):
            return None

        # If it's a TCP event without auth metadata, only count SYN initiates
        if is_ssh_target and not has_auth_fail and event.tcp_flags and "SYN" not in event.tcp_flags:
            return None

        src_ip = event.src_ip
        dst_ip = event.dst_ip
        if not src_ip or not dst_ip:
            return None

        now = event.timestamp or time.time()
        pair = (src_ip, dst_ip)
        self._history[pair].append(now)

        cutoff = now - self.window_seconds
        self._history[pair] = [t for t in self._history[pair] if t >= cutoff]

        attempts = len(self._history[pair])
        if attempts >= self.threshold_attempts:
            dedup_key = f"ssh:{src_ip}->{dst_ip}"
            if self.should_suppress_duplicate(dedup_key, window_seconds=self.window_seconds, current_time=now):
                return None

            if has_auth_fail:
                title = "Repeated SSH Authentication Failures (Suspected Brute-Force)"
                severity = Severity.HIGH
                confidence = 0.95
                desc = (
                    f"Host {src_ip} produced {attempts} failed authentication events against SSH on {dst_ip} "
                    f"within {self.window_seconds:.1f}s, crossing the threshold of {self.threshold_attempts}."
                )
            else:
                title = "Elevated SSH Connection Rate (Potential Service Probing)"
                severity = Severity.MEDIUM
                confidence = 0.70
                desc = (
                    f"Host {src_ip} made {attempts} connection attempts to SSH port 22 on {dst_ip} "
                    f"within {self.window_seconds:.1f}s. Note: network connection rate alone does not confirm failed authentication."
                )

            return Alert(
                detector_id=self.detector_id,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                title=title,
                description=desc,
                evidence={
                    "attempt_count": attempts,
                    "target_service": "SSH (port 22)",
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold_attempts,
                    "verified_auth_failure_logs": has_auth_fail
                },
                threshold_details=f">= {self.threshold_attempts} SSH attempts/failures in {self.window_seconds}s",
                confidence=confidence,
                recommendations=[
                    f"Check auth logs on target host {dst_ip} for repeated failed logins.",
                    f"Consider rate-limiting or blocking repeated connections from {src_ip}.",
                    "Ensure SSH password authentication is disabled in favor of key-based auth."
                ],
                is_synthetic=event.is_synthetic
            )

        if len(self._history) > 1000:
            self._history = {k: v for k, v in self._history.items() if v and v[-1] >= cutoff}

        return None

    def reset(self) -> None:
        super().reset()
        self._history.clear()
