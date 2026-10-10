"""ARP spoofing and conflicting IP-to-MAC mapping anomaly detector."""

from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, NetworkEvent, Severity


class ArpAnomalyDetector(BaseDetector):
    """Detects conflicting or rapidly fluctuating IP-to-MAC mappings indicating ARP spoofing/poisoning."""

    def __init__(self, window_seconds: float = 30.0, enabled: bool = True):
        super().__init__(
            detector_id="DET-ARP-SPOOF",
            name="ARP Spoof / Conflict Detector",
            description="Identifies conflicting or rapidly changing IP-to-MAC associations on the local network.",
            enabled=enabled
        )
        self.window_seconds = window_seconds
        # Mapping: IP -> (MAC, timestamp)
        self._ip_mac_table: Dict[str, Tuple[str, float]] = {}

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        if not self.enabled:
            return None

        # Only process ARP events with valid IP and MAC
        if event.protocol != "ARP" or not event.arp_spa or not event.arp_sha:
            return None

        ip = event.arp_spa
        mac = event.arp_sha.upper().strip()
        now = event.timestamp or time.time()

        # Ignore broadcast, DHCP probe (0.0.0.0), or invalid MACs
        if ip in {"0.0.0.0", "255.255.255.255"}:
            return None
        if mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            return None

        if ip in self._ip_mac_table:
            known_mac, last_seen = self._ip_mac_table[ip]
            if known_mac != mac:
                delta = now - last_seen
                if delta <= self.window_seconds:
                    dedup_key = f"arp_conflict:{ip}:{mac}"
                    if not self.should_suppress_duplicate(dedup_key, window_seconds=60.0, current_time=now):
                        alert = Alert(
                            detector_id=self.detector_id,
                            severity=Severity.HIGH,
                            src_ip=ip,
                            title="Conflicting ARP Mapping (Suspected ARP Spoofing / Poisoning)",
                            description=(
                                f"IP {ip} was previously mapped to MAC {known_mac}, but a conflicting "
                                f"announcement from MAC {mac} was observed {delta:.1f}s later."
                            ),
                            evidence={
                                "ip": ip,
                                "known_mac": known_mac,
                                "conflicting_mac": mac,
                                "time_delta_seconds": round(delta, 2),
                                "window_seconds": self.window_seconds
                            },
                            threshold_details=f"Conflicting MAC for same IP within {self.window_seconds}s",
                            confidence=0.90,
                            recommendations=[
                                f"Inspect host with MAC {mac} for unauthorized network intervention tools (e.g. arpspoof, ettercap).",
                                "Verify if legitimate DHCP IP reassignment or network interface change occurred.",
                                "Consider enabling Dynamic ARP Inspection (DAI) on the local switch if supported."
                            ],
                            is_synthetic=event.is_synthetic
                        )
                        # Update mapping to the new MAC
                        self._ip_mac_table[ip] = (mac, now)
                        return alert

        # Record / update observed mapping
        self._ip_mac_table[ip] = (mac, now)

        # Bounded capacity
        if len(self._ip_mac_table) > 2000:
            cutoff = now - (self.window_seconds * 10)
            self._ip_mac_table = {k: v for k, v in self._ip_mac_table.items() if v[1] >= cutoff}

        return None

    def reset(self) -> None:
        super().reset()
        self._ip_mac_table.clear()
