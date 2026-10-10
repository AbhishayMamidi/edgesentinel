"""New device detection engine alerting on unrecognized network participants."""

from __future__ import annotations

import time
from typing import Optional

from edgesentinel.detection.base import BaseDetector
from edgesentinel.models import Alert, Device, NetworkEvent, Severity


class NewDeviceDetector(BaseDetector):
    """Detects and alerts on previously unseen devices connecting to the authorized subnet."""

    def __init__(self, enabled: bool = True):
        super().__init__(
            detector_id="DET-NEW-DEVICE",
            name="New Device Discovery Detector",
            description="Raises an alert when network traffic originates from an IP or MAC address not in the known device inventory.",
            enabled=enabled
        )

    def process_event(self, event: NetworkEvent) -> Optional[Alert]:
        # Handled in cooperation with DeviceInventory via process_new_device
        return None

    def process_new_device(self, device: Device, is_synthetic: bool = True) -> Optional[Alert]:
        """Triggered when inventory identifies a genuinely new device."""
        if not self.enabled or device.is_trusted:
            return None

        dedup_key = f"new_dev:{device.ip}"
        now = time.time()
        if self.should_suppress_duplicate(dedup_key, window_seconds=3600.0, current_time=now):
            return None

        return Alert(
            detector_id=self.detector_id,
            severity=Severity.LOW,
            src_ip=device.ip,
            title="Unrecognized New Network Device Observed",
            description=(
                f"New device observed on network with IP {device.ip}"
                + (f" and MAC {device.mac}." if device.mac else ".")
            ),
            evidence={
                "ip": device.ip,
                "mac": device.mac,
                "observation_source": device.observation_source,
                "first_seen": device.first_seen,
                "is_trusted": device.is_trusted
            },
            threshold_details="First time observation in device inventory",
            confidence=0.95,
            recommendations=[
                f"Verify whether device at {device.ip} is authorized on this network segment.",
                "If authorized, add it to trusted_devices in configuration to suppress future alerts.",
                "Inspect device hostname and vendor OUI for asset inventory classification."
            ],
            is_synthetic=is_synthetic
        )
