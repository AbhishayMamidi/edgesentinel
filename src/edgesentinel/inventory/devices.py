"""Device inventory tracking and new-device detection."""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Set, Tuple

from edgesentinel.models import Device, NetworkEvent


class DeviceInventory:
    """Maintains lightweight inventory of network hosts observed from traffic."""

    def __init__(self, trusted_devices: Optional[List[str]] = None, max_devices: int = 2000):
        self.trusted_set: Set[str] = set(trusted_devices or ["127.0.0.1", "192.168.1.1"])
        self.max_devices = max_devices
        self._devices: Dict[str, Device] = {}

    def observe_event(self, event: NetworkEvent) -> Tuple[Optional[Device], bool]:
        """
        Record observed hosts from event.
        Returns (Device, is_new) for source IP if valid.
        """
        src_ip = event.src_ip
        if not src_ip or src_ip in {"0.0.0.0", "255.255.255.255"}:
            return None, False

        now = event.timestamp or time.time()
        is_new = False
        mac = event.arp_sha if event.protocol == "ARP" else None

        if src_ip in self._devices:
            dev = self._devices[src_ip]
            dev.last_seen = now
            dev.packet_count += 1
            if mac and not dev.mac:
                dev.mac = mac
            return dev, False
        else:
            # Check capacity
            if len(self._devices) >= self.max_devices:
                # Evict least recently seen
                oldest_ip = min(self._devices, key=lambda k: self._devices[k].last_seen)
                del self._devices[oldest_ip]

            is_new = True
            is_trusted = src_ip in self.trusted_set or (mac is not None and mac in self.trusted_set)
            dev = Device(
                ip=src_ip,
                mac=mac,
                first_seen=now,
                last_seen=now,
                observation_source=event.capture_source,
                is_trusted=is_trusted,
                packet_count=1
            )
            self._devices[src_ip] = dev
            return dev, is_new

    def get_devices(self) -> List[Device]:
        return sorted(self._devices.values(), key=lambda d: d.last_seen, reverse=True)

    def get_device(self, ip: str) -> Optional[Device]:
        return self._devices.get(ip)

    def mark_trusted(self, ip_or_mac: str) -> None:
        self.trusted_set.add(ip_or_mac)
        if ip_or_mac in self._devices:
            self._devices[ip_or_mac].is_trusted = True
