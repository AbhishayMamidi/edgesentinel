"""Simulation capture adapter for testing and offline demonstrations."""

from __future__ import annotations

import logging
import random
import time
from typing import Generator, Optional

from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.models import NetworkEvent
from edgesentinel.simulation.generator import SyntheticTrafficGenerator

logger = logging.getLogger("edgesentinel.capture.simulation")


class SimulationCaptureAdapter(BaseCaptureAdapter):
    """Generates continuous synthetic background network events for offline testing."""

    def __init__(self, interface: str = "sim0", bpf_filter: str = "", interval_seconds: float = 1.0):
        super().__init__(interface or "sim0", bpf_filter)
        self.interval_seconds = interval_seconds
        self._stop_requested = False
        self._gen = SyntheticTrafficGenerator()

    def start(self) -> bool:
        self.is_running = True
        self._stop_requested = False
        logger.info("Simulation capture adapter initialized on '%s'.", self.interface)
        return True

    def stop(self) -> None:
        self.is_running = False
        self._stop_requested = True
        logger.info("Simulation capture adapter stopped.")

    def stream_events(self) -> Generator[NetworkEvent, None, None]:
        """Stream continuous simulated background events."""
        src_ips = ["192.168.1.105", "192.168.1.110", "192.168.1.115"]

        while self.is_running and not self._stop_requested:
            choice = random.random()
            src = random.choice(src_ips)

            if choice < 0.65:
                events = self._gen.generate_normal_tcp(src_ip=src, dst_ip="192.168.1.1", count=4)
            elif choice < 0.85:
                events = self._gen.generate_normal_udp(src_ip=src, dst_ip="1.1.1.1", count=2)
            else:
                events = self._gen.generate_dns_burst(count=3)

            for e in events:
                if not self.is_running or self._stop_requested:
                    return
                self.packets_captured += 1
                yield e

            time.sleep(self.interval_seconds)
