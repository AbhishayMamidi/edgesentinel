"""Live packet capture adapter interfaces for EdgeSentinel."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Dict, Generator, Optional

from edgesentinel.models import NetworkEvent

logger = logging.getLogger("edgesentinel.capture")


class BaseCaptureAdapter(ABC):
    """Abstract base class for live network packet capture adapters."""

    def __init__(self, interface: str = "", bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = False
        self.packets_captured = 0
        self.packets_dropped = 0
        self.last_error: Optional[str] = None
        self.pid: Optional[int] = None

    @abstractmethod
    def start(self) -> bool:
        """Initialize and verify capture prerequisites."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Halt capture and clean up resources."""
        pass

    @abstractmethod
    def stream_events(self) -> Generator[NetworkEvent, None, None]:
        """Stream normalized network events as they are received."""
        pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "captured": self.packets_captured,
            "dropped": self.packets_dropped,
            "is_running": self.is_running,
            "error": self.last_error,
            "pid": self.pid,
        }

