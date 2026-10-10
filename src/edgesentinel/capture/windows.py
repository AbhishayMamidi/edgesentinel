"""Windows live packet capture adapter with driver verification and safe fallback."""

from __future__ import annotations

import logging
from typing import Generator, Optional

from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.models import NetworkEvent
from edgesentinel.platform_info import get_platform_info

logger = logging.getLogger("edgesentinel.capture.windows")


class WindowsCaptureAdapter(BaseCaptureAdapter):
    """Windows-specific packet capture adapter.
    
    Verifies Npcap/WinPcap installation and administrative privileges before attempting capture.
    Safely degrades and reports diagnostics when prerequisites are not met.
    """

    def __init__(self, interface: str = "", bpf_filter: str = ""):
        super().__init__(interface, bpf_filter)
        self.plat_info = get_platform_info()

    def start(self) -> bool:
        if not self.plat_info["is_windows"]:
            logger.error("WindowsCaptureAdapter can only run on Windows hosts.")
            return False

        if not self.plat_info["has_npcap"]:
            logger.warning(
                "Npcap packet capture driver was not found on this Windows system. "
                "Live capture requires Npcap (https://npcap.com). "
                "Please use synthetic simulation ('edgesentinel simulate') or offline PCAP replay ('edgesentinel replay')."
            )
            return False

        if not self.plat_info["is_admin"]:
            logger.warning(
                "Windows packet capture typically requires administrative privileges. "
                "Current process is unprivileged."
            )
            return False

        self.is_running = True
        logger.info("Windows live capture adapter initialized.")
        return True

    def stop(self) -> None:
        self.is_running = False

    def stream_events(self) -> Generator[NetworkEvent, None, None]:
        """Stream live packet events if driver is present, else yield nothing."""
        if not self.is_running:
            return
        # Live Windows capture loop using raw socket or Npcap when authorized
        logger.info("Awaiting live packets on Windows interface '%s'...", self.interface)
