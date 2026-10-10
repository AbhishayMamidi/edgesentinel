"""Linux capture adapter using tcpdump subprocess streaming for Raspberry Pi 3B+."""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import subprocess
import time
from typing import Generator, List, Optional

from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.models import NetworkEvent

logger = logging.getLogger("edgesentinel.capture.linux")


class LinuxTcpdumpAdapter(BaseCaptureAdapter):
    """Streams and parses live packet metadata from a tcpdump child process on Linux / Raspberry Pi."""

    def __init__(self, interface: str = "eth0", bpf_filter: str = ""):
        super().__init__(interface, bpf_filter)
        self._process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        if os.name == "nt":
            logger.warning("LinuxTcpdumpAdapter is designed for Linux / Raspberry Pi systems and cannot run on Windows.")
            return False

        if not shutil.which("tcpdump"):
            logger.error("tcpdump utility not found in PATH. Please install via: sudo apt-get install tcpdump")
            return False

        cmd: List[str] = [
            "tcpdump",
            "-l",              # Line-buffered stdout
            "-n",              # Don't convert addresses to names
            "-tt",             # Unformatted epoch timestamp
            "-q",              # Quick, quiet protocol output
            "-i", self.interface or "any"
        ]

        if self.bpf_filter:
            cmd.extend(self.bpf_filter.split())

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            self.is_running = True
            logger.info("Started tcpdump capture subprocess with PID %d on interface '%s'", self._process.pid, self.interface)
            return True
        except PermissionError:
            logger.error(
                "Permission denied running tcpdump. Ensure user is in pcap group or binary has setcap: "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)"
            )
            return False
        except Exception as e:
            logger.error("Failed to start tcpdump: %s", e)
            return False

    def stop(self) -> None:
        """Gracefully terminate child process."""
        self.is_running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            except Exception:
                pass
            self._process = None
            logger.info("tcpdump capture subprocess terminated.")

    def stream_events(self) -> Generator[NetworkEvent, None, None]:
        """Read and parse tcpdump stdout line-by-line."""
        if not self._process or not self._process.stdout:
            return

        # Regular expressions for standard tcpdump line formats
        # e.g.: 1700000000.123456 IP 192.168.1.50.54321 > 192.168.1.1.80: tcp 0
        ip_pattern = re.compile(
            r"^(\d+\.\d+)\s+IP\s+([\d\.]+)\.(\d+)\s+>\s+([\d\.]+)\.(\d+):\s+(tcp|udp)\s+(\d+)?",
            re.IGNORECASE
        )

        for line in self._process.stdout:
            if not self.is_running:
                break

            line = line.strip()
            if not line:
                continue

            self.packets_captured += 1
            match = ip_pattern.match(line)
            if match:
                ts_str, src_ip, src_port, dst_ip, dst_port, proto, pkt_len = match.groups()
                tcp_flags = None
                if "S" in line: tcp_flags = "SYN"
                elif "F" in line: tcp_flags = "FIN"
                elif "R" in line: tcp_flags = "RST"

                yield NetworkEvent(
                    timestamp=float(ts_str),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(src_port),
                    dst_port=int(dst_port),
                    protocol=proto.upper(),
                    tcp_flags=tcp_flags,
                    packet_len=int(pkt_len) if pkt_len else 60,
                    interface=self.interface,
                    capture_source="live_linux",
                    is_synthetic=False
                )
