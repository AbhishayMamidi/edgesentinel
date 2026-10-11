"""Linux capture adapter using tcpdump subprocess streaming for Raspberry Pi 3B+."""

from __future__ import annotations

import logging
import os
import re
import shutil
import struct
import subprocess
import threading
import time
from typing import Generator, List, Optional

from edgesentinel.analysis.parser import parse_ethernet_frame, parse_sll_frame, _parse_ipv4
from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.models import NetworkEvent

logger = logging.getLogger("edgesentinel.capture.linux")


class LinuxTcpdumpAdapter(BaseCaptureAdapter):
    """Streams and parses live packet metadata from a tcpdump child process on Linux / Raspberry Pi."""

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "",
        snaplen: int = 128,
        promiscuous: bool = False,
        mode: str = "pcap"
    ):
        super().__init__(interface, bpf_filter)
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.mode = mode.lower()
        self._process: Optional[subprocess.Popen] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self.pid: Optional[int] = None

    def start(self) -> bool:
        if os.name == "nt":
            logger.warning("LinuxTcpdumpAdapter is designed for Linux / Raspberry Pi systems and cannot run on Windows.")
            self.last_error = "Platform unsupported: LinuxTcpdumpAdapter requires Linux"
            return False

        if not shutil.which("tcpdump"):
            self.last_error = "tcpdump utility not found in PATH. Please install via: sudo apt-get install tcpdump"
            logger.error(self.last_error)
            return False

        if self.mode == "pcap":
            cmd: List[str] = [
                "tcpdump",
                "-U",              # Packet-buffered output
                "-w", "-",         # Write raw PCAP to stdout
                "-i", self.interface or "any",
                "-s", str(self.snaplen)
            ]
            if not self.promiscuous:
                cmd.append("-p")   # Don't put the interface into promiscuous mode
        else:
            cmd = [
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
                bufsize=0 if self.mode == "pcap" else 1,
                text=False if self.mode == "pcap" else True
            )
            self.pid = self._process.pid
            self.is_running = True

            # Dedicated thread to consume stderr, preventing pipe deadlocks and logging errors
            self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self._stderr_thread.start()

            # Verify the process didn't exit immediately on permission/interface failure
            time.sleep(0.2)
            ret = self._process.poll()
            if ret is not None:
                self.is_running = False
                err_msg = self.last_error or f"tcpdump exited immediately with status code {ret}"
                self.last_error = err_msg
                logger.error("tcpdump failed to start: %s", err_msg)
                return False

            logger.info(
                "Started tcpdump capture subprocess with PID %d on interface '%s' (mode=%s)",
                self.pid, self.interface, self.mode
            )
            return True

        except PermissionError:
            self.last_error = (
                "Permission denied running tcpdump. Ensure binary has cap_net_raw: "
                "sudo setcap cap_net_raw=eip $(which tcpdump)"
            )
            logger.error(self.last_error)
            self.is_running = False
            return False
        except Exception as e:
            self.last_error = f"Failed to start tcpdump: {e}"
            logger.error(self.last_error)
            self.is_running = False
            return False

    def _read_stderr(self) -> None:
        """Continuously read stderr lines to avoid pipe buffer deadlocks."""
        if not self._process or not self._process.stderr:
            return
        try:
            for raw_line in iter(self._process.stderr.readline, b"" if self.mode == "pcap" else ""):
                if not raw_line:
                    break
                line_str = (
                    raw_line.decode("utf-8", errors="replace").strip()
                    if isinstance(raw_line, bytes)
                    else str(raw_line).strip()
                )
                if line_str:
                    logger.debug("tcpdump stderr: %s", line_str)
                    lower = line_str.lower()
                    if "error" in lower or "denied" in lower or "no such device" in lower:
                        self.last_error = line_str
        except Exception:
            pass

    def stop(self) -> None:
        """Gracefully terminate child process."""
        self.is_running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                try:
                    self._process.kill()
                except Exception:
                    pass
            except Exception:
                pass
            self._process = None
            self.pid = None
            logger.info("tcpdump capture subprocess terminated.")

    def _read_exact(self, num_bytes: int) -> bytes:
        """Read exactly num_bytes from process binary stdout."""
        if not self._process or not self._process.stdout:
            return b""
        buf = bytearray()
        while len(buf) < num_bytes and self.is_running:
            try:
                chunk = self._process.stdout.read(num_bytes - len(buf))
                if not chunk:
                    break
                buf.extend(chunk)
            except Exception:
                break
        return bytes(buf)

    def stream_events(self) -> Generator[NetworkEvent, None, None]:
        """Stream normalized network events from tcpdump output."""
        if not self._process or not self._process.stdout:
            return

        if self.mode == "pcap":
            yield from self._stream_pcap_events()
        else:
            yield from self._stream_text_events()

    def _stream_pcap_events(self) -> Generator[NetworkEvent, None, None]:
        """Stream and parse raw PCAP bytes from tcpdump."""
        global_hdr = self._read_exact(24)
        if len(global_hdr) < 24:
            if self.is_running:
                logger.error("tcpdump stream terminated before receiving 24-byte PCAP header.")
            return

        magic = struct.unpack("!I", global_hdr[:4])[0]
        if magic == 0xA1B2C3D4:
            endian, nano = ">", False
        elif magic == 0xD4C3B2A1:
            endian, nano = "<", False
        elif magic == 0xA1B23C4D:
            endian, nano = ">", True
        elif magic == 0x4D3CB2A1:
            endian, nano = "<", True
        else:
            logger.error("Unsupported PCAP magic bytes from tcpdump: 0x%08X", magic)
            return

        _, _, _, _, _, snaplen, network = struct.unpack(f"{endian}IHHiIII", global_hdr)

        while self.is_running and self._process and self._process.poll() is None:
            pkt_hdr = self._read_exact(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            if incl_len <= 0 or incl_len > 65535:
                continue

            pkt_data = self._read_exact(incl_len)
            if len(pkt_data) < incl_len:
                break

            self.packets_captured += 1
            ts = float(ts_sec) + (float(ts_sub) / 1e9 if nano else float(ts_sub) / 1e6)

            event: Optional[NetworkEvent] = None
            if network == 1:  # DLT_EN10MB (Ethernet / WiFi)
                event = parse_ethernet_frame(pkt_data, capture_source="live_linux")
            elif network in (113, 276):  # DLT_LINUX_SLL / SLL2 ('any' interface)
                event = parse_sll_frame(pkt_data, capture_source="live_linux")
            elif network in (12, 101):  # DLT_RAW
                event = _parse_ipv4(pkt_data, "", "", capture_source="live_linux", frame_len=len(pkt_data))
            else:
                event = parse_ethernet_frame(pkt_data, capture_source="live_linux")

            if event:
                event.timestamp = ts
                event.interface = self.interface
                event.is_synthetic = False
                yield event

    def _stream_text_events(self) -> Generator[NetworkEvent, None, None]:
        # Matches e.g.: "1700000000.100000 IP 192.168.1.50.45000 > 192.168.1.1.80: Flags [S], tcp 0"
        ip_pattern = re.compile(
            r"^(\d+\.\d+)\s+IP\s+([\d\.]+)\.(\d+)\s+>\s+([\d\.]+)\.(\d+):",
            re.IGNORECASE
        )

        for line in self._process.stdout:
            if not self.is_running:
                break
            line_str = line.strip() if isinstance(line, str) else line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            self.packets_captured += 1
            match = ip_pattern.match(line_str)
            if match:
                ts_str, src_ip, src_port, dst_ip, dst_port = match.groups()
                tcp_flags = None
                flags_match = re.search(r"Flags\s*\[([^\]]+)\]", line_str)
                if flags_match:
                    f_chars = flags_match.group(1)
                    if "S" in f_chars:
                        tcp_flags = "SYN"
                    elif "F" in f_chars:
                        tcp_flags = "FIN"
                    elif "R" in f_chars:
                        tcp_flags = "RST"
                elif " S " in line_str or line_str.endswith(" S"):
                    tcp_flags = "SYN"
                elif " F " in line_str:
                    tcp_flags = "FIN"
                elif " R " in line_str:
                    tcp_flags = "RST"

                proto = "UDP" if "udp" in line_str.lower() else "TCP"
                len_match = re.search(r"(?:length|tcp|udp)\s+(\d+)", line_str, re.IGNORECASE)
                pkt_len = int(len_match.group(1)) if len_match else 60

                yield NetworkEvent(
                    timestamp=float(ts_str),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(src_port),
                    dst_port=int(dst_port),
                    protocol=proto,
                    tcp_flags=tcp_flags,
                    packet_len=pkt_len,
                    interface=self.interface,
                    capture_source="live_linux",
                    is_synthetic=False
                )

