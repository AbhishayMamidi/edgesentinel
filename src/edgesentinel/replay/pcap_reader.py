"""Pure Python streaming PCAP reader processing captures with bounded memory."""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Generator, Optional

from edgesentinel.analysis.parser import parse_ethernet_frame
from edgesentinel.models import NetworkEvent

logger = logging.getLogger("edgesentinel.replay")


class PcapReader:
    """Incremental, streaming PCAP reader supporting standard 24-byte global headers."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

    def read_events(self, max_packets: Optional[int] = None) -> Generator[NetworkEvent, None, None]:
        """Stream normalized NetworkEvents packet-by-packet without buffering the file in RAM."""
        with open(self.file_path, "rb") as f:
            # 24-byte Global Header
            global_header = f.read(24)
            if len(global_header) < 24:
                logger.error("PCAP file too short to contain a valid global header.")
                return

            magic = struct.unpack("!I", global_header[:4])[0]
            if magic == 0xA1B2C3D4:
                endian = ">"
                nano = False
            elif magic == 0xD4C3B2A1:
                endian = "<"
                nano = False
            elif magic == 0xA1B23C4D:
                endian = ">"
                nano = True
            elif magic == 0x4D3CB2A1:
                endian = "<"
                nano = True
            else:
                logger.error("Unsupported or invalid PCAP magic bytes: 0x%08X", magic)
                return

            # Header unpack: magic(4), major(2), minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
            _, _, _, _, _, snaplen, network = struct.unpack(f"{endian}IHHiIII", global_header)

            packet_count = 0
            while True:
                if max_packets is not None and packet_count >= max_packets:
                    break

                # 16-byte Packet Header: ts_sec, ts_usec, incl_len, orig_len
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break  # End of file

                ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                if incl_len > snaplen or incl_len > 65535:
                    logger.warning("Packet length %d exceeds snaplen %d; stopping.", incl_len, snaplen)
                    break

                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Timestamp calculation
                ts = float(ts_sec) + (float(ts_sub) / 1e9 if nano else float(ts_sub) / 1e6)

                event = None
                # DLT_EN10MB (Ethernet) = 1
                if network == 1:
                    event = parse_ethernet_frame(pkt_data, capture_source="pcap")
                # DLT_RAW = 12 or 101 (Raw IP without Ethernet)
                elif network in (12, 101):
                    from edgesentinel.analysis.parser import _parse_ipv4
                    event = _parse_ipv4(pkt_data, "", "", capture_source="pcap", frame_len=len(pkt_data))

                if event:
                    event.timestamp = ts
                    event.is_synthetic = False
                    yield event
                    packet_count += 1
