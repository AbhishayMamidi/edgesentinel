"""Unit tests for offline streaming PCAP reader and packet decoder."""

import os
import struct
import tempfile
import pytest

from edgesentinel.analysis.parser import parse_ethernet_frame
from edgesentinel.replay.pcap_reader import PcapReader


def create_minimal_pcap_file(filepath: str, num_packets: int = 5):
    """Generate a valid binary PCAP file with IPv4 TCP packets."""
    with open(filepath, "wb") as f:
        # Global Header (24 bytes)
        # magic=0xa1b2c3d4 (big endian), version=2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for i in range(num_packets):
            # 14-byte Ethernet Header
            # Dst: 00:11:22:33:44:55, Src: AA:BB:CC:DD:EE:FF, EtherType: 0x0800 (IPv4)
            eth = struct.pack("!6s6sH", b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800)

            # 20-byte IPv4 Header
            # ver_ihl=0x45, dscp_ecn=0, total_len=40, id=1000+i, flags=0x4000, ttl=64, proto=6 (TCP), checksum=0
            # src=192.168.1.50, dst=192.168.1.1
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 40, 1000 + i, 0x4000, 64, 6, 0,
                bytes([192, 168, 1, 50]), bytes([192, 168, 1, 1])
            )

            # 20-byte TCP Header
            # src_port=50000+i, dst_port=80, seq=100, ack=0, offset_flags=0x5002 (SYN), window=65535, sum=0, urg=0
            tcp = struct.pack("!HHIIHHHH", 50000 + i, 80, 100, 0, 0x5002, 65535, 0, 0)

            pkt_bytes = eth + ip + tcp
            incl_len = len(pkt_bytes)

            # 16-byte Packet Header
            # ts_sec=1700000000+i, ts_usec=0, incl_len, orig_len
            f.write(struct.pack("!IIII", 1700000000 + i, 0, incl_len, incl_len))
            f.write(pkt_bytes)


def test_pcap_reader_streaming():
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, "test.pcap")
        create_minimal_pcap_file(pcap_path, num_packets=10)

        reader = PcapReader(pcap_path)
        events = list(reader.read_events())

        assert len(events) == 10
        assert events[0].src_ip == "192.168.1.50"
        assert events[0].dst_ip == "192.168.1.1"
        assert events[0].dst_port == 80
        assert events[0].protocol == "TCP"
        assert events[0].tcp_flags == "SYN"
        assert events[0].is_synthetic is False
        assert events[0].capture_source == "pcap"
        assert events[0].timestamp >= 1700000000


def test_parse_malformed_ethernet_frame():
    assert parse_ethernet_frame(b"short") is None
    assert parse_ethernet_frame(b"\x00" * 13) is None
