"""Pure Python zero-dependency streaming packet decoder for Ethernet, IPv4, TCP, UDP, ARP, and DNS."""

from __future__ import annotations

import socket
import struct
from typing import Optional, Tuple

from edgesentinel.models import NetworkEvent


def parse_ethernet_frame(data: bytes, capture_source: str = "pcap") -> Optional[NetworkEvent]:
    """Parse raw Ethernet frame bytes into a normalized NetworkEvent."""
    if len(data) < 14:
        return None

    # Ethernet Header: Dest MAC (6), Src MAC (6), EtherType (2)
    dst_mac_bytes, src_mac_bytes, eth_type = struct.unpack("!6s6sH", data[:14])
    src_mac = ":".join(f"{b:02x}" for b in src_mac_bytes).upper()
    dst_mac = ":".join(f"{b:02x}" for b in dst_mac_bytes).upper()
    payload = data[14:]

    # Handle 802.1Q VLAN Tagging if present
    if eth_type == 0x8100 and len(payload) >= 4:
        eth_type = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]

    # IPv4
    if eth_type == 0x0800:
        return _parse_ipv4(payload, src_mac, dst_mac, capture_source, len(data))

    # ARP
    elif eth_type == 0x0806:
        return _parse_arp(payload, capture_source, len(data))

    return None


def parse_sll_frame(data: bytes, capture_source: str = "pcap") -> Optional[NetworkEvent]:
    """Parse Linux Cooked Capture (SLL) frame bytes into a normalized NetworkEvent."""
    if len(data) < 16:
        return None

    packet_type, arphrd, addr_len, addr_bytes, eth_type = struct.unpack("!HHH8sH", data[:16])
    src_mac = ""
    if 0 < addr_len <= 8:
        src_mac = ":".join(f"{b:02x}" for b in addr_bytes[:addr_len]).upper()

    payload = data[16:]
    if eth_type == 0x0800:
        return _parse_ipv4(payload, src_mac, "", capture_source, len(data))
    elif eth_type == 0x0806:
        return _parse_arp(payload, capture_source, len(data))

    return None



def _parse_ipv4(data: bytes, src_mac: str, dst_mac: str, capture_source: str, frame_len: int) -> Optional[NetworkEvent]:
    if len(data) < 20:
        return None

    ver_ihl = data[0]
    version = (ver_ihl >> 4) & 0x0F
    if version != 4:
        return None

    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None

    total_len = struct.unpack("!H", data[2:4])[0]
    if total_len < ihl:
        return None

    # Check IPv4 Fragmentation: flags (3 bits) + fragment offset (13 bits)
    flags_frag = struct.unpack("!H", data[6:8])[0]
    fragment_offset = (flags_frag & 0x1FFF) * 8

    # Non-initial fragments do not start with transport headers
    if fragment_offset != 0:
        src_ip_bytes = data[12:16]
        dst_ip_bytes = data[16:20]
        return NetworkEvent(
            src_ip=socket.inet_ntoa(src_ip_bytes),
            dst_ip=socket.inet_ntoa(dst_ip_bytes),
            protocol="IP-FRAG",
            packet_len=frame_len,
            capture_source=capture_source,
            is_synthetic=False,
            metadata={"fragment_offset": fragment_offset}
        )

    protocol_num = data[9]
    src_ip_bytes = data[12:16]
    dst_ip_bytes = data[16:20]
    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)
    transport_data = data[ihl:]

    # TCP
    if protocol_num == 6 and len(transport_data) >= 20:
        data_offset = (transport_data[12] >> 4) * 4
        if data_offset < 20 or len(transport_data) < data_offset:
            return None
        src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHIIH", transport_data[:14])
        flags_val = offset_flags & 0x01FF

        flag_names = []
        if flags_val & 0x0002: flag_names.append("SYN")
        if flags_val & 0x0010: flag_names.append("ACK")
        if flags_val & 0x0001: flag_names.append("FIN")
        if flags_val & 0x0004: flag_names.append("RST")
        if flags_val & 0x0008: flag_names.append("PSH")
        if flags_val & 0x0020: flag_names.append("URG")

        tcp_flags = "-".join(flag_names) if flag_names else None

        return NetworkEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            tcp_flags=tcp_flags,
            packet_len=frame_len,
            capture_source=capture_source,
            is_synthetic=False,
            metadata={"src_mac": src_mac, "dst_mac": dst_mac}
        )

    # UDP
    elif protocol_num == 17 and len(transport_data) >= 8:
        src_port, dst_port, udp_len = struct.unpack("!HHH", transport_data[:6])
        if udp_len < 8:
            return None
        udp_payload = transport_data[8:]
        dns_query = None
        dns_qtype = None

        # Basic DNS dissection if port 53
        if (src_port == 53 or dst_port == 53) and len(udp_payload) >= 12:
            dns_query, dns_qtype = _parse_simple_dns(udp_payload)

        return NetworkEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="UDP",
            packet_len=frame_len,
            capture_source=capture_source,
            dns_query=dns_query,
            dns_qtype=dns_qtype,
            is_synthetic=False,
            metadata={"src_mac": src_mac, "dst_mac": dst_mac}
        )

    # ICMP
    elif protocol_num == 1 and len(transport_data) >= 4:
        icmp_type, icmp_code = struct.unpack("!BB", transport_data[:2])
        return NetworkEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="ICMP",
            packet_len=frame_len,
            capture_source=capture_source,
            is_synthetic=False,
            metadata={"icmp_type": icmp_type, "icmp_code": icmp_code}
        )

    # Other IP
    return NetworkEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=f"IP-{protocol_num}",
        packet_len=frame_len,
        capture_source=capture_source,
        is_synthetic=False
    )


def _parse_arp(data: bytes, capture_source: str, frame_len: int) -> Optional[NetworkEvent]:
    if len(data) < 28:
        return None

    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", data[:8])
    if hw_type == 1 and proto_type == 0x0800 and hw_len == 6 and proto_len == 4:
        sha_bytes, spa_bytes, tha_bytes, tpa_bytes = struct.unpack("!6s4s6s4s", data[8:28])
        sha = ":".join(f"{b:02x}" for b in sha_bytes).upper()
        spa = socket.inet_ntoa(spa_bytes)
        tha = ":".join(f"{b:02x}" for b in tha_bytes).upper()
        tpa = socket.inet_ntoa(tpa_bytes)
        op_str = "REQUEST" if opcode == 1 else ("REPLY" if opcode == 2 else str(opcode))

        return NetworkEvent(
            src_ip=spa,
            dst_ip=tpa,
            protocol="ARP",
            packet_len=frame_len,
            capture_source=capture_source,
            arp_op=op_str,
            arp_sha=sha,
            arp_spa=spa,
            arp_tha=tha,
            arp_tpa=tpa,
            is_synthetic=False
        )
    return None


def _parse_simple_dns(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Extract first question name and type from raw DNS wire bytes."""
    try:
        # Header is 12 bytes
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return None, None

        idx = 12
        labels = []
        label_count = 0
        while idx < len(data) and label_count < 64:
            length = data[idx]
            if length == 0:
                idx += 1
                break
            # Ignore pointer compression for simple query name extraction
            if (length & 0xC0) == 0xC0:
                idx += 2
                break
            # RFC 1035: Label length cannot exceed 63 octets
            if length > 63 or idx + 1 + length > len(data):
                break
            idx += 1
            labels.append(data[idx:idx + length].decode("ascii", errors="replace"))
            idx += length
            label_count += 1

        query_name = ".".join(labels) if labels else None
        qtype_str = None
        if idx + 2 <= len(data):
            qtype = struct.unpack("!H", data[idx:idx + 2])[0]
            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
            qtype_str = type_map.get(qtype, str(qtype))

        return query_name, qtype_str
    except Exception:
        return None, None
