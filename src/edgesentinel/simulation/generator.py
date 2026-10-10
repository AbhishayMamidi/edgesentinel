"""Deterministic synthetic network traffic generator for testing and evaluation."""

from __future__ import annotations

import random
import time
from typing import Iterable, List, Optional

from edgesentinel.models import NetworkEvent


class SyntheticTrafficGenerator:
    """Generates clearly marked synthetic network events with deterministic seeds."""

    def __init__(self, seed: Optional[int] = 42):
        self.rng = random.Random(seed)

    def generate_normal_tcp(
        self,
        src_ip: str = "192.168.1.50",
        dst_ip: str = "192.168.1.1",
        dst_port: int = 443,
        count: int = 10,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate normal bidirectional TCP session events."""
        t = start_time if start_time is not None else time.time()
        src_port = self.rng.randint(49152, 65535)
        events = []

        # 3-way handshake
        events.append(NetworkEvent(
            timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol="TCP",
            tcp_flags="SYN", packet_len=60, capture_source="simulation", is_synthetic=True
        ))
        t += 0.01
        events.append(NetworkEvent(
            timestamp=t, src_ip=dst_ip, dst_ip=src_ip,
            src_port=dst_port, dst_port=src_port, protocol="TCP",
            tcp_flags="SYN-ACK", packet_len=60, capture_source="simulation", is_synthetic=True
        ))
        t += 0.01
        events.append(NetworkEvent(
            timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol="TCP",
            tcp_flags="ACK", packet_len=52, capture_source="simulation", is_synthetic=True
        ))

        # Data exchange
        for _ in range(max(1, count - 4)):
            t += 0.05 + self.rng.uniform(0.01, 0.05)
            # Request
            events.append(NetworkEvent(
                timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol="TCP",
                tcp_flags="ACK", packet_len=self.rng.randint(100, 1400),
                capture_source="simulation", is_synthetic=True
            ))
            t += 0.02
            # Response
            events.append(NetworkEvent(
                timestamp=t, src_ip=dst_ip, dst_ip=src_ip,
                src_port=dst_port, dst_port=src_port, protocol="TCP",
                tcp_flags="ACK", packet_len=self.rng.randint(200, 1500),
                capture_source="simulation", is_synthetic=True
            ))

        # Teardown
        t += 0.05
        events.append(NetworkEvent(
            timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol="TCP",
            tcp_flags="FIN-ACK", packet_len=52, capture_source="simulation", is_synthetic=True
        ))
        t += 0.01
        events.append(NetworkEvent(
            timestamp=t, src_ip=dst_ip, dst_ip=src_ip,
            src_port=dst_port, dst_port=src_port, protocol="TCP",
            tcp_flags="ACK", packet_len=52, capture_source="simulation", is_synthetic=True
        ))

        return events

    def generate_normal_udp(
        self,
        src_ip: str = "192.168.1.50",
        dst_ip: str = "1.1.1.1",
        dst_port: int = 53,
        count: int = 5,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate normal UDP requests and responses (e.g. DNS)."""
        t = start_time if start_time is not None else time.time()
        events = []
        for _ in range(count):
            t += self.rng.uniform(0.5, 2.0)
            src_port = self.rng.randint(49152, 65535)
            # Query
            events.append(NetworkEvent(
                timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol="UDP",
                packet_len=75, dns_query="example.org", dns_qtype="A",
                capture_source="simulation", is_synthetic=True
            ))
            t += 0.03
            # Reply
            events.append(NetworkEvent(
                timestamp=t, src_ip=dst_ip, dst_ip=src_ip,
                src_port=dst_port, dst_port=src_port, protocol="UDP",
                packet_len=120, dns_query="example.org", dns_qtype="A", dns_rcode=0,
                capture_source="simulation", is_synthetic=True
            ))
        return events

    def generate_port_scan(
        self,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "192.168.1.5",
        ports: Optional[Iterable[int]] = None,
        interval_seconds: float = 0.05,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate SYN port-scan pattern targeting distinct ports."""
        target_ports = list(ports) if ports is not None else list(range(20, 45))
        t = start_time if start_time is not None else time.time()
        events = []

        for port in target_ports:
            events.append(NetworkEvent(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=self.rng.randint(40000, 60000),
                dst_port=port,
                protocol="TCP",
                tcp_flags="SYN",
                packet_len=60,
                capture_source="simulation",
                is_synthetic=True,
                metadata={"scan_technique": "TCP SYN Half-Open"}
            ))
            t += interval_seconds

        return events

    def generate_syn_flood(
        self,
        src_ip: str = "192.168.1.105",
        dst_ip: str = "192.168.1.1",
        count: int = 50,
        interval_seconds: float = 0.02,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate elevated SYN rate without completing handshakes."""
        t = start_time if start_time is not None else time.time()
        events = []
        for _ in range(count):
            events.append(NetworkEvent(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=self.rng.randint(1024, 65535),
                dst_port=80,
                protocol="TCP",
                tcp_flags="SYN",
                packet_len=60,
                capture_source="simulation",
                is_synthetic=True
            ))
            t += interval_seconds
        return events

    def generate_ssh_bruteforce(
        self,
        src_ip: str = "192.168.1.110",
        dst_ip: str = "192.168.1.20",
        attempts: int = 8,
        interval_seconds: float = 0.5,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate repeated connection attempts to SSH port 22."""
        t = start_time if start_time is not None else time.time()
        events = []
        for _ in range(attempts):
            src_port = self.rng.randint(30000, 60000)
            # SYN attempt
            events.append(NetworkEvent(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=22,
                protocol="TCP",
                tcp_flags="SYN",
                packet_len=60,
                capture_source="simulation",
                is_synthetic=True,
                metadata={"auth_failure": True}
            ))
            t += interval_seconds
        return events

    def generate_dns_burst(
        self,
        src_ip: str = "192.168.1.115",
        dns_server: str = "192.168.1.1",
        count: int = 30,
        include_long_query: bool = True,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate high-frequency or anomalous DNS queries."""
        t = start_time if start_time is not None else time.time()
        events = []
        for i in range(count):
            if include_long_query and i == 5:
                domain = "a" * 70 + ".tunnel.exfiltrate-data.example.com"
            else:
                domain = f"query-{i}-{self.rng.randint(100, 999)}.domain.com"

            events.append(NetworkEvent(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dns_server,
                src_port=self.rng.randint(40000, 60000),
                dst_port=53,
                protocol="UDP",
                packet_len=65 + len(domain),
                dns_query=domain,
                dns_qtype="A",
                capture_source="simulation",
                is_synthetic=True
            ))
            t += 0.04  # 25 queries per second
        return events

    def generate_arp_conflict(
        self,
        target_ip: str = "192.168.1.1",
        legit_mac: str = "00:11:22:33:44:00",
        spoofed_mac: str = "AA:BB:CC:DD:EE:99",
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate conflicting ARP mapping (ARP spoof / poisoned cache)."""
        t = start_time if start_time is not None else time.time()
        events = [
            # Legitimate mapping announcement
            NetworkEvent(
                timestamp=t,
                src_ip=target_ip,
                dst_ip="255.255.255.255",
                protocol="ARP",
                arp_op="REPLY",
                arp_spa=target_ip,
                arp_sha=legit_mac,
                capture_source="simulation",
                is_synthetic=True
            ),
            # Conflicting spoofed announcement from different MAC
            NetworkEvent(
                timestamp=t + 1.0,
                src_ip=target_ip,
                dst_ip="255.255.255.255",
                protocol="ARP",
                arp_op="REPLY",
                arp_spa=target_ip,
                arp_sha=spoofed_mac,
                capture_source="simulation",
                is_synthetic=True
            )
        ]
        return events

    def generate_traffic_spike(
        self,
        src_ip: str = "192.168.1.120",
        dst_ip: str = "192.168.1.1",
        count: int = 150,
        packet_len: int = 1500,
        interval_seconds: float = 0.01,
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate sudden high-volume traffic burst."""
        t = start_time if start_time is not None else time.time()
        events = []
        for _ in range(count):
            events.append(NetworkEvent(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=50000,
                dst_port=80,
                protocol="TCP",
                tcp_flags="ACK",
                packet_len=packet_len,
                capture_source="simulation",
                is_synthetic=True
            ))
            t += interval_seconds
        return events

    def generate_new_device(
        self,
        ip: str = "192.168.1.240",
        mac: str = "52:54:00:12:34:56",
        start_time: Optional[float] = None
    ) -> List[NetworkEvent]:
        """Generate initial observation packet from a newly connected device."""
        t = start_time if start_time is not None else time.time()
        return [
            NetworkEvent(
                timestamp=t,
                src_ip=ip,
                dst_ip="255.255.255.255",
                protocol="ARP",
                arp_op="REQUEST",
                arp_spa=ip,
                arp_sha=mac,
                capture_source="simulation",
                is_synthetic=True
            )
        ]
