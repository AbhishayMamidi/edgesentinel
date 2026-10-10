"""Comprehensive edge-case, boundary, and robustness unit tests for EdgeSentinel."""

import os
import struct
import tempfile
import time
import pytest

from edgesentinel.analysis.parser import parse_ethernet_frame, _parse_simple_dns
from edgesentinel.detection.port_scan import PortScanDetector
from edgesentinel.detection.syn_anomaly import SynAnomalyDetector
from edgesentinel.detection.ssh_bruteforce import SshBruteforceDetector
from edgesentinel.detection.dns_anomaly import DnsAnomalyDetector
from edgesentinel.detection.arp_anomaly import ArpAnomalyDetector
from edgesentinel.detection.traffic_anomaly import TrafficAnomalyDetector
from edgesentinel.flows.tracker import FlowTracker
from edgesentinel.inventory.devices import DeviceInventory
from edgesentinel.models import Device, NetworkEvent, Severity
from edgesentinel.simulation.generator import SyntheticTrafficGenerator
from edgesentinel.storage.database import Database


def test_malformed_packets_robustness():
    """Ensure malformed or truncated binary frames do not crash parser."""
    # 1. Truncated Ethernet
    assert parse_ethernet_frame(b"") is None
    assert parse_ethernet_frame(b"\x00" * 13) is None

    # 2. Truncated IPv4 (Ethernet valid, IP header truncated)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00"
    assert parse_ethernet_frame(eth_hdr + b"\x45\x00") is None

    # 3. Invalid IHL (< 20 bytes)
    # IHL = 4 (16 bytes), which is illegal for IPv4
    invalid_ihl_ip = b"\x44" + b"\x00" * 19
    assert parse_ethernet_frame(eth_hdr + invalid_ihl_ip) is None

    # 4. IPv4 Fragmentation (fragment offset > 0)
    # flags_frag: offset = 120 (0x000F -> 15*8 = 120 bytes)
    frag_ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 100, 1234, 0x000F, 64, 6, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    ) + (b"X" * 40)
    event_frag = parse_ethernet_frame(eth_hdr + frag_ip)
    assert event_frag is not None
    assert event_frag.protocol == "IP-FRAG"
    assert event_frag.metadata["fragment_offset"] == 120

    # 5. Malformed DNS bytes (compression pointer loop / corrupt lengths)
    query, qtype = _parse_simple_dns(b"\x00" * 10)  # Too short
    assert query is None and qtype is None

    # DNS with recursive compression pointer (C0 0C)
    dns_pointer_loop = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
    q_loop, _ = _parse_simple_dns(dns_pointer_loop)
    # Should safely terminate without infinite loop
    assert q_loop is None or isinstance(q_loop, str)

    # DNS with label length > 63
    dns_oversized_label = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x50" + (b"A" * 80)
    q_over, _ = _parse_simple_dns(dns_oversized_label)
    assert q_over is None

    # 6. Truncated ARP
    arp_hdr = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x06"
    assert parse_ethernet_frame(arp_hdr + b"\x00\x01\x08\x00") is None


def test_detector_threshold_boundaries():
    """Verify exact threshold boundaries (threshold - 1, exact threshold)."""
    # 1. Port scan boundary: threshold = 15
    ps_det = PortScanDetector(threshold_ports=15, window_seconds=10.0)
    gen = SyntheticTrafficGenerator(seed=42)

    # Exactly 14 ports (threshold - 1)
    below = gen.generate_port_scan(ports=range(1, 15))
    alerts_below = [ps_det.process_event(e) for e in below]
    assert not any(a for a in alerts_below)

    # Exactly 15th port (threshold met)
    probe_15 = NetworkEvent(
        timestamp=time.time(), src_ip="192.168.1.100", dst_ip="192.168.1.5",
        src_port=50000, dst_port=15, protocol="TCP", tcp_flags="SYN", is_synthetic=True
    )
    alert_15 = ps_det.process_event(probe_15)
    assert alert_15 is not None
    assert alert_15.detector_id == "DET-PORT-SCAN"

    # 2. SSH Brute boundary: threshold = 5
    ssh_det = SshBruteforceDetector(threshold_attempts=5, window_seconds=10.0)
    now = time.time()
    for i in range(4):  # 4 attempts (threshold - 1)
        ev = NetworkEvent(
            timestamp=now + (i * 0.1), src_ip="10.0.0.9", dst_ip="10.0.0.1",
            dst_port=22, protocol="TCP", tcp_flags="SYN", is_synthetic=True
        )
        assert ssh_det.process_event(ev) is None

    # 5th attempt -> triggers
    ev_5 = NetworkEvent(
        timestamp=now + 0.5, src_ip="10.0.0.9", dst_ip="10.0.0.1",
        dst_port=22, protocol="TCP", tcp_flags="SYN", is_synthetic=True
    )
    alert_ssh = ssh_det.process_event(ev_5)
    assert alert_ssh is not None
    assert alert_ssh.detector_id == "DET-SSH-BRUTE"


def test_arp_anomaly_unassigned_dhcp_probe_ignored():
    """Ensure ARP probes with 0.0.0.0 are ignored to prevent false positives."""
    arp_det = ArpAnomalyDetector(window_seconds=10.0)
    now = time.time()
    # RFC 5227 DHCP probe from host 1
    probe1 = NetworkEvent(
        timestamp=now, protocol="ARP", arp_op="REQUEST", arp_spa="0.0.0.0", arp_sha="AA:BB:CC:DD:EE:01",
        src_ip="0.0.0.0", dst_ip="255.255.255.255"
    )
    assert arp_det.process_event(probe1) is None

    # RFC 5227 DHCP probe from host 2 (different MAC, same 0.0.0.0)
    probe2 = NetworkEvent(
        timestamp=now + 0.1, protocol="ARP", arp_op="REQUEST", arp_spa="0.0.0.0", arp_sha="AA:BB:CC:DD:EE:02",
        src_ip="0.0.0.0", dst_ip="255.255.255.255"
    )
    # Must NOT flag as ARP conflict
    assert arp_det.process_event(probe2) is None


def test_device_inventory_multicast_filtering_and_capacity():
    """Ensure multicast addresses are ignored and inventory enforces capacity."""
    inv = DeviceInventory(max_devices=5)

    # 1. Multicast IP ignored
    mcast_event = NetworkEvent(
        src_ip="224.0.0.251", dst_ip="224.0.0.251", protocol="UDP", src_port=5353, dst_port=5353
    )
    dev, is_new = inv.observe_event(mcast_event)
    assert dev is None and is_new is False

    # 2. Capacity eviction test (max 5)
    for i in range(10):
        ev = NetworkEvent(
            src_ip=f"192.168.1.{10 + i}", dst_ip="192.168.1.1", protocol="TCP"
        )
        inv.observe_event(ev)

    assert len(inv.get_devices()) == 5


def test_flow_tracker_capacity_and_eviction():
    """Ensure flow tracker respects max_flows bound."""
    tracker = FlowTracker(max_flows=10, idle_timeout=1.0)
    now = time.time()

    # Insert 15 flows
    for i in range(15):
        ev = NetworkEvent(
            timestamp=now, src_ip="10.0.0.1", dst_ip=f"10.0.0.{i+2}",
            src_port=50000 + i, dst_port=80, protocol="TCP"
        )
        tracker.process_event(ev)

    # Bounded table must not exceed max_flows
    assert tracker.get_active_count() <= 10

    # Test idle expiration
    expired = tracker.expire_stale_flows(current_time=now + 5.0)
    assert len(expired) >= 1
    assert tracker.get_active_count() == 0


def test_alert_deduplication_sliding_window():
    """Ensure alerts with identical deduplication keys are suppressed within window."""
    ps_det = PortScanDetector(threshold_ports=5, window_seconds=10.0)
    now = time.time()

    # Trigger initial alert
    events = [
        NetworkEvent(timestamp=now, src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=p, protocol="TCP", tcp_flags="SYN")
        for p in range(20, 26)
    ]
    alerts = [ps_det.process_event(e) for e in events if ps_det.process_event(e)]
    assert len(alerts) == 1

    # Subsequent probe within deduplication window -> suppressed
    probe_again = NetworkEvent(
        timestamp=now + 1.0, src_ip="192.168.1.50", dst_ip="192.168.1.1",
        dst_port=27, protocol="TCP", tcp_flags="SYN"
    )
    assert ps_det.process_event(probe_again) is None

    # After deduplication window expires -> alerts again if threshold crossed
    now_later = now + 30.0
    ps_det._history.clear()
    events_later = [
        NetworkEvent(timestamp=now_later, src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=p, protocol="TCP", tcp_flags="SYN")
        for p in range(80, 86)
    ]
    alerts_later = [ps_det.process_event(e) for e in events_later if ps_det.process_event(e)]
    assert len(alerts_later) == 1
