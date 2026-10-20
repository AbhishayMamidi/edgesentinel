"""Unit tests for EdgeSentinel detection engines."""

import time
import pytest

from edgesentinel.detection.port_scan import PortScanDetector
from edgesentinel.detection.syn_anomaly import SynAnomalyDetector
from edgesentinel.detection.ssh_bruteforce import SshBruteforceDetector
from edgesentinel.detection.dns_anomaly import DnsAnomalyDetector
from edgesentinel.detection.arp_anomaly import ArpAnomalyDetector
from edgesentinel.detection.traffic_anomaly import TrafficAnomalyDetector
from edgesentinel.detection.new_device import NewDeviceDetector
from edgesentinel.models import Device, NetworkEvent, Severity
from edgesentinel.simulation.generator import SyntheticTrafficGenerator


def collect_alerts(detector, events):
    """Helper to process events sequentially and collect non-None alerts."""
    alerts = []
    for e in events:
        a = detector.process_event(e)
        if a is not None:
            alerts.append(a)
    return alerts


def test_port_scan_detector_threshold_and_evidence():
    detector = PortScanDetector(threshold_ports=10, window_seconds=5.0)
    gen = SyntheticTrafficGenerator(seed=123)

    # 1. Below threshold (5 ports) -> No alert
    events_below = gen.generate_port_scan(
        src_ip="192.168.1.100", dst_ip="192.168.1.5", ports=range(80, 85)
    )
    alerts = collect_alerts(detector, events_below)
    assert len(alerts) == 0

    # 2. Exceeds threshold (15 ports) -> Triggers alert
    events_above = gen.generate_port_scan(
        src_ip="192.168.1.100", dst_ip="192.168.1.5", ports=range(80, 95)
    )
    alerts_triggered = collect_alerts(detector, events_above)

    assert len(alerts_triggered) == 1
    alert = alerts_triggered[0]
    assert alert.detector_id == "DET-PORT-SCAN"
    assert alert.severity == Severity.HIGH
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "192.168.1.5"
    assert alert.evidence["distinct_ports_count"] >= 10
    assert len(alert.recommendations) > 0
    assert alert.is_synthetic is True


def test_port_scan_benign_traffic_no_false_positive():
    detector = PortScanDetector(threshold_ports=10, window_seconds=5.0)
    gen = SyntheticTrafficGenerator(seed=123)
    events = gen.generate_normal_tcp(src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=443, count=25)
    alerts = collect_alerts(detector, events)
    assert len(alerts) == 0


def test_syn_flood_detector():
    detector = SynAnomalyDetector(threshold_syn_rate=20.0, window_seconds=5.0)
    gen = SyntheticTrafficGenerator(seed=123)

    normal = gen.generate_normal_tcp(count=5)
    assert len(collect_alerts(detector, normal)) == 0

    flood = gen.generate_syn_flood(count=40, interval_seconds=0.02)
    alerts = collect_alerts(detector, flood)
    assert len(alerts) >= 1
    assert alerts[0].detector_id == "DET-SYN-FLOOD"
    assert alerts[0].severity == Severity.HIGH


def test_syn_flood_benign_burst_no_false_positive():
    """Verify that a standard 5-packet burst within a fraction of a second does not trigger a false flood alert."""
    detector = SynAnomalyDetector(threshold_syn_rate=25.0, window_seconds=5.0)
    now = time.time()
    # 5 SYN packets within 50ms (typical for rapid page load parallel requests)
    events = [
        NetworkEvent(
            timestamp=now + (i * 0.01),
            src_ip="192.168.88.1",
            dst_ip="192.168.88.11",
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            tcp_flags="SYN",
            is_synthetic=True
        )
        for i in range(5)
    ]
    alerts = collect_alerts(detector, events)
    assert len(alerts) == 0


def test_ssh_bruteforce_detector():
    detector = SshBruteforceDetector(threshold_attempts=5, window_seconds=30.0)
    gen = SyntheticTrafficGenerator(seed=123)

    low = gen.generate_ssh_bruteforce(attempts=2)
    assert len(collect_alerts(detector, low)) == 0

    # Case A: Repeated auth failure logs -> Severity.HIGH
    high_auth = gen.generate_ssh_bruteforce(attempts=8)
    alerts_auth = collect_alerts(detector, high_auth)
    assert len(alerts_auth) == 1
    assert alerts_auth[0].detector_id == "DET-SSH-BRUTE"
    assert alerts_auth[0].severity == Severity.HIGH
    assert "Authentication Failures" in alerts_auth[0].title
    assert alerts_auth[0].evidence["verified_auth_failure_logs"] is True

    # Case B: Connection attempts only without auth logs -> Severity.MEDIUM
    detector.reset()
    now = time.time()
    conn_only = [
        NetworkEvent(
            timestamp=now + (i * 0.1),
            src_ip="192.168.1.111", dst_ip="192.168.1.20",
            src_port=40000 + i, dst_port=22, protocol="TCP", tcp_flags="SYN",
            metadata={}  # No auth_failure flag
        )
        for i in range(8)
    ]
    alerts_conn = collect_alerts(detector, conn_only)
    assert len(alerts_conn) == 1
    assert alerts_conn[0].detector_id == "DET-SSH-BRUTE"
    assert alerts_conn[0].severity == Severity.MEDIUM
    assert "Connection Rate" in alerts_conn[0].title


def test_dns_anomaly_detector_long_query_and_rate():
    detector = DnsAnomalyDetector(query_rate_threshold=15.0, max_query_len=50, window_seconds=5.0)
    now = time.time()

    # Long query tunneling check
    long_event = NetworkEvent(
        timestamp=now,
        src_ip="10.0.0.5", dst_ip="8.8.8.8", src_port=50000, dst_port=53, protocol="UDP",
        dns_query="exfiltration-chunk-123456789012345678901234567890.attacker.com"
    )
    alert = detector.process_event(long_event)
    assert alert is not None
    assert alert.detector_id == "DET-DNS-ANOMALY"
    assert "Tunneling" in alert.title

    # Rate burst check
    detector.reset()
    burst_events = [
        NetworkEvent(
            timestamp=now + (i * 0.02),
            src_ip="10.0.0.5", dst_ip="8.8.8.8", src_port=50000 + i, dst_port=53, protocol="UDP",
            dns_query=f"test{i}.com"
        )
        for i in range(25)
    ]
    rate_alerts = collect_alerts(detector, burst_events)
    assert len(rate_alerts) >= 1


def test_arp_anomaly_detector():
    detector = ArpAnomalyDetector(window_seconds=30.0)
    gen = SyntheticTrafficGenerator(seed=123)

    conflict = gen.generate_arp_conflict(
        target_ip="192.168.1.1", legit_mac="00:11:22:33:44:00", spoofed_mac="AA:BB:CC:DD:EE:99"
    )
    alerts = collect_alerts(detector, conflict)
    assert len(alerts) == 1
    assert alerts[0].detector_id == "DET-ARP-SPOOF"
    assert alerts[0].evidence["known_mac"] == "00:11:22:33:44:00"
    assert alerts[0].evidence["conflicting_mac"] == "AA:BB:CC:DD:EE:99"


def test_new_device_detector():
    detector = NewDeviceDetector(enabled=True)

    untrusted_dev = Device(ip="192.168.1.200", mac="11:22:33:44:55:66", is_trusted=False)
    alert = detector.process_new_device(untrusted_dev)
    assert alert is not None
    assert alert.detector_id == "DET-NEW-DEVICE"
    assert alert.src_ip == "192.168.1.200"

    # Trusted device -> Should not alert
    trusted_dev = Device(ip="192.168.1.1", mac="00:00:00:00:00:01", is_trusted=True)
    alert_trusted = detector.process_new_device(trusted_dev)
    assert alert_trusted is None
