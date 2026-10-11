"""Unit and integration tests for Linux capture adapter, MonitorRunner, and CLI monitor command."""

from __future__ import annotations

import io
import os
import struct
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from edgesentinel.analysis.parser import parse_sll_frame
from edgesentinel.capture.linux import LinuxTcpdumpAdapter
from edgesentinel.capture.simulation import SimulationCaptureAdapter
from edgesentinel.config import AppConfig
from edgesentinel.dashboard.app import create_app
from edgesentinel.monitoring.runner import MonitorRunner
from edgesentinel.storage.database import Database


def test_linux_capture_adapter_pcap_parsing():
    """Verify LinuxTcpdumpAdapter parses binary PCAP streams correctly."""
    pcap_path = Path(__file__).resolve().parent.parent / "fixtures" / "sample_scan.pcap"
    assert pcap_path.exists(), "sample_scan.pcap fixture missing"

    with open(pcap_path, "rb") as f:
        pcap_bytes = f.read()

    adapter = LinuxTcpdumpAdapter(interface="eth0", mode="pcap")
    adapter.is_running = True

    mock_process = MagicMock()
    mock_process.poll.return_value = None
    mock_process.stdout = io.BytesIO(pcap_bytes)
    adapter._process = mock_process

    events = list(adapter.stream_events())
    assert len(events) > 0
    assert adapter.packets_captured == len(events)
    first = events[0]
    assert first.capture_source == "live_linux"
    assert first.interface == "eth0"
    assert first.src_ip is not None
    assert first.protocol in ("TCP", "UDP", "ARP", "ICMP")


def test_linux_capture_adapter_text_fallback():
    """Verify fallback text parsing in LinuxTcpdumpAdapter."""
    adapter = LinuxTcpdumpAdapter(interface="wlan0", mode="text")
    adapter.is_running = True

    text_stream = (
        "1700000000.100000 IP 192.168.1.50.45000 > 192.168.1.1.80: Flags [S], tcp 0\n"
        "1700000000.200000 IP 192.168.1.1.80 > 192.168.1.50.45000: Flags [R], tcp 0\n"
    )

    mock_process = MagicMock()
    mock_process.stdout = io.StringIO(text_stream)
    adapter._process = mock_process

    events = list(adapter.stream_events())
    assert len(events) == 2
    assert events[0].src_ip == "192.168.1.50"
    assert events[0].dst_ip == "192.168.1.1"
    assert events[0].dst_port == 80
    assert events[0].tcp_flags == "SYN"
    assert events[1].tcp_flags == "RST"


def test_linux_capture_adapter_immediate_exit_detection():
    """Verify adapter detects immediate tcpdump process failure and captures stderr."""
    adapter = LinuxTcpdumpAdapter(interface="nonexistent99", mode="pcap")

    with patch("os.name", "posix"), \
         patch("shutil.which", return_value="/usr/bin/tcpdump"), \
         patch("subprocess.Popen") as mock_popen:

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = 1  # Process died immediately
        mock_proc.returncode = 1
        mock_proc.stderr.read.return_value = b"tcpdump: nonexistent99: No such device exists\n"
        mock_proc.stderr.readline.return_value = b""
        mock_popen.return_value = mock_proc

        result = adapter.start()
        assert result is False
        assert adapter.is_running is False
        assert "nonexistent99" in (adapter.last_error or "") or "exited immediately" in (adapter.last_error or "")


def test_parse_sll_frame_linux_cooked_capture():
    """Verify parsing of Linux Cooked Capture (SLL) DLT 113 frame."""
    # SLL header (16 bytes): packet_type(2), arphrd(2), slen(2), saddr(8), protocol(2)
    sll_hdr = struct.pack("!HHH8sH", 0, 1, 6, b"\x00\x11\x22\x33\x44\x55\x00\x00", 0x0800)
    # Minimal IPv4 header (20 bytes): ver/ihl(1), dscp(1), len(2), id(2), flags/frag(2), ttl(1), proto(1), chk(2), src(4), dst(4)
    ipv4_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\xc0\xa8\x01\x32", b"\xc0\xa8\x01\x01")
    # Minimal TCP header (20 bytes): src_port(2), dst_port(2), seq(4), ack(4), offset/flags(2), win(2), chk(2), urp(2)
    tcp_hdr = struct.pack("!HHIIHHHH", 54321, 80, 100, 0, (5 << 12) | 0x02, 65535, 0, 0)

    raw_frame = sll_hdr + ipv4_hdr + tcp_hdr
    event = parse_sll_frame(raw_frame, capture_source="live_linux")
    assert event is not None
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "192.168.1.1"
    assert event.src_port == 54321
    assert event.dst_port == 80
    assert event.protocol == "TCP"
    assert event.tcp_flags == "SYN"


def test_monitor_runner_lifecycle_and_simulation(tmp_path):
    """Verify MonitorRunner starts, streams synthetic packets, updates stats, and stops cleanly."""
    db_file = tmp_path / "test_monitor.db"
    cfg = AppConfig()
    cfg.storage.database_path = str(db_file)
    cfg.capture.backend = "simulation"

    runner = MonitorRunner(config=cfg)
    assert not runner.is_running

    started = runner.start(background=True)
    assert started
    assert runner.is_running

    status = runner.get_status()
    assert status["status"] == "active"
    assert status["is_running"] is True
    assert status["backend"] == "simulation"

    time.sleep(1.2)  # Allow simulation stream to yield events
    runner.stop()

    assert not runner.is_running
    status_after = runner.get_status()
    assert status_after["status"] == "stopped"
    assert status_after["packets_captured"] > 0
    assert status_after["events_processed"] > 0


def test_monitor_runner_pid_lock_prevent_duplicates(tmp_path):
    """Verify MonitorRunner prevents duplicate concurrent monitor instances."""
    db_file = tmp_path / "test_lock.db"
    cfg = AppConfig()
    cfg.storage.database_path = str(db_file)
    cfg.capture.backend = "simulation"

    runner1 = MonitorRunner(config=cfg)
    runner2 = MonitorRunner(config=cfg)

    assert runner1.start(background=True)
    try:
        # Second instance should be blocked by PID lock if external PID detected
        with patch.object(runner2, "is_external_monitor_running", return_value=88888):
            result = runner2.start(background=True)
            assert result is False
            assert "already active" in (runner2.last_error or "")
    finally:
        runner1.stop()


def test_cli_argument_ordering_universal(tmp_path):
    """Verify CLI accepts --config before and after subcommands."""
    import argparse

    test_config = tmp_path / "cfg.yaml"
    test_config.write_text("environment: test\n", encoding="utf-8")

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--config", "-c", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", default=None)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", parents=[sub_common])

    # Order A: --config before subcommand
    args_a = parser.parse_args(["--config", str(test_config), "status"])
    assert args_a.config == str(test_config)
    assert args_a.command == "status"

    # Order B: --config after subcommand
    args_b = parser.parse_args(["status", "--config", str(test_config)])
    assert args_b.config == str(test_config)
    assert args_b.command == "status"

    # Order C: default when not provided
    args_c = parser.parse_args(["status"])
    assert args_c.config is None
    assert args_c.command == "status"



def test_dashboard_api_capture_status(tmp_path):
    """Verify GET /api/status accurately reflects capture state."""
    db_file = tmp_path / "test_api.db"
    cfg = AppConfig()
    cfg.storage.database_path = str(db_file)
    cfg.capture.backend = "simulation"
    cfg.dashboard.with_monitor = True

    app = create_app(config=cfg, with_monitor=True)
    with TestClient(app) as client:
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.json()
        assert "capture" in data
        assert data["capture"]["backend"] == "simulation"
        assert data["capture"]["status"] in ("active", "stopped")
