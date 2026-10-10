"""Command-Line Interface for EdgeSentinel."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

# Reconfigure standard streams for Windows terminal encoding resilience
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

src_dir = str(Path(__file__).resolve().parent.parent)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from edgesentinel.analysis.pipeline import EventPipeline
from edgesentinel.config import load_config
from edgesentinel.platform_info import get_platform_info
from edgesentinel.simulation.scenarios import get_scenario_events
from edgesentinel.storage.database import Database

try:
    from rich.console import Console
    from rich.table import Table
    console = Console(legacy_windows=False)
    HAS_RICH = True
except Exception:
    HAS_RICH = False


def print_msg(msg: str, style: str = "") -> None:
    # Strip or replace unicode characters that may break Windows consoles
    safe_msg = msg.encode("ascii", errors="replace").decode("ascii") if not HAS_RICH else msg
    if HAS_RICH and style:
        try:
            console.print(f"[{style}]{msg}[/{style}]")
            return
        except Exception:
            pass
    print(safe_msg)


def cmd_status(args) -> int:
    config = load_config(args.config)
    db = Database(config.storage.database_path)
    plat = get_platform_info()
    stats = db.get_stats()

    print_msg("=== EdgeSentinel Status ===", "bold cyan")
    print(f"Operating System   : {plat['os']} {plat['release']} ({plat['architecture']})")
    print(f"Python Version     : {plat['python_version']}")
    print(f"Admin / Privileged : {'Yes' if plat['is_admin'] else 'No (Unprivileged)'}")
    print(f"System RAM         : {plat['available_ram_mb']} MB available / {plat['total_ram_mb']} MB total")
    print(f"Capture Backend    : {config.capture.backend}")
    print(f"Tcpdump Available  : {'Yes' if plat['has_tcpdump'] else 'No'}")
    print(f"Npcap Available    : {'Yes' if plat['has_npcap'] else 'No'}")
    print(f"Database Path      : {stats['db_path']} ({stats['db_size_kb']} KB)")
    print(f"Total Events       : {stats['total_events']}")
    print(f"Total Alerts       : {stats['total_alerts']}")
    print(f"Observed Devices   : {stats['total_devices']}")
    print(f"Active Flows       : {stats['active_flows']}")
    return 0


def cmd_config_check(args) -> int:
    try:
        config = load_config(args.config)
        print_msg("[OK] Configuration is valid and verified.", "bold green")
        print(f"Environment    : {config.environment}")
        print(f"Database Path  : {config.storage.database_path}")
        print(f"Retention Days : {config.storage.retention_days}")
        print(f"Dashboard Host : {config.dashboard.host}:{config.dashboard.port}")
        print(f"Port Scan Det  : {'Enabled' if config.detection.port_scan.enabled else 'Disabled'} (Threshold: {config.detection.port_scan.threshold_ports} ports / {config.detection.port_scan.window_seconds}s)")
        print(f"SYN Flood Det  : {'Enabled' if config.detection.syn_anomaly.enabled else 'Disabled'}")
        print(f"SSH Brute Det  : {'Enabled' if config.detection.ssh_bruteforce.enabled else 'Disabled'}")
        print(f"DNS Anomaly Det: {'Enabled' if config.detection.dns_anomaly.enabled else 'Disabled'}")
        print(f"ARP Anomaly Det: {'Enabled' if config.detection.arp_anomaly.enabled else 'Disabled'}")
        print(f"Traffic Anom   : {'Enabled' if config.detection.traffic_anomaly.enabled else 'Disabled'}")
        print(f"Trusted Hosts  : {', '.join(config.inventory.trusted_devices)}")
        return 0
    except Exception as e:
        print_msg(f"[ERROR] Configuration Error: {e}", "bold red")
        return 1


def cmd_alerts(args) -> int:
    config = load_config(args.config)
    db = Database(config.storage.database_path)
    alerts = db.get_alerts(limit=args.limit, severity=args.severity)

    if not alerts:
        print_msg("No alerts found matching criteria.", "yellow")
        return 0

    if HAS_RICH:
        table = Table(title="EdgeSentinel Alerts")
        table.add_column("ID", style="cyan")
        table.add_column("Time", style="dim")
        table.add_column("Severity", style="bold")
        table.add_column("Detector")
        table.add_column("Source -> Target")
        table.add_column("Title")
        table.add_column("Simulated")

        for a in alerts:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(a.timestamp))
            sev_color = {
                "CRITICAL": "red bold",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "green"
            }.get(a.severity.value, "white")
            target = f"{a.src_ip or '-'} -> {a.dst_ip or '-'}"
            sim_badge = "[italic yellow]SIMULATED[/italic yellow]" if a.is_synthetic else "OBSERVED"
            table.add_row(
                a.id, t_str, f"[{sev_color}]{a.severity.value}[/{sev_color}]",
                a.detector_id, target, a.title, sim_badge
            )
        console.print(table)
    else:
        print(f"{'ID':<14} {'SEVERITY':<10} {'DETECTOR':<16} {'TITLE'}")
        print("-" * 75)
        for a in alerts:
            sim = "[SIM]" if a.is_synthetic else ""
            print(f"{a.id:<14} {a.severity.value:<10} {a.detector_id:<16} {a.title} {sim}")

    return 0


def cmd_devices(args) -> int:
    config = load_config(args.config)
    db = Database(config.storage.database_path)
    devices = db.get_devices()

    if not devices:
        print_msg("No observed devices in inventory.", "yellow")
        return 0

    if HAS_RICH:
        table = Table(title="Device Inventory")
        table.add_column("IP Address", style="bold cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Trusted", style="bold")
        table.add_column("Packets", justify="right")
        table.add_column("First Seen", style="dim")
        table.add_column("Last Seen", style="dim")

        for d in devices:
            f_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(d.first_seen))
            l_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(d.last_seen))
            trust = "[green]YES[/green]" if d.is_trusted else "[yellow]NO[/yellow]"
            table.add_row(d.ip, d.mac or "-", trust, str(d.packet_count), f_str, l_str)
        console.print(table)
    else:
        print(f"{'IP':<18} {'MAC':<20} {'TRUSTED':<10} {'PACKETS':<10}")
        print("-" * 60)
        for d in devices:
            print(f"{d.ip:<18} {d.mac or '-':<20} {'YES' if d.is_trusted else 'NO':<10} {d.packet_count:<10}")

    return 0


def cmd_events(args) -> int:
    config = load_config(args.config)
    db = Database(config.storage.database_path)
    events = db.get_events(limit=args.limit)

    if not events:
        print_msg("No network events found in database.", "yellow")
        return 0

    print(f"{'TIMESTAMP':<20} {'PROTO':<6} {'SRC':<21} {'DST':<21} {'FLAGS':<8} {'SOURCE'}")
    print("-" * 88)
    for e in events:
        t_str = time.strftime("%H:%M:%S", time.gmtime(e.timestamp))
        src = f"{e.src_ip}:{e.src_port or 0}"
        dst = f"{e.dst_ip}:{e.dst_port or 0}"
        sim = "SIMULATED" if e.is_synthetic else "OBSERVED"
        print(f"{t_str:<20} {e.protocol:<6} {src:<21} {dst:<21} {e.tcp_flags or '-':<8} {sim}")
    return 0


def cmd_simulate(args) -> int:
    scenario = args.scenario
    print_msg(f"Generating synthetic scenario: '{scenario}'...", "bold cyan")
    try:
        events = get_scenario_events(scenario, count_modifier=args.multiplier)
    except ValueError as e:
        print_msg(f"Error: {e}", "bold red")
        return 1

    config = load_config(args.config)
    db = Database(config.storage.database_path)
    pipeline = EventPipeline(config=config, db=db)

    start_time = time.time()
    alerts = pipeline.ingest_events(events)
    elapsed = time.time() - start_time

    print_msg(
        f"[+] Processed {len(events)} synthetic events in {elapsed:.3f}s. "
        f"Triggered {len(alerts)} alert(s).",
        "bold green"
    )

    for a in alerts:
        print_msg(f" -> [{a.severity.value}] {a.detector_id}: {a.title}", "yellow")
        if a.evidence:
            print(f"    Evidence: {a.evidence}")

    return 0


def cmd_db_check(args) -> int:
    config = load_config(args.config)
    db = Database(config.storage.database_path)
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        res = cursor.fetchone()[0]

    stats = db.get_stats()
    print_msg("=== SQLite Database Check ===", "bold cyan")
    print(f"Integrity Check: {res}")
    print(f"Database File  : {stats['db_path']}")
    print(f"File Size      : {stats['db_size_kb']} KB")
    print(f"Events Stored  : {stats['total_events']}")
    print(f"Alerts Stored  : {stats['total_alerts']}")
    print(f"Devices Stored : {stats['total_devices']}")
    return 0 if res == "ok" else 1


def cmd_replay(args) -> int:
    from edgesentinel.replay.pcap_reader import PcapReader

    pcap_path = args.pcap_file
    print_msg(f"Streaming PCAP file: '{pcap_path}'...", "bold cyan")
    try:
        reader = PcapReader(pcap_path)
    except FileNotFoundError as e:
        print_msg(f"[ERROR] {e}", "bold red")
        return 1

    config = load_config(args.config)
    db = Database(config.storage.database_path)
    pipeline = EventPipeline(config=config, db=db)

    count = 0
    alerts_triggered = 0
    start = time.time()
    for event in reader.read_events(max_packets=args.max_packets):
        alert = pipeline.ingest_event(event)
        if alert:
            alerts_triggered += 1
            print_msg(f" -> [{alert.severity.value}] {alert.detector_id}: {alert.title}", "yellow")
        count += 1

    pipeline.flush()
    elapsed = time.time() - start
    print_msg(
        f"[+] Replayed {count} packet events in {elapsed:.3f}s. "
        f"Triggered {alerts_triggered} alert(s).",
        "bold green"
    )
    return 0


def cmd_dashboard(args) -> int:
    import uvicorn
    from edgesentinel.dashboard.app import create_app

    config = load_config(args.config)
    port = args.port or config.dashboard.port
    host = args.host or config.dashboard.host

    print_msg(f"Starting EdgeSentinel Local Dashboard on http://{host}:{port}", "bold green")
    print_msg("Defensive local-first security: Strictly bound to localhost.", "dim")
    app = create_app(config)
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="edgesentinel",
        description="EdgeSentinel: Local-First Lightweight Network Security Monitoring Platform"
    )
    parser.add_argument("--config", "-c", help="Path to config.yaml", default=None)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # status
    subparsers.add_parser("status", help="Display application and host platform status")

    # config-check
    subparsers.add_parser("config-check", help="Validate configuration settings")

    # alerts
    alerts_p = subparsers.add_parser("alerts", help="Query recorded security alerts")
    alerts_p.add_argument("--limit", type=int, default=50, help="Maximum alerts to retrieve")
    alerts_p.add_argument("--severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by severity")

    # devices
    subparsers.add_parser("devices", help="List observed network devices")

    # events
    events_p = subparsers.add_parser("events", help="List recent network traffic events")
    events_p.add_argument("--limit", type=int, default=50, help="Maximum events to retrieve")

    # simulate
    sim_p = subparsers.add_parser("simulate", help="Inject deterministic synthetic traffic scenario")
    sim_p.add_argument(
        "scenario",
        choices=["port-scan", "syn-flood", "ssh-failures", "dns-burst", "arp-conflict", "traffic-spike", "new-device", "normal-traffic"],
        help="Scenario pattern to simulate"
    )
    sim_p.add_argument("--multiplier", type=int, default=1, help="Scale factor for event count")

    # db-check
    subparsers.add_parser("db-check", help="Verify SQLite database integrity")

    # replay
    replay_p = subparsers.add_parser("replay", help="Replay packet events from an offline PCAP capture")
    replay_p.add_argument("pcap_file", help="Path to PCAP file")
    replay_p.add_argument("--max-packets", type=int, default=None, help="Stop after N packets")

    # dashboard
    dash_p = subparsers.add_parser("dashboard", help="Launch local web monitoring dashboard")
    dash_p.add_argument("--port", type=int, default=None, help="Dashboard port")
    dash_p.add_argument("--host", default=None, help="Dashboard host")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "status": cmd_status,
        "config-check": cmd_config_check,
        "alerts": cmd_alerts,
        "devices": cmd_devices,
        "events": cmd_events,
        "simulate": cmd_simulate,
        "replay": cmd_replay,
        "db-check": cmd_db_check,
        "dashboard": cmd_dashboard,
    }

    handler = handlers.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
