"""Named simulation scenarios for testing, evaluation, and CLI triggers."""

from __future__ import annotations

from typing import List
from edgesentinel.models import NetworkEvent
from edgesentinel.simulation.generator import SyntheticTrafficGenerator


def get_scenario_events(scenario_name: str, count_modifier: int = 1) -> List[NetworkEvent]:
    """Generate events for a named simulation scenario."""
    gen = SyntheticTrafficGenerator()
    name = scenario_name.lower().replace("_", "-")

    if name in {"port-scan", "port_scan"}:
        return gen.generate_port_scan(ports=range(20, 20 + (25 * count_modifier)))

    elif name in {"syn-flood", "syn_anomaly", "syn-anomaly"}:
        return gen.generate_syn_flood(count=40 * count_modifier)

    elif name in {"ssh-bruteforce", "ssh_failures", "ssh-failures"}:
        return gen.generate_ssh_bruteforce(attempts=8 * count_modifier)

    elif name in {"dns-burst", "dns_anomaly", "dns-anomaly"}:
        return gen.generate_dns_burst(count=35 * count_modifier)

    elif name in {"arp-conflict", "arp_anomaly", "arp-anomaly"}:
        return gen.generate_arp_conflict()

    elif name in {"traffic-spike", "traffic_anomaly", "traffic-anomaly"}:
        return gen.generate_traffic_spike(count=150 * count_modifier)

    elif name in {"new-device", "new_device"}:
        return gen.generate_new_device()

    elif name in {"normal-traffic", "normal_traffic", "benign"}:
        events = []
        events.extend(gen.generate_normal_tcp(count=15))
        events.extend(gen.generate_normal_udp(count=8))
        return sorted(events, key=lambda e: e.timestamp)

    else:
        raise ValueError(
            f"Unknown scenario '{scenario_name}'. Valid options: "
            "port-scan, syn-flood, ssh-failures, dns-burst, arp-conflict, "
            "traffic-spike, new-device, normal-traffic"
        )
