"""Bounded, stateful network flow tracker with idle expiration."""

from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional, Tuple

from edgesentinel.models import FlowRecord, NetworkEvent


class FlowTracker:
    """Tracks active connections using bounded memory suitable for 1GB RAM targets."""

    def __init__(self, max_flows: int = 5000, idle_timeout: float = 60.0):
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self._flows: Dict[str, FlowRecord] = {}

    def _canonical_flow_id(self, event: NetworkEvent) -> str:
        """Create a deterministic flow ID regardless of packet direction."""
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0
        (ip1, p1), (ip2, p2) = sorted([(event.src_ip, src_port), (event.dst_ip, dst_port)])
        raw = f"{ip1}:{p1}-{ip2}:{p2}-{event.protocol.upper()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def process_event(self, event: NetworkEvent) -> Optional[FlowRecord]:
        """Update active flow table with incoming event."""
        # Only track IP-based flows
        if not event.src_ip or not event.dst_ip:
            return None

        flow_id = self._canonical_flow_id(event)
        now = event.timestamp or time.time()

        if flow_id in self._flows:
            flow = self._flows[flow_id]
            flow.last_seen = now
            flow.packet_count += 1
            flow.byte_count += event.packet_len
            if event.tcp_flags and event.tcp_flags not in flow.tcp_flags_seen:
                flow.tcp_flags_seen.append(event.tcp_flags)
            if "FIN" in (event.tcp_flags or "") or "RST" in (event.tcp_flags or ""):
                flow.state = "CLOSED"
            return flow
        else:
            # Enforce bounded capacity
            if len(self._flows) >= self.max_flows:
                self.expire_stale_flows(force_cleanup=True)

            flow = FlowRecord(
                flow_id=flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                src_port=event.src_port or 0,
                dst_port=event.dst_port or 0,
                protocol=event.protocol,
                start_time=now,
                last_seen=now,
                packet_count=1,
                byte_count=event.packet_len,
                tcp_flags_seen=[event.tcp_flags] if event.tcp_flags else [],
                state="ACTIVE"
            )
            self._flows[flow_id] = flow
            return flow

    def expire_stale_flows(self, current_time: Optional[float] = None, force_cleanup: bool = False) -> List[FlowRecord]:
        """Expire flows that exceeded idle timeout or drop oldest if capacity reached."""
        now = current_time or time.time()
        expired: List[FlowRecord] = []

        to_remove = []
        for fid, f in self._flows.items():
            if (now - f.last_seen) > self.idle_timeout or f.state == "CLOSED":
                f.state = "EXPIRED" if f.state != "CLOSED" else "CLOSED"
                expired.append(f)
                to_remove.append(fid)

        for fid in to_remove:
            del self._flows[fid]

        # If forced cleanup due to max_flows and nothing expired yet, evict oldest 10%
        if force_cleanup and len(self._flows) >= self.max_flows:
            sorted_flows = sorted(self._flows.values(), key=lambda x: x.last_seen)
            evict_count = max(1, int(self.max_flows * 0.1))
            for f in sorted_flows[:evict_count]:
                f.state = "EVICTED"
                expired.append(f)
                if f.flow_id in self._flows:
                    del self._flows[f.flow_id]

        return expired

    def get_active_count(self) -> int:
        return len(self._flows)

    def get_active_flows(self) -> List[FlowRecord]:
        return list(self._flows.values())
