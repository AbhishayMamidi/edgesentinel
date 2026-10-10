"""Data models and schemas for EdgeSentinel."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class NetworkEvent(BaseModel):
    """Normalized network event schema."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "TCP"  # TCP, UDP, ICMP, ARP, DNS
    tcp_flags: Optional[str] = None  # e.g. "SYN", "ACK", "SYN-ACK", "FIN", "RST"
    packet_len: int = 0
    interface: Optional[str] = None
    capture_source: str = "simulation"  # simulation, pcap, live_windows, live_linux
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    arp_op: Optional[str] = None  # REQUEST, REPLY
    arp_sha: Optional[str] = None
    arp_spa: Optional[str] = None
    arp_tha: Optional[str] = None
    arp_tpa: Optional[str] = None
    is_synthetic: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """Normalized alert schema."""
    id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: float = Field(default_factory=time.time)
    detector_id: str
    severity: Severity = Severity.MEDIUM
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    threshold_details: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0
    recommendations: List[str] = Field(default_factory=list)
    is_synthetic: bool = True
    status: AlertStatus = AlertStatus.NEW


class Device(BaseModel):
    """Observed device in inventory."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    observation_source: str = "simulation"
    is_trusted: bool = False
    packet_count: int = 1


class FlowRecord(BaseModel):
    """Tracked network flow statistics."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 1
    byte_count: int = 0
    tcp_flags_seen: List[str] = Field(default_factory=list)
    state: str = "ACTIVE"


class SystemMetrics(BaseModel):
    """System and engine health metrics."""
    timestamp: float = Field(default_factory=time.time)
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    disk_percent: float = 0.0
    disk_free_gb: float = 0.0
    queue_size: int = 0
    events_processed: int = 0
    alerts_generated: int = 0
    active_flows: int = 0
    active_devices: int = 0
