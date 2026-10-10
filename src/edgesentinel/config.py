"""Configuration management and validation for EdgeSentinel."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator


class StorageConfig(BaseModel):
    database_path: str = "data/edgesentinel.db"
    busy_timeout_ms: int = 5000
    retention_days: int = 7
    batch_size: int = 100
    flush_interval_seconds: float = 1.0

    @field_validator("retention_days", "batch_size")
    @classmethod
    def validate_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Value must be positive")
        return v


class CaptureConfig(BaseModel):
    backend: str = "simulation"  # simulation, pcap, windows, linux
    interface: str = ""
    bpf_filter: str = ""
    promiscuous: bool = False

    @field_validator("backend")
    @classmethod
    def validate_backend(cls, v: str) -> str:
        valid = {"simulation", "pcap", "windows", "linux"}
        if v not in valid:
            raise ValueError(f"Invalid backend: {v}. Must be one of {valid}")
        return v


class MonitoringConfig(BaseModel):
    interval_seconds: float = 2.0
    max_queue_size: int = 5000

    @field_validator("max_queue_size")
    @classmethod
    def validate_queue_size(cls, v: int) -> int:
        if v < 100:
            raise ValueError("Queue size cannot be smaller than 100")
        return v


class DashboardConfig(BaseModel):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8080

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v


class PortScanConfig(BaseModel):
    enabled: bool = True
    threshold_ports: int = 15
    window_seconds: float = 10.0


class SynAnomalyConfig(BaseModel):
    enabled: bool = True
    threshold_syn_rate: float = 25.0
    window_seconds: float = 5.0


class SshBruteforceConfig(BaseModel):
    enabled: bool = True
    threshold_attempts: int = 5
    window_seconds: float = 60.0


class DnsAnomalyConfig(BaseModel):
    enabled: bool = True
    query_rate_threshold: float = 20.0
    max_query_len: int = 60
    window_seconds: float = 10.0


class ArpAnomalyConfig(BaseModel):
    enabled: bool = True
    window_seconds: float = 30.0


class TrafficAnomalyConfig(BaseModel):
    enabled: bool = True
    threshold_multiplier: float = 3.0
    window_seconds: float = 15.0


class NewDeviceConfig(BaseModel):
    enabled: bool = True


class DetectionConfig(BaseModel):
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    syn_anomaly: SynAnomalyConfig = Field(default_factory=SynAnomalyConfig)
    ssh_bruteforce: SshBruteforceConfig = Field(default_factory=SshBruteforceConfig)
    dns_anomaly: DnsAnomalyConfig = Field(default_factory=DnsAnomalyConfig)
    arp_anomaly: ArpAnomalyConfig = Field(default_factory=ArpAnomalyConfig)
    traffic_anomaly: TrafficAnomalyConfig = Field(default_factory=TrafficAnomalyConfig)
    new_device: NewDeviceConfig = Field(default_factory=NewDeviceConfig)


class InventoryConfig(BaseModel):
    trusted_devices: List[str] = Field(default_factory=lambda: ["127.0.0.1", "192.168.1.1"])


class ResponseConfig(BaseModel):
    mode: str = "dry_run"  # passive, dry_run

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in {"passive", "dry_run"}:
            raise ValueError(f"Invalid response mode: {v}. Only 'passive' and 'dry_run' allowed.")
        return v


class AppConfig(BaseModel):
    environment: str = "development"
    storage: StorageConfig = Field(default_factory=StorageConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    inventory: InventoryConfig = Field(default_factory=InventoryConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load and validate configuration from YAML file or return defaults."""
    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    else:
        # Search relative to current working directory or package
        candidates.extend([
            Path("config.yaml"),
            Path("config.yml"),
            Path("config.example.yaml"),
            Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
        ])

    for p in candidates:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return AppConfig(**data)
            except Exception as e:
                raise ValueError(f"Error parsing configuration file {p}: {e}") from e

    # Fallback to defaults
    return AppConfig()
