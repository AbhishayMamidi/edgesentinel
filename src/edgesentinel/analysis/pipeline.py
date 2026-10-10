"""Common event-processing pipeline connecting adapters, flow tracking, inventory, and detectors."""

from __future__ import annotations

import logging
import queue
import time
from typing import List, Optional

from edgesentinel.alerts.manager import AlertManager
from edgesentinel.config import AppConfig
from edgesentinel.detection import (
    ArpAnomalyDetector,
    BaseDetector,
    DnsAnomalyDetector,
    NewDeviceDetector,
    PortScanDetector,
    SshBruteforceDetector,
    SynAnomalyDetector,
    TrafficAnomalyDetector,
)
from edgesentinel.flows.tracker import FlowTracker
from edgesentinel.inventory.devices import DeviceInventory
from edgesentinel.models import Alert, FlowRecord, NetworkEvent, SystemMetrics
from edgesentinel.monitoring.health import ResourceMonitor
from edgesentinel.storage.database import Database

logger = logging.getLogger("edgesentinel.pipeline")


class EventPipeline:
    """Shared pipeline receiving normalized events from simulation, replay, or live capture."""

    def __init__(self, config: AppConfig, db: Database):
        self.config = config
        self.db = db
        self.event_queue: queue.Queue[NetworkEvent] = queue.Queue(maxsize=config.monitoring.max_queue_size)

        # Components
        self.flow_tracker = FlowTracker(
            max_flows=config.monitoring.max_queue_size,
            idle_timeout=60.0
        )
        self.inventory = DeviceInventory(
            trusted_devices=config.inventory.trusted_devices
        )
        self.alert_manager = AlertManager(db=db, auto_flush=False)
        self.monitor = ResourceMonitor(data_dir=str(self.db.db_path.parent))

        # Detectors
        det_cfg = config.detection
        self.port_scan_detector = PortScanDetector(
            threshold_ports=det_cfg.port_scan.threshold_ports,
            window_seconds=det_cfg.port_scan.window_seconds,
            enabled=det_cfg.port_scan.enabled
        )
        self.syn_anomaly_detector = SynAnomalyDetector(
            threshold_syn_rate=det_cfg.syn_anomaly.threshold_syn_rate,
            window_seconds=det_cfg.syn_anomaly.window_seconds,
            enabled=det_cfg.syn_anomaly.enabled
        )
        self.ssh_bruteforce_detector = SshBruteforceDetector(
            threshold_attempts=det_cfg.ssh_bruteforce.threshold_attempts,
            window_seconds=det_cfg.ssh_bruteforce.window_seconds,
            enabled=det_cfg.ssh_bruteforce.enabled
        )
        self.dns_anomaly_detector = DnsAnomalyDetector(
            query_rate_threshold=det_cfg.dns_anomaly.query_rate_threshold,
            max_query_len=det_cfg.dns_anomaly.max_query_len,
            window_seconds=det_cfg.dns_anomaly.window_seconds,
            enabled=det_cfg.dns_anomaly.enabled
        )
        self.arp_anomaly_detector = ArpAnomalyDetector(
            window_seconds=det_cfg.arp_anomaly.window_seconds,
            enabled=det_cfg.arp_anomaly.enabled
        )
        self.traffic_anomaly_detector = TrafficAnomalyDetector(
            threshold_multiplier=det_cfg.traffic_anomaly.threshold_multiplier,
            window_seconds=det_cfg.traffic_anomaly.window_seconds,
            enabled=det_cfg.traffic_anomaly.enabled
        )
        self.new_device_detector = NewDeviceDetector(
            enabled=det_cfg.new_device.enabled
        )

        self.detectors: List[BaseDetector] = [
            self.port_scan_detector,
            self.syn_anomaly_detector,
            self.ssh_bruteforce_detector,
            self.dns_anomaly_detector,
            self.arp_anomaly_detector,
            self.traffic_anomaly_detector,
        ]

        # Batch write staging
        self._pending_events: List[NetworkEvent] = []
        self._pending_flows: dict[str, FlowRecord] = {}
        self._pending_devices: dict[str, Device] = {}
        self._last_flush_time = time.time()
        self.total_processed = 0
        self.total_alerts = 0

    def ingest_event(self, event: NetworkEvent) -> Optional[Alert]:
        """Process a single event through all pipeline stages synchronously."""
        self.total_processed += 1

        # 1. Update flow tracker
        flow = self.flow_tracker.process_event(event)
        if flow:
            self._pending_flows[flow.flow_id] = flow

        # 2. Update device inventory
        device, is_new = self.inventory.observe_event(event)
        if device:
            self._pending_devices[device.ip] = device
            if is_new:
                new_dev_alert = self.new_device_detector.process_new_device(
                    device, is_synthetic=event.is_synthetic
                )
                if new_dev_alert and self.alert_manager.dispatch(new_dev_alert):
                    self.total_alerts += 1

        # 3. Run rule-based detectors
        triggered_alert: Optional[Alert] = None
        for detector in self.detectors:
            alert = detector.process_event(event)
            if alert:
                if self.alert_manager.dispatch(alert):
                    self.total_alerts += 1
                    triggered_alert = alert

        # 4. Stage event for database persistence
        self._pending_events.append(event)

        # 5. Flush if batch limit reached or time elapsed
        now = time.time()
        if (
            len(self._pending_events) >= self.config.storage.batch_size
            or (now - self._last_flush_time) >= self.config.storage.flush_interval_seconds
        ):
            self.flush()

        return triggered_alert

    def ingest_events(self, events: List[NetworkEvent]) -> List[Alert]:
        """Batch ingestion for simulations and PCAP replay."""
        alerts: List[Alert] = []
        for e in events:
            a = self.ingest_event(e)
            if a:
                alerts.append(a)
        self.flush()
        return alerts

    def flush(self) -> None:
        """Commit staged events, flows, and devices to database."""
        if self._pending_events:
            self.db.insert_events_batch(self._pending_events)
            self._pending_events.clear()

        # Check for expired flows
        expired = self.flow_tracker.expire_stale_flows()
        for f in expired:
            self._pending_flows[f.flow_id] = f

        if self._pending_flows:
            self.db.upsert_flows_batch(list(self._pending_flows.values()))
            self._pending_flows.clear()

        if self._pending_devices:
            self.db.upsert_devices_batch(list(self._pending_devices.values()))
            self._pending_devices.clear()

        self.alert_manager.flush()
        self._last_flush_time = time.time()

    def get_metrics(self) -> SystemMetrics:
        """Fetch current pipeline and system resource metrics."""
        return self.monitor.get_metrics(
            queue_size=self.event_queue.qsize(),
            events_processed=self.total_processed,
            alerts_generated=self.total_alerts,
            active_flows=self.flow_tracker.get_active_count(),
            active_devices=len(self.inventory.get_devices())
        )
