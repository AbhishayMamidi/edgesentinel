"""Resource and health monitoring for EdgeSentinel."""

from __future__ import annotations

import os
import shutil
import time
from typing import Optional
import psutil

from edgesentinel.models import SystemMetrics


class ResourceMonitor:
    """Monitors CPU, memory, and disk resources with awareness of low-memory targets."""

    def __init__(self, data_dir: str = "data"):
        self.process = psutil.Process(os.getpid())
        self.data_dir = data_dir
        # Prime CPU percent reading
        self.process.cpu_percent()
        psutil.cpu_percent()

    def get_metrics(
        self,
        queue_size: int = 0,
        events_processed: int = 0,
        alerts_generated: int = 0,
        active_flows: int = 0,
        active_devices: int = 0
    ) -> SystemMetrics:
        """Collect current system and process resource metrics."""
        # Process specific memory
        mem_info = self.process.memory_info()
        rss_mb = round(mem_info.rss / (1024 * 1024), 2)

        # Host system metrics
        sys_mem = psutil.virtual_memory()
        cpu_pct = psutil.cpu_percent(interval=None)

        # Disk usage for data storage
        try:
            disk_info = shutil.disk_usage(self.data_dir)
            disk_pct = round((disk_info.used / disk_info.total) * 100, 1)
            disk_free_gb = round(disk_info.free / (1024 * 1024 * 1024), 2)
        except Exception:
            disk_pct = 0.0
            disk_free_gb = 0.0

        return SystemMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_pct,
            memory_percent=sys_mem.percent,
            memory_used_mb=rss_mb,
            disk_percent=disk_pct,
            disk_free_gb=disk_free_gb,
            queue_size=queue_size,
            events_processed=events_processed,
            alerts_generated=alerts_generated,
            active_flows=active_flows,
            active_devices=active_devices
        )

    def is_memory_critical(self, threshold_mb: float = 350.0) -> bool:
        """Check if process memory consumption crosses safe threshold for 1GB Pi target."""
        mem_info = self.process.memory_info()
        rss_mb = mem_info.rss / (1024 * 1024)
        return rss_mb > threshold_mb
