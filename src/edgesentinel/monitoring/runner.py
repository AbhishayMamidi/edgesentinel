"""Monitoring runner coordinating live capture adapters, pipelines, and persistence."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from edgesentinel.analysis.pipeline import EventPipeline
from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.capture.linux import LinuxTcpdumpAdapter
from edgesentinel.capture.simulation import SimulationCaptureAdapter
from edgesentinel.capture.windows import WindowsCaptureAdapter
from edgesentinel.config import AppConfig, load_config
from edgesentinel.storage.database import Database

logger = logging.getLogger("edgesentinel.monitoring.runner")


class MonitorRunner:
    """Manages the lifecycle of packet capture, pipeline ingestion, and periodic persistence."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        db: Optional[Database] = None,
        pipeline: Optional[EventPipeline] = None
    ):
        self.config = config or load_config()
        self.db = db or Database(self.config.storage.database_path)
        self.pipeline = pipeline or EventPipeline(config=self.config, db=self.db)

        self.adapter: Optional[BaseCaptureAdapter] = None
        self.is_running = False
        self.last_error: Optional[str] = None
        self.start_time: Optional[float] = None

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._pid_file: Optional[Path] = None

    def _get_pid_file_path(self) -> Path:
        db_dir = Path(self.config.storage.database_path).resolve().parent
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / "monitor.pid"

    def is_external_monitor_running(self) -> Optional[int]:
        """Check if another process holds the monitor lock."""
        pid_file = self._get_pid_file_path()
        if not pid_file.exists():
            return None

        try:
            content = pid_file.read_text(encoding="utf-8").strip()
            pid = int(content)
            if pid == os.getpid():
                return None  # Own lock

            # Check if pid is active
            if os.name == "nt":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                SYNCHRONIZE = 0x00100000
                process = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
                if process:
                    kernel32.CloseHandle(process)
                    return pid
            else:
                try:
                    os.kill(pid, 0)
                    return pid
                except (OSError, ProcessLookupError):
                    pass
        except Exception:
            pass

        # Stale PID file
        try:
            pid_file.unlink(missing_ok=True)
        except Exception:
            pass
        return None

    def _acquire_pid_lock(self) -> bool:
        other_pid = self.is_external_monitor_running()
        if other_pid:
            self.last_error = f"Another EdgeSentinel monitor process is already active (PID {other_pid})"
            logger.warning(self.last_error)
            return False

        try:
            pid_file = self._get_pid_file_path()
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            self._pid_file = pid_file
            return True
        except Exception as e:
            self.last_error = f"Failed to acquire monitor PID lock: {e}"
            logger.error(self.last_error)
            return False

    def _release_pid_lock(self) -> None:
        if self._pid_file and self._pid_file.exists():
            try:
                self._pid_file.unlink(missing_ok=True)
            except Exception:
                pass
            self._pid_file = None

    def _create_adapter(self) -> BaseCaptureAdapter:
        backend = (self.config.capture.backend or "simulation").lower()

        if backend == "linux":
            return LinuxTcpdumpAdapter(
                interface=self.config.capture.interface or "eth0",
                bpf_filter=self.config.capture.bpf_filter,
                snaplen=getattr(self.config.capture, "snaplen", 128),
                promiscuous=getattr(self.config.capture, "promiscuous", False),
                mode=getattr(self.config.capture, "mode", "pcap")
            )
        elif backend == "windows":
            return WindowsCaptureAdapter(
                interface=self.config.capture.interface,
                bpf_filter=self.config.capture.bpf_filter
            )
        elif backend == "simulation":
            return SimulationCaptureAdapter(
                interface=self.config.capture.interface or "sim0",
                bpf_filter=self.config.capture.bpf_filter
            )
        else:
            raise ValueError(f"Unsupported capture backend: {backend}")

    def start(self, background: bool = False) -> bool:
        """Start the monitoring capture and processing loop."""
        if self.is_running:
            logger.info("Monitor is already running.")
            return True

        if not self._acquire_pid_lock():
            return False

        try:
            self.adapter = self._create_adapter()
        except Exception as e:
            self.last_error = f"Failed to initialize capture adapter: {e}"
            logger.error(self.last_error)
            self._release_pid_lock()
            return False

        if not self.adapter.start():
            self.last_error = self.adapter.last_error or "Failed to start capture adapter"
            logger.error(self.last_error)
            self._release_pid_lock()
            return False

        self.is_running = True
        self.last_error = None
        self.start_time = time.time()
        self._stop_event.clear()

        logger.info(
            "Monitoring engine active. Backend: '%s', Interface: '%s'",
            self.config.capture.backend, getattr(self.adapter, "interface", "unknown")
        )

        if background:
            self._worker_thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="EdgeSentinel-CaptureWorker"
            )
            self._worker_thread.start()
            return True
        else:
            self._install_signals()
            self._run_loop()
            return True

    def _install_signals(self) -> None:
        def _sig_handler(signum, frame):
            logger.info("Received termination signal %s. Stopping monitor...", signum)
            self.stop()
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, _sig_handler)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, _sig_handler)
        except Exception:
            pass

    def _run_loop(self) -> None:
        """Core streaming loop feeding captured packets into pipeline."""
        if not self.adapter:
            return

        try:
            for event in self.adapter.stream_events():
                if self._stop_event.is_set():
                    break
                self.pipeline.ingest_event(event)
        except Exception as e:
            if not self._stop_event.is_set():
                self.last_error = f"Capture loop encountered exception: {e}"
                logger.error(self.last_error)
        finally:
            try:
                self.pipeline.flush()
            except Exception:
                pass
            self.stop()

    def stop(self) -> None:
        """Stop packet capture, flush pipeline, and release locks."""
        if not self.is_running and not self.adapter:
            return

        self._stop_event.set()
        self.is_running = False

        if self.adapter:
            try:
                self.adapter.stop()
            except Exception:
                pass

        if (
            self._worker_thread
            and self._worker_thread.is_alive()
            and threading.current_thread() != self._worker_thread
        ):
            try:
                self._worker_thread.join(timeout=3.0)
            except Exception:
                pass

        try:
            self.pipeline.flush()
        except Exception:
            pass

        self._release_pid_lock()
        logger.info("Monitoring engine stopped cleanly.")

    def get_status(self) -> Dict[str, Any]:
        """Provide detailed status diagnostics of the capture and pipeline engine."""
        adapter_stats = self.adapter.get_stats() if self.adapter else {}
        other_pid = self.is_external_monitor_running()

        if self.is_running:
            state = "active"
        elif other_pid:
            state = "external_active"
        elif self.last_error or (self.adapter and self.adapter.last_error):
            state = "error"
        else:
            state = "stopped"

        effective_err = self.last_error or (self.adapter.last_error if self.adapter else None)

        return {
            "status": state,
            "is_running": self.is_running or (other_pid is not None),
            "backend": self.config.capture.backend,
            "interface": getattr(self.adapter, "interface", self.config.capture.interface),
            "pid": getattr(self.adapter, "pid", None) or other_pid,
            "packets_captured": adapter_stats.get("captured", 0),
            "packets_dropped": adapter_stats.get("dropped", 0),
            "events_processed": self.pipeline.total_processed,
            "alerts_generated": self.pipeline.total_alerts,
            "error": effective_err,
            "uptime_seconds": round(time.time() - self.start_time, 1) if self.start_time and self.is_running else 0
        }
