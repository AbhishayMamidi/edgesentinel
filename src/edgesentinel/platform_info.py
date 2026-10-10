"""Platform detection and environment diagnostics for EdgeSentinel."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any, Dict
import psutil


def get_platform_info() -> Dict[str, Any]:
    """Inspect local operating system, architecture, permissions, and capture tools."""
    system = platform.system()
    machine = platform.machine()
    is_windows = system == "Windows"
    is_linux = system == "Linux"
    is_arm = "arm" in machine.lower() or "aarch64" in machine.lower()

    # Admin / root check
    is_admin = False
    try:
        if is_windows:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            is_admin = os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        is_admin = False

    # Check for tcpdump
    has_tcpdump = shutil.which("tcpdump") is not None

    # Check for Windows capture drivers (Npcap / WinPcap)
    has_npcap = False
    if is_windows:
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        npcap_paths = [
            os.path.join(sys_root, "System32", "Npcap", "wpcap.dll"),
            os.path.join(sys_root, "System32", "wpcap.dll"),
        ]
        has_npcap = any(os.path.exists(p) for p in npcap_paths)

    mem = psutil.virtual_memory()

    return {
        "os": system,
        "os_version": platform.version(),
        "release": platform.release(),
        "architecture": machine,
        "python_version": sys.version.split()[0],
        "is_windows": is_windows,
        "is_linux": is_linux,
        "is_arm": is_arm,
        "is_admin": is_admin,
        "has_tcpdump": has_tcpdump,
        "has_npcap": has_npcap,
        "total_ram_mb": round(mem.total / (1024 * 1024), 1),
        "available_ram_mb": round(mem.available / (1024 * 1024), 1),
        "cpu_count": psutil.cpu_count(logical=True),
        "recommended_capture_backend": (
            "linux" if is_linux and has_tcpdump else ("windows" if is_windows and has_npcap else "simulation")
        ),
    }
