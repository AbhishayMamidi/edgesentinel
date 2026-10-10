"""Strictly passive and dry-run defensive response manager with management IP allowlisting."""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Set

from edgesentinel.models import Alert

logger = logging.getLogger("edgesentinel.response")


class DefensiveResponseManager:
    """Provides preview-only, audit-logged firewall mitigation rules.
    
    CRITICAL: In compliance with project guidelines, this module operates strictly
    in passive/dry-run mode and NEVER executes firewall commands directly.
    """

    def __init__(self, mode: str = "dry_run", management_ips: Optional[List[str]] = None):
        self.mode = mode
        # Strict allowlist protection to prevent administrator lockout
        self.allowlist: Set[str] = {
            "127.0.0.1", "::1", "localhost", "0.0.0.0"
        }
        if management_ips:
            self.allowlist.update(management_ips)

        self._audit_log: List[Dict[str, str]] = []

    def evaluate_mitigation(self, alert: Alert) -> Optional[Dict[str, str]]:
        """Generate dry-run mitigation commands for a confirmed high/critical alert."""
        target_ip = alert.src_ip
        if not target_ip:
            return None

        # Absolute safeguard: Never generate blocking rules against management addresses
        if target_ip in self.allowlist:
            logger.info("Mitigation skipped: IP %s is protected by allowlist.", target_ip)
            return None

        # Build preview commands for common firewall backends
        iptables_cmd = f"sudo iptables -I INPUT -s {target_ip} -j DROP -m comment --comment 'EdgeSentinel {alert.id}'"
        nftables_cmd = f"sudo nft add element inet filter blacklist {{ {target_ip} }}"
        netsh_cmd = f"netsh advfirewall firewall add rule name=\"EdgeSentinel Block {target_ip}\" dir=in action=block remoteip={target_ip}"

        proposal = {
            "alert_id": alert.id,
            "target_ip": target_ip,
            "detector_id": alert.detector_id,
            "severity": alert.severity.value,
            "mode": self.mode,
            "timestamp": str(time.time()),
            "iptables_preview": iptables_cmd,
            "nftables_preview": nftables_cmd,
            "netsh_preview": netsh_cmd,
            "action": "DRY_RUN_PREVIEW_ONLY"
        }

        self._audit_log.append(proposal)
        logger.info(
            "[DRY-RUN MITIGATION PREVIEW] IP: %s | Rule: %s",
            target_ip, iptables_cmd
        )
        return proposal

    def get_audit_log(self) -> List[Dict[str, str]]:
        return list(self._audit_log)
