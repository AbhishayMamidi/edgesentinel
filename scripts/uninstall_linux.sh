#!/usr/bin/env bash
# EdgeSentinel - Clean Uninstallation Script for Linux
# NOTE: Do NOT execute on Windows development machines.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This uninstallation script must be run as root." >&2
   exit 1
fi

echo "Stopping and disabling edgesentinel service..."
systemctl stop edgesentinel.service || true
systemctl disable edgesentinel.service || true
rm -f /etc/systemd/system/edgesentinel.service
systemctl daemon-reload

echo "Removing application binaries and files..."
rm -rf /opt/edgesentinel

echo ""
echo "[OK] EdgeSentinel removed."
echo "     Note: Data directory /var/lib/edgesentinel and configs in /etc/edgesentinel"
echo "     were preserved. Delete them manually if full purge is desired:"
echo "     sudo rm -rf /var/lib/edgesentinel /etc/edgesentinel"
