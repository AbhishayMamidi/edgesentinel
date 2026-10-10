#!/usr/bin/env bash
# EdgeSentinel - Linux / Raspberry Pi 3B+ Automated Installation Script
# TARGET: Raspberry Pi OS Lite (Debian / ARM64)
# NOTE: Do NOT execute on Windows development machines.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This installation script must be run as root (e.g. sudo bash install_linux.sh)." >&2
   exit 1
fi

echo "=========================================================="
echo " EdgeSentinel - Deployment Setup for Raspberry Pi 3B+"
echo "=========================================================="

APP_USER="edgesentinel"
INSTALL_DIR="/opt/edgesentinel"
CONFIG_DIR="/etc/edgesentinel"
DATA_DIR="/var/lib/edgesentinel"
LOG_DIR="/var/log/edgesentinel"

# 1. Install system prerequisites
echo "[1/7] Installing system packages (python3, venv, tcpdump)..."
apt-get update -y
apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    tcpdump \
    libcap2-bin

# 2. Grant tcpdump capture permissions to unprivileged processes
echo "[2/7] Configuring network capture capabilities..."
setcap cap_net_raw,cap_net_admin=eip $(which tcpdump) || true

# 3. Create dedicated system user
echo "[3/7] Creating service user '${APP_USER}'..."
if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    useradd -r -s /bin/false -d "${INSTALL_DIR}" -M "${APP_USER}"
fi

# 4. Prepare directory layout
echo "[4/7] Setting up application directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"

# Copy source repository to /opt/edgesentinel
cp -r . "${INSTALL_DIR}/"

# 5. Create Python Virtual Environment
echo "[5/7] Creating Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install -e "${INSTALL_DIR}"

# 6. Install configuration
echo "[6/7] Deploying production configuration..."
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    cp "${INSTALL_DIR}/config.example.yaml" "${CONFIG_DIR}/config.yaml"
    # Adjust paths for Linux standard hierarchy
    sed -i "s|data/edgesentinel.db|${DATA_DIR}/edgesentinel.db|g" "${CONFIG_DIR}/config.yaml"
    sed -i "s|backend: \"simulation\"|backend: \"linux\"|g" "${CONFIG_DIR}/config.yaml"
fi

# Permissions
chown -R "${APP_USER}:${APP_USER}" "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 750 "${CONFIG_DIR}" "${DATA_DIR}"

# 7. Install and start systemd service
echo "[7/7] Registering systemd service..."
cp "${INSTALL_DIR}/deploy/edgesentinel.service" /etc/systemd/system/edgesentinel.service
systemctl daemon-reload
systemctl enable edgesentinel.service
systemctl restart edgesentinel.service

echo ""
echo "[OK] EdgeSentinel successfully installed and started."
echo "     Dashboard available locally at: http://127.0.0.1:8080"
echo "     Check service status: systemctl status edgesentinel"
echo "     View live logs: journalctl -u edgesentinel -f"
