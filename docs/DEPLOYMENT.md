# EdgeSentinel Raspberry Pi 3B+ Deployment Guide

> [!IMPORTANT]
> **Laptop-First Isolation Reminder**: Do not connect to or run commands on the Raspberry Pi during the development phase. This guide provides deployment artifacts and procedures prepared for execution once authorization is granted.

---

## 1. Target Hardware Specifications

- **Device**: Raspberry Pi 3B+
- **Architecture**: ARMv8 64-bit (ARM64 / aarch64)
- **RAM**: 1 GB LPDDR2 SDRAM (Shared with GPU)
- **Operating System**: Raspberry Pi OS Lite (64-bit Debian Bookworm)
- **Networking**: Gigabit Ethernet over USB 2.0 (`eth0`) / 802.11ac Wi-Fi (`wlan0`)
- **Storage**: MicroSD card (UHS-I)

---

## 2. Pre-Deployment Verification Checklist

Before deploying to the physical Pi:
- [ ] Confirm Raspberry Pi OS Lite is installed and bootable.
- [ ] Verify SSH access and key authentication from deployment workstation.
- [ ] Verify Tailscale connectivity if remote management is used.
- [ ] Confirm Python 3.10+ is available on target: `python3 --version`.
- [ ] Confirm `tcpdump` is installed: `which tcpdump`.
- [ ] Verify free disk space on root filesystem: `df -h /`.

---

## 3. Deployment Procedure

### Step 1: Transfer Code to Target
```bash
# From Windows workstation (once authorized)
scp -r edgesentinel/ pi@<PI_IP>:/tmp/edgesentinel_deploy/
```

### Step 2: Run Automated Installer
```bash
# On the Raspberry Pi
cd /tmp/edgesentinel_deploy
sudo bash scripts/install_linux.sh
```

The script will:
1. Install system prerequisites (`python3-venv`, `tcpdump`, `libcap2-bin`).
2. Grant network capture capabilities to `tcpdump`.
3. Create the unprivileged `edgesentinel` system user.
4. Set up `/opt/edgesentinel` virtual environment.
5. Deploy `/etc/edgesentinel/config.yaml` with production Linux paths.
6. Install and enable the `edgesentinel.service` systemd unit.

---

## 4. Post-Deployment Verification

```bash
# Check service status
sudo systemctl status edgesentinel

# View real-time logs
sudo journalctl -u edgesentinel -f

# Verify database creation
ls -lh /var/lib/edgesentinel/edgesentinel.db

# Test CLI from unprivileged shell
/opt/edgesentinel/.venv/bin/edgesentinel status --config /etc/edgesentinel/config.yaml
```

---

## 5. Rollback and Uninstallation

To completely remove the service:
```bash
sudo bash /opt/edgesentinel/scripts/uninstall_linux.sh
```
