# EdgeSentinel — Raspberry Pi 3B+ Deployment Runbook

> [!IMPORTANT]
> **Laptop-First Isolation Reminder**:
> During development, the Raspberry Pi remains powered off and uncontacted.
> This runbook is prepared for the operator to execute **once the physical Raspberry Pi is powered on and authorized for deployment**.

---

## 1. Target Hardware & Environment Profile

| Parameter | Specification | Notes |
| :--- | :--- | :--- |
| **Target Device** | Raspberry Pi 3B+ | Headless operational mode |
| **CPU Architecture** | ARMv8 (64-bit `aarch64` / `arm64`) | Compatible with standard Debian ARM64 |
| **System Memory** | 1.0 GB LPDDR2 SDRAM | Shared with GPU (allocate min 16MB to GPU) |
| **Operating System** | Raspberry Pi OS Lite (64-bit Bookworm) | No GUI / desktop packages |
| **Network Interfaces**| `eth0` (Primary wired) / `wlan0` (Wi-Fi) | 100/1000 Mbps Ethernet over USB 2.0 |
| **Remote Access** | SSH key-only, optional Tailscale mesh | Local dashboard bound to 127.0.0.1 |
| **Capture Backend** | `tcpdump` streaming via subprocess | Unprivileged with `CAP_NET_RAW` |

---

## 2. Pre-Flight Verification on Raspberry Pi

Once you power on the Raspberry Pi and connect via SSH, run this pre-flight verification block:

```bash
# Verify OS and Architecture
uname -m
# Expected: aarch64 (or armv7l on 32-bit OS)

# Check operating system release
cat /etc/os-release | grep -E "(PRETTY_NAME|VERSION_ID)"

# Verify available RAM and swap
free -h
# Expected: ~900MB total available memory, at least 100MB swap

# Verify root storage availability
df -h /
# Minimum requirement: >= 2.0 GB free disk space

# Check Python 3 availability
python3 --version
# Minimum requirement: Python 3.10+
```

---

## 3. Deployment Artifact Transfer

Deploy using the verified release archive `edgesentinel-0.1.0-rc1.tar.gz` and checksum file `SHA256SUMS.txt`.

### On the Development Laptop (Windows Terminal / PowerShell):
```powershell
# Set your target Pi hostname or IP
$PI_HOST = "pi@raspberrypi.local"   # or Tailscale IP

# Transfer release bundle to target temporary staging
scp dist/edgesentinel-0.1.0-rc1.tar.gz dist/SHA256SUMS.txt ${PI_HOST}:/tmp/
```

---

## 4. Installation Procedure on Raspberry Pi

### Step 1: Verify Checksum and Extract
```bash
cd /tmp

# Verify SHA256 integrity
sha256sum -c SHA256SUMS.txt --ignore-missing
# Expected output: edgesentinel-0.1.0-rc1.tar.gz: OK

# Unpack archive
tar -xzf edgesentinel-0.1.0-rc1.tar.gz
cd edgesentinel-0.1.0-rc1
```

### Step 2: Execute Automated Installer
```bash
sudo bash scripts/install_linux.sh
```

The script automatically executes the following actions:
1. Installs minimal system packages: `python3`, `python3-venv`, `python3-pip`, `tcpdump`, `libcap2-bin`.
2. Configures `setcap cap_net_raw,cap_net_admin=eip` on `/usr/bin/tcpdump`.
3. Creates the unprivileged system user and group `edgesentinel`.
4. Installs the application into `/opt/edgesentinel` and creates a dedicated virtual environment in `/opt/edgesentinel/.venv`.
5. Deploys production configuration to `/etc/edgesentinel/config.yaml` with data stored in `/var/lib/edgesentinel/edgesentinel.db`.
6. Sets strict file permissions (`chmod 750 /var/lib/edgesentinel`, `chmod 640 /etc/edgesentinel/config.yaml`).
7. Installs `/etc/systemd/system/edgesentinel.service` with strict resource quotas (`MemoryMax=350M`, `CPUQuota=60%`).
8. Enables and starts the service.

---

## 5. Post-Deployment Verification

Execute these verification commands on the Pi to validate health:

### 1. Check Service Status
```bash
sudo systemctl status edgesentinel.service
```
*Expected*: `Active: active (running)` with memory footprint under 80 MB.

### 2. Verify Live Journal Logs
```bash
sudo journalctl -u edgesentinel.service -n 50 --no-pager
```
*Expected*: Clean startup log indicating database initialized at `/var/lib/edgesentinel/edgesentinel.db` and dashboard listening on `http://127.0.0.1:8080`.

### 3. Test Local API
```bash
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool
```
*Expected*: JSON response returning platform info, metrics, and event stats.

### 4. Run CLI Health & Database Checks
```bash
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel status --config /etc/edgesentinel/config.yaml
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel db-check --config /etc/edgesentinel/config.yaml
```
*Expected*: `Integrity Check: ok`.

---

## 6. Accessing the Dashboard via Tailscale / Remote Port Forwarding

By default, EdgeSentinel binds strictly to `127.0.0.1` for defensive zero-exposure security.

### Option A: SSH Local Port Forwarding (Recommended for quick checks)
From your Windows laptop:
```powershell
ssh -L 8080:127.0.0.1:8080 pi@raspberrypi.local
```
Then open `http://127.0.0.1:8080` in your Windows browser.

### Option B: Tailscale Private Access
If Tailscale is installed on the Pi:
1. In `/etc/edgesentinel/config.yaml`, update `dashboard.host` to your Pi's Tailscale 100.x.y.z IP.
2. Restart the service:
```bash
sudo systemctl restart edgesentinel.service
```
3. Access `http://<tailscale-ip>:8080` securely from any authenticated device on your Tailscale tailnet.

---

## 7. Emergency Rollback and Uninstallation

If you ever need to remove EdgeSentinel cleanly:

```bash
sudo bash /opt/edgesentinel/scripts/uninstall_linux.sh
```

To purge all historic logs and database files as well:
```bash
sudo rm -rf /var/lib/edgesentinel /etc/edgesentinel /var/log/edgesentinel
sudo userdel edgesentinel || true
```
