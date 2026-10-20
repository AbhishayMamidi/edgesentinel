# EdgeSentinel — Raspberry Pi 3B+ Deployment Runbook & Verification

## 1. Verified Hardware & Deployment Profile

| Parameter | Specification | Current Verified Deployment Value |
| :--- | :--- | :--- |
| **Target Device** | Raspberry Pi 3B+ | Headless operational mode |
| **CPU Architecture** | ARMv8 (64-bit `aarch64`) | `Linux 6.18.50+rpt-rpi-v8 #1 SMP PREEMPT Debian 1:6.18.50-1+rpt1` |
| **System Memory** | 1.0 GB LPDDR2 SDRAM | 905 MiB total, ~665 MiB free/available |
| **Operating System** | Debian 13 (Trixie / Bookworm-compatible) | Clean standard minimal install |
| **Network Interface**| Wi-Fi `wlan0` | Active IP: **`192.168.88.11`** (MAC: `B8:27:EB:BA:4D:22`) |
| **Historical IP Note**| DHCP lease history | `192.168.88.10` resolved as earlier lease for identical MAC |
| **Remote Access** | SSH key authentication | User `abhi@192.168.88.11` |
| **Capture Backend** | `tcpdump` streaming via subprocess | `tcpdump -U -w - -i wlan0 -s 128 -p` (unprivileged with `CAP_NET_RAW`) |
| **Service Status** | systemd daemon | `active (running)`, boot-enabled (`multi-user.target.wants`) |
| **Dashboard Bind** | Localhost only | Strictly bound to `127.0.0.1:8080` (CORS restricted) |

---

## 2. Directory Layout & File Permissions

```
/opt/edgesentinel/                 drwxr-xr-x  edgesentinel:edgesentinel
├── .venv/                         drwxr-xr-x  edgesentinel:edgesentinel  (Python 3.13 venv)
├── deploy/edgesentinel.service    -rw-r--r--  edgesentinel:edgesentinel
└── src/edgesentinel/              drwxr-xr-x  edgesentinel:edgesentinel

/etc/edgesentinel/                 drwxr-x---  edgesentinel:edgesentinel  (chmod 0750)
└── config.yaml                    -rw-r-----  edgesentinel:edgesentinel  (chmod 0640)

/var/lib/edgesentinel/             drwxr-x---  edgesentinel:edgesentinel  (chmod 0750)
├── edgesentinel.db                -rw-r-----  edgesentinel:edgesentinel  (chmod 0640)
├── monitor.pid                    -rw-r--r--  edgesentinel:edgesentinel
└── backups/                       drwxr-x---  edgesentinel:edgesentinel  (chmod 0750)
    └── edgesentinel_*.db          -rw-r-----  edgesentinel:edgesentinel  (chmod 0640)

/etc/systemd/system/
└── edgesentinel.service           -rw-r--r--  root:root                  (chmod 0644)
```

---

## 3. Verified Systemd Service Configuration

File: `/etc/systemd/system/edgesentinel.service`
```ini
[Unit]
Description=EdgeSentinel - Local-First Network Security Monitoring & IDS
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=edgesentinel
Group=edgesentinel
WorkingDirectory=/opt/edgesentinel
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=/opt/edgesentinel/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=/opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml dashboard --port 8080 --host 127.0.0.1

Restart=always
RestartSec=5s

# 1GB RAM Target Budget Protections (Raspberry Pi 3B+)
MemoryHigh=300M
MemoryMax=350M
CPUQuota=60%

# Security Hardening & Principle of Least Privilege
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

---

## 4. Operational Health & Status Verification

### 1. Verify Service State
```bash
sudo systemctl status edgesentinel.service --no-pager
# Output: Active: active (running)
# Output: Loaded: ... (enabled; preset: enabled)
```

### 2. Verify Live Capture Subprocess
```bash
ps aux | grep -E "(edgesentinel|tcpdump)" | grep -v grep
# Expected: Main python process (PID ~2701) and tcpdump child process (PID ~2703)
```

### 3. Verify SQLite Integrity and Event Ingestion
```bash
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check
# Expected output:
# === SQLite Database Check ===
# Integrity Check: ok
# Database File  : /var/lib/edgesentinel/edgesentinel.db
# File Size      : ~17 MB
# Events Stored  : >50,000
```

### 4. Query Real-Time Diagnostics API
```bash
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool
```

---

## 5. Dashboard Remote Access from Windows 11

Because EdgeSentinel binds exclusively to loopback `127.0.0.1` for defensive zero-exposure security, remote access is achieved via encrypted SSH local port forwarding.

### Step 1: Open Persistent SSH Tunnel
In a Windows PowerShell window:
```powershell
ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
```

### Step 2: Access Dashboard in Browser
Open: [http://127.0.0.1:8080](http://127.0.0.1:8080)

### Step 3: Available REST Endpoints
- Dashboard UI: `GET http://127.0.0.1:8080/`
- Platform & System Health: `GET http://127.0.0.1:8080/api/status`
- Persisted Security Alerts: `GET http://127.0.0.1:8080/api/alerts?limit=50`
- Network Device Inventory: `GET http://127.0.0.1:8080/api/devices`
- Live Traffic Events: `GET http://127.0.0.1:8080/api/events?limit=50`
