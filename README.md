# EdgeSentinel

**EdgeSentinel** is a lightweight, local-first network security monitoring (NSM) and intrusion detection platform (IDS) engineered for a **laptop-first development lifecycle on Windows 11** with verified production deployment to an unprivileged **Raspberry Pi 3B+ (1 GB RAM)**.

---

## Key Features

- **Laptop-First Isolation**: Fully functional on Windows 11 without requiring external hardware or kernel capture drivers.
- **Rule-Based Detection Engine**:
  - `DET-PORT-SCAN`: Port scan detection across distinct destination ports with deduplication.
  - `DET-SYN-FLOOD`: TCP SYN rate burst / half-open flood indicators with baseline duration calibration.
  - `DET-SSH-BRUTE`: Repeated connection attempts and authentication failure indicators against SSH (port 22).
  - `DET-DNS-ANOMALY`: DNS query rate spikes and abnormally long domain names (DNS tunneling / exfiltration detection).
  - `DET-ARP-SPOOF`: Conflicting IP-to-MAC mapping detection (ARP poisoning/spoofing).
  - `DET-TRAFFIC-SPIKE`: Rolling statistical traffic surge detection.
  - `DET-NEW-DEVICE`: Detection and asset tracking of newly discovered devices.
- **Pure-Python Streaming PCAP Reader**: Dissects offline `.pcap` files without C dependencies or libpcap.
- **Deterministic Synthetic Traffic Generator**: Evaluates detectors and false positive rates safely on Windows.
- **Bounded Resource Architecture**: Enforces flow table and queue caps designed strictly for 1GB RAM hardware targets (<60MB observed footprint).
- **Local Web Dashboard & CLI**: Real-time alerts, device inventory, system metrics, and simulation controls.
- **Passive Defensive Posture**: Non-destructive, dry-run response mode (`dry_run`) with strict allowlist protection.

---

## Quick Start on Windows 11

### 1. Requirements
- Python 3.10+ (tested on Python 3.12, 3.13 & 3.14)
- Git

### 2. Setup
```powershell
# Navigate to the project directory
cd edgesentinel

# Install dependencies in editable mode
pip install -e .
```

### 3. Verify Configuration & Status
```powershell
# Validate configuration file
edgesentinel config-check

# Check host platform and database status
edgesentinel status

# Verify database integrity
edgesentinel db-check
```

### 4. Run Synthetic Simulation
```powershell
# Simulate a TCP port scan
edgesentinel simulate port-scan

# Simulate a DNS burst / tunneling attempt
edgesentinel simulate dns-burst

# Simulate benign traffic to verify false-positive suppression
edgesentinel simulate normal-traffic
```

### 5. Inspect Alerts & Device Inventory
```powershell
# View recent security alerts
edgesentinel alerts

# View observed network devices
edgesentinel devices

# View raw events
edgesentinel events --limit 10
```

### 6. Launch Local Web Dashboard
```powershell
# Start dashboard on localhost:8080
edgesentinel dashboard --port 8080
```
Then open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your web browser.

---

## Production Raspberry Pi 3B+ Deployment

EdgeSentinel is deployed as a hardened, unprivileged systemd service on Raspberry Pi 3B+ (`192.168.88.11`):

- **Service Account**: `edgesentinel:edgesentinel` (unprivileged).
- **Capture Process**: `tcpdump` streaming raw PCAP via unbuffered stdout pipe under minimal `CAP_NET_RAW` capability.
- **Systemd Hardening**: `NoNewPrivileges=true`, `ProtectSystem=full`, `ProtectHome=true`, `PrivateTmp=true`, `MemoryMax=350M`, `CPUQuota=60%`.
- **Database Permissions**: Database file `/var/lib/edgesentinel/edgesentinel.db` (`0640`), directory (`0750`).
- **Dashboard Access**: Bound strictly to loopback `127.0.0.1:8080`.

### Accessing the Raspberry Pi Dashboard from Windows
In a Windows PowerShell window:
```powershell
ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
```
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.

---

## Automated Testing

Run the full automated test suite (37 unit, integration, and E2E tests):
```powershell
pytest -v
```

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Architectural overview, pipeline flow, and subsystem design.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — Raspberry Pi 3B+ runbook, verified state, and service setup.
- [docs/SECURITY.md](docs/SECURITY.md) — Threat model, passive posture, sandboxing, and Wi-Fi visibility boundaries.
- [docs/BACKUP_AND_RESTORE.md](docs/BACKUP_AND_RESTORE.md) — Online hot backup and isolated restore drill guide.
- [docs/REBOOT_RUNBOOK.md](docs/REBOOT_RUNBOOK.md) — Safe reboot recovery checklist and post-boot verification.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Diagnostic runbook for Windows and Raspberry Pi runtimes.
- [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md) — Detailed detection rule specifications and evidence thresholds.
- [docs/RESOURCE_BUDGET.md](docs/RESOURCE_BUDGET.md) — 1GB RAM budget allocations and resource profiles.
- [docs/HANDOVER.md](docs/HANDOVER.md) — Authoritative final handover report and acceptance ledger.
