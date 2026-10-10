# EdgeSentinel

**EdgeSentinel** is a lightweight, local-first network security monitoring (NSM) and intrusion detection platform (IDS) designed for a **laptop-first development lifecycle on Windows 11** with eventual production deployment to an unprivileged **Raspberry Pi 3B+ (1 GB RAM)**.

---

## Key Features

- **Laptop-First Isolation**: Fully functional on Windows 11 without requiring packet capture drivers or external hardware.
- **Rule-Based Detection Engine**:
  - `DET-PORT-SCAN`: Port scan detection across distinct destination ports with deduplication.
  - `DET-SYN-FLOOD`: TCP SYN rate burst / half-open flood indicators.
  - `DET-SSH-BRUTE`: Repeated connection attempts and authentication failure indicators against SSH (port 22).
  - `DET-DNS-ANOMALY`: DNS query rate spikes and abnormally long domain names (DNS tunneling / exfiltration detection).
  - `DET-ARP-SPOOF`: Conflicting IP-to-MAC mapping detection (ARP poisoning/spoofing).
  - `DET-TRAFFIC-SPIKE`: Rolling statistical traffic surge detection.
  - `DET-NEW-DEVICE`: Detection and asset tracking of newly discovered devices.
- **Pure-Python Streaming PCAP Reader**: Dissects offline `.pcap` files without C dependencies or libpcap.
- **Deterministic Synthetic Traffic Generator**: Evaluates detectors and false positive rates safely on Windows.
- **Bounded Resource Architecture**: Enforces flow table and queue caps designed strictly for 1GB RAM hardware targets.
- **Local Web Dashboard & CLI**: Real-time alerts, device inventory, system metrics, and simulation controls.
- **Passive Defensive Posture**: Non-destructive, dry-run firewall rule preview with strict allowlist protection.

---

## Quick Start on Windows 11

### 1. Requirements
- Python 3.10+ (tested on Python 3.12 & 3.14)
- Git (optional)

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

### 6. Replay Offline PCAP Captures
```powershell
edgesentinel replay tests/fixtures/sample_scan.pcap
```

### 7. Launch Local Web Dashboard
```powershell
# Start dashboard on localhost:8080
edgesentinel dashboard --port 8080
```
Then open `http://127.0.0.1:8080` in your web browser.

---

## Automated Testing

Run the full automated test suite (18 unit, integration, and E2E tests):
```powershell
pytest -v
```

---

## Directory Structure

```
edgesentinel/
├── deploy/
│   └── edgesentinel.service      # systemd unit file with resource limits for Pi 3B+
├── docs/
│   ├── ARCHITECTURE.md          # End-to-end component and data flow architecture
│   ├── DEPLOYMENT.md            # Raspberry Pi 3B+ deployment instructions & checklist
│   ├── RESOURCE_BUDGET.md       # 1GB RAM budget, memory profiling & performance limits
│   ├── SECURITY.md              # Threat model, passive posture & least privilege design
│   ├── TESTING.md               # Testing matrix, benchmarks & false positive verification
│   └── TROUBLESHOOTING.md       # Diagnostic guide for Windows and Linux runtimes
├── scripts/
│   ├── run_dev.ps1              # Windows local development launcher
│   ├── test_all.ps1             # Windows full test suite runner
│   ├── health_check.ps1         # Windows runtime health and database check
│   ├── install_linux.sh         # Raspberry Pi automated installer (runs on Pi only)
│   └── uninstall_linux.sh       # Clean Linux uninstaller (runs on Pi only)
├── src/
│   └── edgesentinel/
│       ├── alerts/              # AlertManager with deduplication and SQLite persistence
│       ├── analysis/            # Feature extraction and pure-Python packet decoder
│       ├── capture/             # Windows and Linux (tcpdump) live capture adapters
│       ├── dashboard/           # FastAPI backend and vanilla HTML/JS single-page UI
│       ├── detection/           # Modular detection engines (port scan, SYN, SSH, DNS, ARP, etc.)
│       ├── flows/               # Bounded memory flow tracker with idle eviction
│       ├── inventory/           # Device inventory tracker with trusted device allowlist
│       ├── monitoring/          # psutil-based resource and memory budget monitor
│       ├── replay/              # Streaming PCAP reader with zero C dependencies
│       ├── response/            # Passive / dry-run firewall rule preview generator
│       ├── simulation/          # Deterministic synthetic traffic generator
│       ├── storage/             # SQLite database with WAL mode and retention management
│       ├── cli.py               # Complete command line interface
│       ├── config.py            # Pydantic configuration loader and validator
│       ├── models.py            # Normalized NetworkEvent, Alert, Device, and Flow schemas
│       └── platform_info.py     # Non-invasive OS, hardware, and driver detection
└── tests/
    ├── fixtures/                # Committed synthetic test PCAP fixtures
    ├── integration/             # E2E pipeline and dashboard API integration tests
    └── unit/                    # Unit tests for detectors, foundation, and PCAP replay
```

---

## Eventual Raspberry Pi 3B+ Deployment

Deployment to the Raspberry Pi is strictly deferred until authorized. Deployment artifacts and systemd units have been prepared in `deploy/` and `scripts/`. See [docs/DEPLOYMENT.md](file:///C:/Users/Abhishay%20Mamidi/.gemini/antigravity/scratch/edgesentinel/docs/DEPLOYMENT.md) for details.
