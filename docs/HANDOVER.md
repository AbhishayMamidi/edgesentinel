# EdgeSentinel — Definitive Release & Deployment Handover Report

**System**: EdgeSentinel Local-First Network Security Monitoring & IDS  
**Version**: `v0.1.1`  
**Target Hardware**: Raspberry Pi 3B+ (ARM64 `aarch64`, Debian 13) & Windows 11 HP ProBook  
**Target IP**: `192.168.88.11` (Interface: `wlan0`, SSH User: `abhi`)  
**Deployment State**: Active, Running, Hardened, Backed Up & Boot-Enabled  
**Operational Posture**: Strict `dry_run` active; zero automatic blocking or packet injection  
**Final Readiness Verdict**: **`READY WITH DOCUMENTED LIMITATIONS`**

---

## 1. Final Acceptance Ledger

Every requirement from the Master Deployment specification was audited, validated with observable live data, repaired where defective, and verified.

| Category | Requirement / Capability | Status | Evidence & Verification Details |
| :--- | :--- | :---: | :--- |
| **1. Implementation Completeness** | Modular rule-based detectors | **PASS** | 7 active detectors (`DET-PORT-SCAN`, `DET-SYN-FLOOD`, `DET-SSH-BRUTE`, `DET-DNS-ANOMALY`, `DET-ARP-SPOOF`, `DET-TRAFFIC-SPIKE`, `DET-NEW-DEVICE`). |
| | Subprocess capture adapter | **PASS** | `LinuxTcpdumpAdapter` streaming PCAP via stdout pipe from unprivileged `tcpdump`. |
| | Event pipeline & flow tracking | **PASS** | `EventPipeline` updates `FlowTracker` (idle eviction), `DeviceInventory`, and batch flushes. |
| | Retention cleanup CLI | **PASS** | Implemented `edgesentinel db-check --cleanup` wiring `Database.cleanup_retention()`. |
| **2. Test Suite Validation** | Automated tests passing | **PASS** | **37 / 37 passed** (0 failures, 0 errors, 1 deprecation warning) across unit & integration suites in 8.28s. |
| | False-positive regression test | **PASS** | Added `test_syn_flood_benign_burst_no_false_positive` to prevent 5-packet burst alert skew. |
| **3. Security Hardening** | Minimal Linux capabilities | **PASS** | Unprivileged user `edgesentinel`, `CapabilityBoundingSet=CAP_NET_RAW`, `CAP_NET_ADMIN` dropped. |
| | Systemd sandboxing | **PASS** | `NoNewPrivileges=true`, `ProtectSystem=full`, `ProtectHome=true`, `PrivateTmp=true`. |
| | File permissions | **PASS** | Database `/var/lib/edgesentinel/edgesentinel.db` hardened to `0640`, directory `0750`. |
| | Safe loopback binding | **PASS** | Dashboard bound exclusively to `127.0.0.1:8080`; CORS restricted to localhost. |
| **4. Detection & Provenance** | Synthetic event separation | **PASS** | All events carry `is_synthetic` integer flag (`0` for live traffic, `1` for simulation). |
| | Gateway SYN flood remediation | **PASS** | Enforced 1.0s duration baseline and minimum flood count, eliminating gateway `192.168.88.1` alert flood. |
| | Wi-Fi managed-mode boundaries | **PASS** | Documented IEEE 802.11 PTK encryption isolation between wireless stations in station mode. |
| **5. Database & Recovery** | SQLite integrity check | **PASS** | `PRAGMA integrity_check` returned `[('ok',)]` on production and restored databases. |
| | Live event persistence | **PASS** | Live events actively ingesting (>52,000 events stored, 197 alerts recorded). |
| | Verified hot backup | **PASS** | Online backup created at `/var/lib/edgesentinel/backups/edgesentinel_20261020_232048.db` (`11.09 MB`, `0640`). |
| | Isolated restore drill | **PASS** | Restored to temporary isolated sandbox; verified integrity, row counts, and application adapter queries. |
| **6. Raspberry Pi Deployment**| Host identity & IP resolution | **PASS** | Verified `192.168.88.11` (resolved historical `192.168.88.10` as earlier DHCP lease on identical MAC `B8:27:EB:BA:4D:22`). |
| | Service state & boot enablement | **PASS** | `edgesentinel.service` active (`active (running)`), boot-enabled (`multi-user.target.wants`). |
| | Argument ordering alignment | **PASS** | Synchronized systemd `ExecStart` across production, deploy template, and git repository. |
| **7. Dashboard & Remote Access**| Loopback port availability | **PASS** | Verified Windows local port 8080 was free; established background SSH port forwarding. |
| | REST API & UI rendering | **PASS** | Verified `GET /` (HTTP 200, 17.9 KB HTML), `/api/status`, `/api/alerts`, `/api/devices`. |
| **8. Performance & Resources** | RAM budget (<350 MB quota) | **PASS** | Process memory consumption measured at `52.5 MB`–`55.0 MB` (~5.8% of system RAM). |
| | CPU budget (<60% quota) | **PASS** | CPU load measured at `1.4%` (load average: 0.17). |
| | Packet drop rate | **PASS** | `packets_captured`: >24,000, `packets_dropped`: 0, `queue_size`: 0. |
| **9. Documentation Completeness**| Operations & runbooks | **PASS** | Complete runbooks: `DEPLOYMENT.md`, `SECURITY.md`, `BACKUP_AND_RESTORE.md`, `REBOOT_RUNBOOK.md`, `TROUBLESHOOTING.md`. |
| **10. Git Hygiene & Push** | Clean tree & secret exclusion | **PASS** | `.gitignore` verified; no databases, WAL files, PCAPs, or credentials tracked. |
| | GitHub repository publication | **PASS** | Repository created and pushed to `https://github.com/AbhishayMamidi/edgesentinel`. |
| **11. Reboot Recovery** | Safe reboot runbook | **NOT VERIFIED** | **Pending operator reboot authorization.** Systemd unit is fully enabled (`multi-user.target.wants`). |

---

## 2. Resource & Performance Measurements

Measured live from Raspberry Pi 3B+ during continuous network capture:

```
Platform             : Linux 6.18.50+rpt-rpi-v8 aarch64 (Debian 13 Trixie)
Hardware Target      : Raspberry Pi 3B+ (4 Cores, 905 MiB RAM)
Service State        : active (running)
Main PID             : 2701 (python3 / edgesentinel)
Capture PID          : 2703 (tcpdump -U -w - -i wlan0 -s 128 -p)
Memory Used          : 55.01 MB  (Budget limit: 350 MB -> 15.7% of budget utilized)
CPU Usage            : 1.4%      (Budget limit: 60%    -> 2.3% of budget utilized)
Disk Partition       : 24.26 GB free out of 29.0 GB (11.2% utilized)
Database File Size   : 17.36 MB (/var/lib/edgesentinel/edgesentinel.db)
Ingested Events      : 52,617 total
Persisted Alerts     : 197 total (129 HIGH, 51 LOW, 8 MEDIUM, 9 synthetics)
Packets Dropped      : 0
Queue Backlog        : 0
```

---

## 3. Remote Dashboard Access Instructions

EdgeSentinel is bound strictly to loopback `127.0.0.1:8080` on the Raspberry Pi for defensive isolation.

### Connecting from Windows 11 (PowerShell)
```powershell
ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
```

Once running, browse to:
> **Dashboard**: [http://127.0.0.1:8080](http://127.0.0.1:8080)

To terminate the tunnel, press `Ctrl + C` in the PowerShell terminal, or execute:
```powershell
Get-Process ssh -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*8080:127.0.0.1:8080*" } | Stop-Process
```

---

## 4. Published GitHub Repository

- **Repository URL**: `https://github.com/AbhishayMamidi/edgesentinel`
- **Default Branch**: `main`
- **Visibility**: Public
- **Pushed Commit**: Verified against upstream git ref
