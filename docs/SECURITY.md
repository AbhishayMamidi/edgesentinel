# EdgeSentinel Security Policy & Threat Model

## 1. Defensive Philosophy

EdgeSentinel is built strictly as a **defensive monitoring and intrusion detection system**. It does not contain offensive exploitation capabilities, packet-crafting attack modules, credential harvesting, or automated disruptive actions.

---

## 2. Default Passive Posture

- **No Automatic Firewall Rule Execution**: The application observes, correlates, logs, and alerts. It does not automatically modify iptables, nftables, or routing tables.
- **Dry-Run Response Engine**: The response subsystem (`response/dry_run.py`) outputs preview commands for audit purposes only (`response.mode: "dry_run"`).
- **Management Allowlisting**: Localhost (`127.0.0.1`, `::1`), default gateways, and configured trusted devices are hard-coded into an immutable allowlist. Mitigation suggestions for these addresses are strictly blocked to prevent operator lockout.

---

## 3. Local Dashboard & API Hardening

- **Localhost Binding**: The FastAPI backend is configured to bind exclusively to `127.0.0.1` by default. It is not exposed to public network interfaces or 0.0.0.0.
- **Remote Access via SSH Tunneling**: Windows and remote workstations connect exclusively via encrypted SSH port forwarding:
  ```powershell
  ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
  ```
- **CORS Restriction**: Explicitly restricted to `127.0.0.1:8080` and `localhost:8080`.
- **No Remote Shell Execution**: Dashboard endpoints do not accept shell commands or arbitrary script parameters. All actions map to pre-defined internal methods.
- **XSS Mitigation**: The single-page dashboard escapes all dynamic strings before rendering in HTML.

---

## 4. Database Security & File Permissions

- **File and Directory Permissions**:
  - Database file `/var/lib/edgesentinel/edgesentinel.db`: `0640` (`-rw-r-----`), owned by `edgesentinel:edgesentinel`.
  - Directory `/var/lib/edgesentinel`: `0750` (`drwxr-x---`), owned by `edgesentinel:edgesentinel`.
  - Configuration `/etc/edgesentinel/config.yaml`: `0640` (`-rw-r-----`), owned by `edgesentinel:edgesentinel`.
  - Backup directory `/var/lib/edgesentinel/backups`: `0750` (`drwxr-x---`).
- **Parameterized Queries**: All database operations use parameter substitution (`?`). Dynamic SQL string concatenation is strictly prohibited.
- **No Payload Storage**: EdgeSentinel does not store raw packet payloads or sensitive payload content by default to prevent credential leakage and reduce storage footprints.
- **Bounded Retention**: Stored network events are pruned based on the configurable retention window (default: 7 days) via `edgesentinel db-check --cleanup`.

---

## 5. Linux Deployment Least Privilege & Sandboxing

- **Unprivileged Service Account**: The systemd service runs as dedicated system user and group `edgesentinel:edgesentinel`.
- **Minimal Linux Capabilities**: Granted minimal `CAP_NET_RAW` bounded set (`CapabilityBoundingSet=CAP_NET_RAW`, `AmbientCapabilities=CAP_NET_RAW`). `CAP_NET_ADMIN` is explicitly excluded to ensure the process cannot alter routing tables or firewall rules.
- **Systemd Hardening Directives**:
  - `NoNewPrivileges=true`
  - `ProtectSystem=full`
  - `ProtectHome=true`
  - `PrivateTmp=true`
  - `MemoryHigh=300M` / `MemoryMax=350M`
  - `CPUQuota=60%`

---

## 6. Detection Quality, Provenance & Network Visibility Boundaries

### Synthetic vs Observed Provenance
- Every recorded network event contains an explicit `is_synthetic` integer flag (`0` for live captured traffic, `1` for simulation or test injection).
- Alerts inherit `is_synthetic` directly from triggering events, ensuring synthetic tests never masquerade as live intrusion indicators.

### Gateway SYN Burst False-Positive Suppression
- Normal web browsing and parallel TCP connections through the default gateway (`192.168.88.1`) generate short bursts of 3–5 SYN packets in milliseconds.
- `SynAnomalyDetector` uses a calibrated 1.0-second baseline duration and a minimum volume threshold of at least 10 SYN packets, eliminating spurious `DET-SYN-FLOOD` alarms during normal traffic while maintaining high sensitivity to genuine flooding.

### Wi-Fi Managed Mode Capture Boundaries
- When capturing on `wlan0` in standard station (managed) mode (`promiscuous: false`), the Wi-Fi interface observes:
  1. All unicast traffic destined to or originating from the Raspberry Pi (`192.168.88.11`).
  2. All broadcast and multicast frames across the subnet (ARP, mDNS `224.0.0.251`, SSDP, DHCP).
  3. Traffic passing through the gateway directed to the Pi.
- In accordance with IEEE 802.11 standards, unicast frames exchanged directly between two other wireless stations are encrypted with pairwise transient keys (PTK) and filtered at the Wi-Fi physical layer by the access point. EdgeSentinel does not claim visibility over external station-to-station unicast traffic without dedicated monitor-mode hardware or router port mirroring.
