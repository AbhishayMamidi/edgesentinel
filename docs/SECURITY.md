# EdgeSentinel Security Policy & Threat Model

## 1. Defensive Philosophy

EdgeSentinel is built strictly as a **defensive monitoring and intrusion detection system**. It does not contain offensive exploitation capabilities, packet-crafting attack modules, credential harvesting, or automated disruptive actions.

---

## 2. Default Passive Posture

- **No Automatic Firewall Rule Execution**: The application observes, correlates, logs, and alerts. It does not automatically modify iptables, nftables, or routing tables.
- **Dry-Run Response Engine**: The response subsystem (`response/dry_run.py`) outputs preview commands for audit purposes only.
- **Management Allowlisting**: Localhost (`127.0.0.1`, `::1`), default gateways, and configured trusted devices are hard-coded into an immutable allowlist. Mitigation suggestions for these addresses are strictly blocked to prevent operator lockout.

---

## 3. Local Dashboard & API Hardening

- **Localhost Binding**: The FastAPI backend is configured to bind exclusively to `127.0.0.1` by default. It is not exposed to public network interfaces.
- **CORS Restriction**: Explicitly restricted to `127.0.0.1:8080` and `localhost:8080`.
- **No Remote Shell Execution**: Dashboard endpoints do not accept shell commands or arbitrary script parameters. All actions map to pre-defined internal methods.
- **XSS Mitigation**: The single-page dashboard escapes all dynamic strings before rendering in HTML.

---

## 4. Database Security

- **Parameterized Queries**: All database operations use parameter substitution (`?`). Dynamic SQL string concatenation is strictly prohibited.
- **No Payload Storage**: EdgeSentinel does not store raw packet payloads or sensitive payload content by default to prevent credential leakage and reduce storage footprints.
- **Bounded Retention**: Stored network events are automatically pruned based on the configurable retention window (default: 7 days).

---

## 5. Linux Deployment Least Privilege

- **Unprivileged Service Account**: The systemd service runs as a dedicated system user `edgesentinel`.
- **Linux Capabilities**: Packet capture permissions are granted via `CAP_NET_RAW` and `CAP_NET_ADMIN` using Linux capabilities (`setcap` on tcpdump or systemd `AmbientCapabilities`), eliminating the need to run EdgeSentinel as `root`.
- **Systemd Hardening**:
  - `NoNewPrivileges=true`
  - `ProtectSystem=full`
  - `ProtectHome=true`
  - `PrivateTmp=true`
  - `MemoryMax=350M`
