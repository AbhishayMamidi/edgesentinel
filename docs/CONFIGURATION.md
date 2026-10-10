# EdgeSentinel Configuration Guide

This document describes all configuration sections, schema constraints, safe default values, and operational guidelines for EdgeSentinel on both local development environments and target resource-constrained platforms (such as the Raspberry Pi 3B+).

---

## 1. Overview & File Precedence

EdgeSentinel loads its configuration in the following order of precedence:

1. **CLI Flag**: `--config <path>` or `-c <path>` explicitly specified when launching `edgesentinel`.
2. **Current Directory**: `config.yaml` located in the current working directory.
3. **System Production Path**: `/etc/edgesentinel/config.yaml` (standard Linux deployment path).
4. **Internal Defaults**: Pydantic V2 model defaults defined in `edgesentinel.config.AppConfig`.

If no configuration file is present, safe built-in defaults are used. Invalid YAML or values outside validated constraints cause the application to terminate immediately with a descriptive error.

---

## 2. Configuration Reference

### 2.1 `environment`
- **Type**: `str` (`"development"` | `"production"`)
- **Default**: `"development"`
- **Description**: Sets the operational profile. In production, logs are formatted for systemd journald ingestion and debug output is disabled.

### 2.2 `storage`
Controls SQLite database persistence, WAL checkpointing, and retention.

| Parameter | Type | Default | Constraint / Description |
| :--- | :--- | :--- | :--- |
| `database_path` | `str` | `"data/edgesentinel.db"` | Path to the SQLite database file. Automatically creates parent directories. |
| `busy_timeout_ms`| `int` | `5000` | SQLite busy handler timeout in milliseconds. Prevents `sqlite3.OperationalError: database is locked`. |
| `retention_days` | `int` | `7` | Maximum age in days for raw packet events and expired flows. Pruned periodically. |
| `batch_size` | `int` | `100` | Number of events buffered in memory before executing a bulk database insert transaction. |
| `flush_interval_seconds` | `float`| `1.0` | Maximum time in seconds to hold staged events before forcing a database commit. |

### 2.3 `capture`
Specifies how packet metadata is acquired.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `backend` | `str` | `"simulation"` | Capture source: `"simulation"`, `"pcap"`, `"windows"`, or `"linux"`. |
| `interface` | `str` | `""` | Network interface name (e.g., `"eth0"`, `"wlan0"`). Leave blank for default. |
| `bpf_filter` | `str` | `""` | Optional Berkeley Packet Filter string (e.g. `"tcp or udp or arp"`). |
| `promiscuous` | `bool` | `false` | Enable promiscuous interface mode if supported by capture driver. |

### 2.4 `monitoring`
Protects system memory and process execution ceilings.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `interval_seconds` | `float` | `2.0` | Telemetry sampling interval for CPU, memory, and queue depths. |
| `max_queue_size` | `int` | `5000` | Strict queue depth limit. Prevents unbounded memory growth during heavy traffic bursts. |

### 2.5 `dashboard`
Controls the local monitoring web server and REST API.

| Parameter | Type | Default | Security Requirement |
| :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `true` | Whether to expose the web dashboard service. |
| `host` | `str` | `"127.0.0.1"` | **Must remain 127.0.0.1 by default**. Never bind to `0.0.0.0` without an encrypted reverse proxy or SSH tunnel. |
| `port` | `int` | `8080` | Local port for the HTTP service. |

### 2.6 `detection`
Thresholds and sliding time windows for each of the 7 security detectors.

```yaml
detection:
  port_scan:
    enabled: true
    threshold_ports: 15        # Distinct destination ports probed
    window_seconds: 10.0       # Sliding window in seconds
  syn_anomaly:
    enabled: true
    threshold_syn_rate: 25.0   # Minimum SYN packets/second from a single host
    window_seconds: 5.0
  ssh_bruteforce:
    enabled: true
    threshold_attempts: 5      # Failed attempts or burst connections to port 22
    window_seconds: 60.0
  dns_anomaly:
    enabled: true
    query_rate_threshold: 20.0 # Queries per second from a single host
    max_query_len: 60          # Domain name length threshold (exfiltration detection)
    window_seconds: 10.0
  arp_anomaly:
    enabled: true
    window_seconds: 30.0       # Conflicting IP-to-MAC mapping detection window
  traffic_anomaly:
    enabled: true
    threshold_multiplier: 3.0  # Traffic rate multiplier over baseline
    window_seconds: 15.0
  new_device:
    enabled: true              # Flags unrecognized hosts not in trusted inventory
```

### 2.7 `inventory`
Defines trusted network assets excluded from "New Device" alerts.

```yaml
inventory:
  trusted_devices:
    - "127.0.0.1"
    - "192.168.1.1"            # Default local gateway / router
```

### 2.8 `response`
Defines defensive response behavior.

| Parameter | Type | Default | Security Constraint |
| :--- | :--- | :--- | :--- |
| `mode` | `str` | `"dry_run"` | `"passive"` or `"dry_run"`. Automatic firewall modification is strictly disabled. |

---

## 3. Validating Configuration

Validate configuration files using the CLI tool:

```powershell
# Validate custom configuration file
python src/edgesentinel/cli.py config-check --config config.example.yaml
```

Output:
```text
[OK] Configuration is valid and verified.
Environment    : development
Database Path  : data/edgesentinel.db
Retention Days : 7
Dashboard Host : 127.0.0.1:8080
Port Scan Det  : Enabled (Threshold: 15 ports / 10.0s)
SYN Flood Det  : Enabled
SSH Brute Det  : Enabled
DNS Anomaly Det: Enabled
ARP Anomaly Det: Enabled
Traffic Anom   : Enabled
Trusted Hosts  : 127.0.0.1, 192.168.1.1
```
