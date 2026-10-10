# EdgeSentinel Detection Rules Specification

EdgeSentinel incorporates 7 lightweight, rule-based security detectors designed for low-overhead embedded execution on hardware such as the Raspberry Pi 3B+.

---

## Detection Rule Matrix

| Rule ID | Detector Name | Default Severity | Baseline Confidence | Detection Window | Primary Trigger Condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`DET-PORT-SCAN`** | Port Scan Detector | `HIGH` | `0.90` | 10.0 seconds | >= 15 distinct ports probed on target by single source host |
| **`DET-SYN-FLOOD`** | SYN Flood Anomaly | `HIGH` | `0.85` | 5.0 seconds | >= 25.0 TCP SYN packets/second from single source host |
| **`DET-SSH-BRUTE`** | SSH Brute Force Indicator | `HIGH` / `MEDIUM` | `0.95` (fail) / `0.70` (conn) | 60.0 seconds | >= 5 connection attempts or auth failures to port 22 |
| **`DET-DNS-ANOMALY`**| DNS Tunneling / Rate Anomaly| `MEDIUM` | `0.80` | 10.0 seconds | Domain length > 60 chars OR query rate > 20.0 QPS |
| **`DET-ARP-SPOOF`** | ARP Conflict / Spoofing | `HIGH` | `0.95` | 30.0 seconds | Same IP claimed by conflicting MAC addresses within window |
| **`DET-TRAFFIC-SPIKE`**| Sudden Traffic Rate Surge | `LOW` | `0.60` | 15.0 seconds | Moving rate exceeds 3.0x historical baseline average |
| **`DET-NEW-DEVICE`** | Unrecognized Network Device| `LOW` | `0.50` | Persistent | First observation of an IP not listed in trusted assets |

---

## Detailed Detector Specifications

### 1. `DET-PORT-SCAN`: Suspicious Port Scan Activity
- **Threat Detected**: Horizontal or vertical network reconnaissance (e.g., Nmap SYN scans, masscan).
- **Detection Logic**: Maintains a sliding-window set of distinct destination ports contacted by each `src_ip`. If `len(distinct_ports) >= threshold_ports`, an alert triggers.
- **Required Fields**: `src_ip`, `dst_ip`, `dst_port`, `timestamp`, `protocol=="TCP"`, `tcp_flags="SYN"`.
- **False-Positive Prevention**:
  - Filter out trusted management hosts and common ephemeral source ports.
  - Require TCP SYN flag so ordinary established multi-stream sessions (e.g. web browsing) do not trip the counter.
- **Tuning**: Increase `threshold_ports` to 25 or 30 on networks running high-concurrency P2P services.

### 2. `DET-SYN-FLOOD`: Elevated TCP SYN Rate
- **Threat Detected**: SYN-flood denial of service, half-open connection exhaustion, or high-speed scanning.
- **Detection Logic**: Calculates rate as `syn_count / max(window_duration, 0.1)`. If rate exceeds `threshold_syn_rate` (default 25.0 SYN/s), an alert is dispatched.
- **Required Fields**: `src_ip`, `dst_ip`, `timestamp`, `tcp_flags="SYN"`.
- **False-Positive Prevention**: Requires minimum count of 5 packets within the burst window to prevent microsecond divide-by-zero or 1-packet burst anomalies.
- **Tuning**: Adjust `threshold_syn_rate` based on LAN link speed and expected server load.

### 3. `DET-SSH-BRUTE`: SSH Brute-Force Heuristics
- **Threat Detected**: Automated password spraying or credential brute-forcing targeting port 22.
- **Detection Logic**: Tracks attempts to port 22 within sliding window.
  - **Verified Auth Failures** (via auth logs): `Severity.HIGH`, confidence `0.95`.
  - **Rapid Connection Bursts** (via network SYN heuristics): `Severity.MEDIUM`, confidence `0.70`.
- **Required Fields**: `src_ip`, `dst_ip`, `dst_port==22`, `timestamp`.
- **False-Positive Prevention**: Distinct confidence and severity scoring ensures network bursts are never falsely labelled as confirmed compromised credentials.
- **Tuning**: Increase `threshold_attempts` to 10 if automated CI/CD tools repeatedly open SSH connections.

### 4. `DET-DNS-ANOMALY`: DNS Query Rate and Domain Length Anomaly
- **Threat Detected**: DNS tunneling, data exfiltration via encoded subdomains (e.g., Iodine), or DNS amplification scanning.
- **Detection Logic**: Evaluates two independent criteria:
  1. *Exfiltration length*: Length of queried domain name exceeds `max_query_len` (default 60 chars).
  2. *Query rate*: Query frequency from source exceeds `query_rate_threshold` (default 20.0 QPS).
- **Required Fields**: `src_ip`, `dns_query`, `timestamp`.
- **False-Positive Prevention**: Common CDN domains (e.g., Cloudflare, Akamai) with subdomains up to 50 characters pass without alerting.
- **Tuning**: Set `max_query_len: 80` if using long Kubernetes internal service names.

### 5. `DET-ARP-SPOOF`: ARP Poisoning / Spoofing Indicator
- **Threat Detected**: Man-in-the-Middle (MitM) ARP cache poisoning or conflicting IP assignment.
- **Detection Logic**: Caches `(spa, sha)` mappings. If an incoming ARP packet claims an existing IP address with a different hardware MAC within the window, an alert is triggered.
- **Required Fields**: `arp_spa` (Source Protocol Address), `arp_sha` (Source Hardware Address), `arp_op`.
- **False-Positive Prevention**:
  - RFC 5227 DHCP probe address `0.0.0.0` is explicitly ignored.
  - Broadcast MAC (`FF:FF:FF:FF:FF:FF`) is ignored.
- **Tuning**: Expand `window_seconds` if ARP announcements are infrequent on quiet subnets.

### 6. `DET-TRAFFIC-SPIKE`: Volumetric Traffic Anomaly
- **Threat Detected**: Sudden data exfiltration, UDP packet storms, or unannounced backup synchronization.
- **Detection Logic**: Tracks per-window packet arrival rate. If current rate exceeds `historical_mean * threshold_multiplier`, an informational alert triggers.
- **Required Fields**: `timestamp`, `packet_len`.
- **False-Positive Prevention**: Baseline rate requires a minimum warmup window of events before flagging spikes.
- **Tuning**: Increase `threshold_multiplier` from 3.0 to 5.0 on bursty media-streaming networks.

### 7. `DET-NEW-DEVICE`: Unrecognized Network Device
- **Threat Detected**: Rogue hardware attached to unauthorized switchports or Wi-Fi networks.
- **Detection Logic**: Checks whether newly observed IP is in the configured `trusted_devices` list. If not, dispatches a low-severity notification.
- **Required Fields**: `src_ip`, `dst_ip`.
- **False-Positive Prevention**:
  - Multicast (`224.0.0.0/4`), broadcast (`255.255.255.255`), and loopback addresses are excluded from device inventory tracking.
- **Tuning**: Add static routers, print servers, and local workstations to `inventory.trusted_devices`.
