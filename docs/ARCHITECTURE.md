# EdgeSentinel System Architecture

## 1. High-Level Architecture

EdgeSentinel uses a staged, modular pipeline where diverse capture sources are converted into a single normalized event schema before being passed through stateful analysis, inventory tracking, rule-based detection, and persistent SQLite storage.

```
+-------------------------------------------------------------------------+
|                              Input Sources                              |
|  +--------------------+  +--------------------+  +-------------------+  |
|  | Synthetic Generator|  | Offline PCAP Reader|  | Live Linux/tcpdump|  |
|  +--------------------+  +--------------------+  +-------------------+  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        Normalized Event Model                           |
|      (timestamp, src/dst IP, ports, protocol, flags, length, metadata)  |
+-------------------------------------------------------------------------+
                                    |
         +--------------------------+--------------------------+
         |                          |                          |
         v                          v                          v
+------------------+      +--------------------+     +--------------------+
|   Flow Tracker   |      |  Device Inventory  |     |  Detection Engines |
| (Bounded 5-tuple |      | (IP/MAC tracking & |     | - DET-PORT-SCAN    |
|  idle eviction)  |      |  trust validation) |     | - DET-SYN-FLOOD    |
+------------------+      +--------------------+     | - DET-SSH-BRUTE    |
         |                          |                | - DET-DNS-ANOMALY  |
         |                          |                | - DET-ARP-SPOOF    |
         |                          |                | - DET-TRAFFIC-SPIKE|
         |                          |                | - DET-NEW-DEVICE   |
         |                          |                +--------------------+
         |                          |                          |
         v                          v                          v
+-------------------------------------------------------------------------+
|                              Alert Manager                              |
|           (Sliding window deduplication, severity, notifications)       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                          SQLite Event Store                             |
|          (WAL mode, synchronous=NORMAL, indexes, retention purge)       |
+-------------------------------------------------------------------------+
                                    |
         +--------------------------+--------------------------+
         |                                                     |
         v                                                     v
+------------------+                                 +--------------------+
|   CLI Interface  |                                 | Local Web Dashboard|
| (Rich tables &   |                                 | (FastAPI + Vanilla |
|  query filters)  |                                 |  HTML/JS Frontend) |
+------------------+                                 +--------------------+
```

---

## 2. Key Components

### 2.1 Normalized Event Model (`models.py`)
All downstream components receive `NetworkEvent` records. Missing protocol fields remain `None` rather than fabricated. Synthetic packets are explicitly stamped with `is_synthetic=True` and `capture_source="simulation"`.

### 2.2 Streaming PCAP Reader (`replay/pcap_reader.py`)
Decodes binary global headers and per-packet headers directly in Python without libpcap or Npcap. Reads packets incrementally via Python generator semantics to strictly avoid loading multi-megabyte captures into RAM.

### 2.3 Flow Tracker (`flows/tracker.py`)
Calculates canonical bidirectional flow keys for 5-tuples. Enforces bounded memory by maintaining at most 5,000 flows and evicting flows that remain idle longer than 60 seconds.

### 2.4 Detection Engine (`detection/`)
Each detector is an independent state machine inheriting from `BaseDetector`:
- Implements bounded sliding-window state.
- Deduplicates repetitive alerts using host-pair keys.
- Packages quantitative evidence (sampled ports, rates, byte counts, deltas) into the alert.
- Operates strictly with passive read-only evaluation.

### 2.5 SQLite Event Store (`storage/database.py`)
Configured specifically for concurrent reads and resilient writes on flash storage:
- `PRAGMA journal_mode = WAL`: Allows concurrent readers while writing.
- `PRAGMA synchronous = NORMAL`: Prevents unnecessary write amplification on SD cards.
- `PRAGMA busy_timeout = 5000`: Handles lock contention gracefully.
- Parameterized queries throughout to prevent SQL injection.
- Automatic retention purging deletes records older than `retention_days`.
