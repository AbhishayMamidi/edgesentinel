# EdgeSentinel Quality Assurance & Testing Guide

## 1. Testing Strategy

EdgeSentinel follows a strict test-driven development strategy where every detector, parser, and pipeline component is validated using deterministic synthetic inputs and offline test fixtures.

---

## 2. Test Matrix

| Test Module | Coverage Scope | Status |
|---|---|---|
| `tests/unit/test_foundation.py` | Configuration validation, models, platform diagnostics, SQLite transactions & retention, resource monitor | Passed (6/6) |
| `tests/unit/test_detectors.py` | Port scan, SYN anomaly, SSH brute force, DNS anomaly, ARP spoofing, New device detection | Passed (7/7) |
| `tests/unit/test_pcap_replay.py` | Pure-Python binary PCAP parser, streaming reader, malformed packet handling | Passed (2/2) |
| `tests/integration/test_pipeline_e2e.py` | End-to-end simulated port scan pipeline, false positive evaluation with normal traffic, REST API lifecycle | Passed (3/3) |

**Total Tests**: 18 passed in 3.11 seconds.

---

## 3. Running Tests Locally

### Running full test suite:
```powershell
pytest -v
```

### Running unit tests only:
```powershell
pytest tests/unit/ -v
```

### Running integration tests only:
```powershell
pytest tests/integration/ -v
```

---

## 4. False-Positive Validation

To ensure detectors do not alert excessively under normal traffic:
1. `test_port_scan_benign_traffic_no_false_positive`: Ingests 25 packets directed to port 443 across an active TCP session; verifies 0 port scan alerts are raised.
2. `test_benign_traffic_false_positive_evaluation`: Simulates full baseline web and DNS traffic; verifies 0 `DET-PORT-SCAN`, `DET-SYN-FLOOD`, or `DET-SSH-BRUTE` alerts are generated.
