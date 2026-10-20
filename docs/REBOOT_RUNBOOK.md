# EdgeSentinel — Raspberry Pi 3B+ Safe Reboot & Recovery Runbook

> [!CAUTION]
> **Operator Rule**: Do not execute a system reboot without explicit human authorization.
> Reboot recovery is marked as **`NOT VERIFIED (PENDING USER REBOOT AUTHORIZATION)`** until a maintenance window is scheduled and explicitly authorized.

---

## 1. Pre-Reboot Health Checklist

Before issuing a reboot command, verify the following conditions:

```bash
# 1. Verify service health and queue state
curl -s http://127.0.0.1:8080/api/status | grep -o '"queue_size":[0-9]*'
# Expected: "queue_size":0

# 2. Check SQLite database integrity
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check
# Expected: Integrity Check: ok

# 3. Verify latest backup exists and is verified
ls -la /var/lib/edgesentinel/backups/
# Expected: Valid .db backup with chmod 0640 permissions
```

---

## 2. Maintenance Window & Authorization Gate

Reboot must only be executed during an authorized maintenance window:
- **Operator Consent**: Confirmed.
- **Service Impact**: Monitoring will be briefly offline for approximately 45–75 seconds during Raspberry Pi 3B+ boot cycle.

---

## 3. Graceful Shutdown & Reboot Execution

Execute a clean shutdown to ensure WAL buffers are fully checkpointed into the main SQLite database:

```bash
# 1. Stop edgesentinel cleanly to flush memory buffers and release tcpdump
sudo systemctl stop edgesentinel.service

# 2. Verify service is inactive
sudo systemctl is-active edgesentinel.service
# Expected: inactive

# 3. Execute graceful reboot
sudo reboot
```

---

## 4. Reconnection & Dynamic IP Resolution

Because the Raspberry Pi may receive a new DHCP lease from the router (`192.168.88.1`) upon reboot:

1. **Ping last known IP**:
   ```powershell
   # In Windows PowerShell:
   Test-Connection -ComputerName 192.168.88.11 -Count 2
   ```
2. **If IP changed**, discover the new lease via ARP table or subnet scan:
   ```powershell
   # Query ARP cache for Raspberry Pi Foundation OUI (B8:27:EB:*)
   arp -a | Select-String "b8-27-eb"
   ```
   *Note: Both historical IPs `192.168.88.10` and `192.168.88.11` shared MAC `B8:27:EB:BA:4D:22`.*

3. **Reconnect via SSH**:
   ```powershell
   ssh abhi@<DISCOVERED_IP>
   ```

---

## 5. Post-Reboot Verification Sequence

Once reconnected via SSH:

### 5.1 Service Auto-Start Verification
```bash
# Verify systemd auto-started edgesentinel
sudo systemctl status edgesentinel.service --no-pager
# Expected: Active: active (running)
# Expected: Loaded: ... (enabled; preset: enabled)
```

### 5.2 Capture Process Verification
```bash
# Verify tcpdump child process is capturing on wlan0
ps aux | grep -E "(edgesentinel|tcpdump)" | grep -v grep
# Expected: Main python3 process AND tcpdump child process running
```

### 5.3 Database Persistence Verification
```bash
# Verify SQLite integrity and event ingestion
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check
# Expected: Integrity Check: ok
```

### 5.4 Dashboard & SSH Tunnel Recovery
On the Windows HP laptop:
```powershell
# Start the persistent SSH tunnel
ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
```
In browser, open [http://127.0.0.1:8080](http://127.0.0.1:8080) and verify dashboard renders with active metrics.

---

## 6. Failure Diagnosis & Rollback

If `edgesentinel.service` fails to start post-reboot:

1. **Inspect logs**:
   ```bash
   journalctl -u edgesentinel.service -n 50 --no-pager
   ```
2. **Common root causes**:
   - `wlan0 not ready`: Network wait timeout before Wi-Fi association. The service unit specifies `After=network.target network-online.target Wants=network-online.target` to prevent this.
   - `Permission denied`: Verify `/var/lib/edgesentinel` ownership:
     ```bash
     sudo chown -R edgesentinel:edgesentinel /var/lib/edgesentinel /etc/edgesentinel
     ```
   - `Corrupted database`: Follow restore procedure in `docs/BACKUP_AND_RESTORE.md`.
