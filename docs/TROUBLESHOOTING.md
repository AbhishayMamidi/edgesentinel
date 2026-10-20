# EdgeSentinel Troubleshooting Guide & Diagnostic Runbook

## 1. Network & Detection Quality Issues

### Issue: Spurious repeated `DET-SYN-FLOOD` alerts on default gateway (`192.168.88.1`)
- **Symptoms**: Journal logs and alerts table flood with HIGH-severity `DET-SYN-FLOOD` alarms attributing 50 SYN/s to router `192.168.88.1` with descriptions like `Host 192.168.88.1 generated 5 SYN packets (50.0 SYN/s) over 5.0s`.
- **Root Cause**: Microsecond rate skew in `SynAnomalyDetector`. When 5 parallel TCP handshakes arrive within 100ms during normal web browsing, calculating `duration = max(now - earliest, 0.1)` yielded `5 / 0.1 = 50.0 SYN/s`. Comparing this instantaneous millisecond rate against a 5-second threshold and using a low minimum count threshold of 5 triggered false alarms.
- **Resolution**:
  1. A duration baseline of 1.0s (`duration = max(now - earliest, 1.0)`) is enforced.
  2. The minimum volume threshold is raised from 5 to `max(10, int(threshold_syn_rate * 0.5))`.
  3. Deduplication suppression window was expanded from 10s to 60s.

### Issue: Raspberry Pi target IP address changes dynamically
- **Symptoms**: SSH connection to `192.168.88.11` times out or fails with connection refused.
- **Root Cause**: DHCP lease expiration on the local router (`192.168.88.1`) reassigned the address (e.g., previous lease was `192.168.88.10`, currently `192.168.88.11`).
- **Resolution**: Query ARP cache on Windows for the Raspberry Pi Foundation hardware OUI (`B8:27:EB:*`):
  ```powershell
  arp -a | Select-String "b8-27-eb"
  ```
  Both historical addresses share the same physical interface MAC (`B8:27:EB:BA:4D:22`).

---

## 2. Remote Access & SSH Tunnel Issues

### Issue: Dashboard inaccessible at `http://127.0.0.1:8080` from Windows
- **Symptoms**: Browser displays "This site can't be reached" or "Connection refused".
- **Root Cause**:
  1. The SSH local port forwarding tunnel is not running.
  2. Or Windows local port 8080 is already occupied by another application.
- **Resolution**:
  1. Verify whether local port 8080 is available:
     ```powershell
     Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
     ```
  2. If occupied, forward to an alternative local port:
     ```powershell
     ssh -N -L 8081:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
     ```
     Then browse to `http://127.0.0.1:8081`.
  3. If free, start the standard tunnel:
     ```powershell
     ssh -N -L 8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes abhi@192.168.88.11
     ```

---

## 3. Service Lifecycle & Systemd Issues

### Issue: Systemd service fails with Click CLI argument error
- **Symptoms**: `systemctl status edgesentinel` shows exit code 2; logs state `Unrecognized argument --config`.
- **Root Cause**: In Click/Argparse subparser hierarchies, the global `--config` flag must precede the subcommand (`edgesentinel --config /etc/edgesentinel/config.yaml dashboard`). Placing it after `dashboard` caused subparser failure.
- **Resolution**: Ensure `/etc/systemd/system/edgesentinel.service` uses:
  ```ini
  ExecStart=/opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml dashboard --port 8080 --host 127.0.0.1
  ```

### Issue: Service disabled after system reboot
- **Symptoms**: EdgeSentinel does not auto-start after Raspberry Pi reboots.
- **Root Cause**: Systemd unit was previously loaded but not enabled.
- **Resolution**: Enable the unit:
  ```bash
  sudo systemctl enable edgesentinel.service
  ```
  Verify symlink exists in `/etc/systemd/system/multi-user.target.wants/`.

---

## 4. SQLite Storage & Permissions Issues

### Issue: `Permission denied` opening `/var/lib/edgesentinel/edgesentinel.db`
- **Symptoms**: CLI commands run by user `abhi` fail with permission errors.
- **Root Cause**: Database directory is restricted to `0750` and file to `0640` owned by `edgesentinel:edgesentinel`.
- **Resolution**: Always run administrative database tasks using `sudo -u edgesentinel`:
  ```bash
  sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check
  ```

### Issue: `sqlite3.OperationalError: database is locked`
- **Symptoms**: Database write operations stall or raise `database is locked`.
- **Root Cause**: Non-WAL journal mode or missing busy timeout during concurrent reads/writes.
- **Resolution**:
  1. EdgeSentinel automatically sets `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;`.
  2. Confirm database resides on local SD card storage, not an NFS/CIFS mount.
