# EdgeSentinel Troubleshooting Guide

## 1. Windows 11 Development Issues

### Issue: `UnicodeEncodeError` when running CLI
- **Symptoms**: `UnicodeEncodeError: 'charmap' codec can't encode character...`
- **Root Cause**: Windows command prompt or legacy PowerShell defaults to active code page 1252.
- **Resolution**: EdgeSentinel automatically handles this in `src/edgesentinel/cli.py` using stream reconfiguration and ASCII fallbacks. If running external tools, run `chcp 65001` in PowerShell before launching.

### Issue: `PermissionError: [WinError 32]` during SQLite tests
- **Symptoms**: Process cannot access the database file because it is being used by another process.
- **Root Cause**: On Windows, SQLite holds file locks until database connection handles are explicitly closed.
- **Resolution**: `Database.get_connection()` uses a context manager that strictly guarantees `conn.close()` in its `finally` block.

### Issue: Live packet capture unavailable on Windows
- **Symptoms**: `edgesentinel status` reports `Capture Backend: simulation` or `Npcap Available: No`.
- **Explanation**: Live capture on Windows requires the Npcap driver (installed in WinPcap API-compatible mode). For development, live capture is not required. Use `edgesentinel simulate` or `edgesentinel replay`.

---

## 2. Raspberry Pi 3B+ Linux Issues

### Issue: Permission denied running `tcpdump`
- **Symptoms**: `LinuxTcpdumpAdapter` fails to start child process with `PermissionError`.
- **Resolution**: Grant capture capabilities to the `tcpdump` executable:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
  ```

### Issue: Out of Memory (OOM) killer terminates EdgeSentinel
- **Symptoms**: Process killed with exit code 137; `dmesg` reports `Out of memory: Killed process edgesentinel`.
- **Root Cause**: High queue buffering or unbounded flow states exceeding the 350 MB budget.
- **Resolution**:
  1. Inspect `max_queue_size` in `config.yaml` (default: 5000).
  2. Reduce `idle_timeout` in flow tracking.
  3. Ensure systemd `MemoryMax=350M` is in effect.

### Issue: SQLite database locked
- **Symptoms**: `sqlite3.OperationalError: database is locked`.
- **Resolution**: EdgeSentinel enables WAL (`Write-Ahead Logging`) mode by default with `PRAGMA busy_timeout = 5000`. Ensure the database directory is stored on local storage and not an NFS/CIFS network share.
