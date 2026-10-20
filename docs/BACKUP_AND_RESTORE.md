# EdgeSentinel — Database Backup and Disaster Recovery Guide

## 1. Overview and Architecture
EdgeSentinel persists all network events, security alerts, observed devices, and flow records in SQLite (`/var/lib/edgesentinel/edgesentinel.db`).
The database uses:
- **Write-Ahead Logging (WAL)** (`PRAGMA journal_mode=WAL;`) for high concurrency and resilience.
- **Synchronous Normal** (`PRAGMA synchronous=NORMAL;`) ensuring crash consistency without disk write bottlenecks.
- **Thread-safe connection pooling** with 5000ms busy timeout (`PRAGMA busy_timeout=5000;`).
- **Strict least-privilege permissions**: Database file `0640` (`-rw-r-----`), directory `0750` (`drwxr-x---`), owned by service user `edgesentinel:edgesentinel`.

---

## 2. Verified Hot Backup Procedure

To prevent partial reads or database corruption, online backups must utilize SQLite's online backup API or `VACUUM INTO`.

### Online Hot Backup Script
```bash
# Execute as edgesentinel or with sudo on Raspberry Pi:
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/python3 - << 'EOF'
import sqlite3, time
from pathlib import Path

db_path = "/var/lib/edgesentinel/edgesentinel.db"
backup_dir = Path("/var/lib/edgesentinel/backups")
backup_dir.mkdir(parents=True, exist_ok=True)

ts = time.strftime("%Y%m%d_%H%M%S")
backup_file = backup_dir / f"edgesentinel_{ts}.db"

src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
dst = sqlite3.connect(str(backup_file))
with dst:
    src.backup(dst, pages=100)
dst.close()
src.close()

# Verify backup integrity
chk = sqlite3.connect(str(backup_file))
cur = chk.cursor()
cur.execute("PRAGMA integrity_check;")
res = cur.fetchall()
chk.close()

backup_file.chmod(0o640)
print(f"[OK] Backup created: {backup_file} (Integrity: {res})")
EOF
```

### Verified Production Backup
- **Location**: `/var/lib/edgesentinel/backups/edgesentinel_20261020_232048.db`
- **File Size**: `11.09 MB`
- **Integrity**: `[('ok',)]`
- **Permissions**: `0640` (`edgesentinel:edgesentinel`)

---

## 3. Isolated Restore Drill Procedure

> [!IMPORTANT]
> **Safety Rule**: Never overwrite the active production database during validation. Always restore to a temporary isolated path to confirm schema and record integrity first.

### Step 1: Copy to Isolated Staging Directory
```bash
RESTORE_TMP=$(mktemp -d /tmp/es_restore_XXXXXX)
sudo cp /var/lib/edgesentinel/backups/edgesentinel_20261020_232048.db "${RESTORE_TMP}/edgesentinel_restored.db"
```

### Step 2: Validate Database Integrity and Tables
```bash
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/python3 - << EOF
import sqlite3

db_path = "${RESTORE_TMP}/edgesentinel_restored.db"
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# 1. Integrity check
cur.execute("PRAGMA integrity_check;")
print("Integrity Check:", cur.fetchall())

# 2. Table row counts
for table in ['events', 'alerts', 'devices', 'flows', 'schema_version']:
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    print(f"Table {table}: {cur.fetchone()[0]} records")

conn.close()
EOF
```

### Step 3: Verify Application Adapter Compatibility
```bash
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/python3 - << EOF
from edgesentinel.storage.database import Database
db = Database("${RESTORE_TMP}/edgesentinel_restored.db")
print("Adapter Stats:", db.get_stats())
print("Events Query:", len(db.get_events(limit=5)))
print("Alerts Query:", len(db.get_alerts(limit=5)))
print("Devices Query:", len(db.get_devices()))
EOF
```

### Step 4: Clean Up Temporary Staging Directory
```bash
sudo rm -rf "${RESTORE_TMP}"
```

---

## 4. Production Disaster Recovery Procedure

If the active SQLite database ever encounters severe corruption or disk errors:

1. **Stop EdgeSentinel service**:
   ```bash
   sudo systemctl stop edgesentinel.service
   ```
2. **Move damaged database to isolation**:
   ```bash
   sudo mv /var/lib/edgesentinel/edgesentinel.db /var/lib/edgesentinel/edgesentinel_corrupted_$(date +%Y%m%d).db
   sudo rm -f /var/lib/edgesentinel/edgesentinel.db-wal /var/lib/edgesentinel/edgesentinel.db-shm
   ```
3. **Restore verified backup**:
   ```bash
   sudo cp /var/lib/edgesentinel/backups/edgesentinel_20261020_232048.db /var/lib/edgesentinel/edgesentinel.db
   sudo chown edgesentinel:edgesentinel /var/lib/edgesentinel/edgesentinel.db
   sudo chmod 640 /var/lib/edgesentinel/edgesentinel.db
   ```
4. **Verify integrity**:
   ```bash
   sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check
   ```
5. **Start service**:
   ```bash
   sudo systemctl start edgesentinel.service
   sudo systemctl status edgesentinel.service --no-pager
   ```

---

## 5. Retention and Maintenance Commands

To prune expired records older than the configured `retention_days` (default 7 days):

```bash
# Verify integrity and execute retention cleanup:
sudo -u edgesentinel /opt/edgesentinel/.venv/bin/edgesentinel --config /etc/edgesentinel/config.yaml db-check --cleanup
```
