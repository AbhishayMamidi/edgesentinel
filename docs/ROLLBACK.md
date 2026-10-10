# EdgeSentinel Rollback & Recovery Runbook

This document defines the procedure for stopping, rolling back, restoring, and cleanly uninstalling EdgeSentinel on Linux / Raspberry Pi OS installations.

---

## 1. Immediate Service Emergency Stop

If the service exhibits abnormal resource consumption, service conflicts, or network interference, stop it immediately:

```bash
# Gracefully stop the systemd service
sudo systemctl stop edgesentinel.service

# Verify the process is stopped
sudo systemctl is-active edgesentinel.service
# Expected output: inactive
```

*Note: EdgeSentinel performs passive network capture only and never alters kernel firewall rules. Stopping the service immediately terminates all packet capture without affecting host routing.*

---

## 2. Preserving and Backing Up the Database

Before performing any rollback, upgrade, or uninstallation, back up the SQLite database to preserve historic security alerts and device inventory records:

```bash
# Create a secure backup directory
sudo mkdir -p /var/backups/edgesentinel

# Safely copy database with metadata preserved
sudo cp -p /var/lib/edgesentinel/edgesentinel.db /var/backups/edgesentinel/edgesentinel_backup_$(date +%Y%m%d_%H%M%S).db

# Verify backup integrity
ls -lh /var/backups/edgesentinel/
```

---

## 3. Configuration Rollback

If a configuration change in `/etc/edgesentinel/config.yaml` caused a failure or crash loop:

```bash
# 1. Restore the default example configuration
sudo cp /opt/edgesentinel/config.example.yaml /etc/edgesentinel/config.yaml

# 2. Adjust paths for standard Linux directories
sudo sed -i 's|data/edgesentinel.db|/var/lib/edgesentinel/edgesentinel.db|g' /etc/edgesentinel/config.yaml
sudo sed -i 's|backend: "simulation"|backend: "linux"|g' /etc/edgesentinel/config.yaml

# 3. Ensure proper file ownership
sudo chown edgesentinel:edgesentinel /etc/edgesentinel/config.yaml
sudo chmod 640 /etc/edgesentinel/config.yaml

# 4. Restart service
sudo systemctl restart edgesentinel.service
```

---

## 4. Reverting to Previous Application Version

If a new package release exhibits regression:

```bash
# 1. Stop service
sudo systemctl stop edgesentinel.service

# 2. Re-install previous known-good wheel or release directory
cd /opt/edgesentinel
sudo -u edgesentinel .venv/bin/pip install --force-reinstall /tmp/previous_release/edgesentinel-0.1.0-py3-none-any.whl

# 3. Start service
sudo systemctl start edgesentinel.service
sudo systemctl status edgesentinel.service
```

---

## 5. Clean Uninstallation (Preserving Historical Data)

To remove EdgeSentinel while preserving your security logs, alert databases, and configurations:

```bash
# Execute the uninstallation script
sudo bash /opt/edgesentinel/scripts/uninstall_linux.sh
```

This script:
1. Stops and disables `edgesentinel.service`.
2. Removes `/etc/systemd/system/edgesentinel.service` and reloads systemd.
3. Removes `/opt/edgesentinel` application files and virtual environment.
4. **Preserves** `/var/lib/edgesentinel/` (database) and `/etc/edgesentinel/` (configuration).

---

## 6. Complete Purge (Destructive Cleanup)

If you wish to completely purge all EdgeSentinel data and user accounts:

```bash
# 1. Run standard uninstall
sudo bash /opt/edgesentinel/scripts/uninstall_linux.sh

# 2. Remove data, configurations, and logs
sudo rm -rf /var/lib/edgesentinel /etc/edgesentinel /var/log/edgesentinel /var/backups/edgesentinel

# 3. Remove dedicated service account
sudo userdel edgesentinel || true
```
