# server

Scripts designed for Linux server administration, user management, container daemons (Podman/Docker), systemd units, and network services.

## Contents
* [`setup_user.sh`](./setup_user.sh) — Provision a new Linux user with Zsh, SSH keys, lingering, and rootless Podman.
* [`backup_seafile.sh`](./backup_seafile.sh) — Resilient encrypted incremental backup from Seafile (via WebDAV or local mount) to Google Drive via Rclone.

---

## Utilities

### `backup-seafile`
Automated, encrypted incremental backup from a Seafile instance directly to Google Drive (`gdrive-crypt:SeafileBackup`) using Rclone and systemd timers.

#### Why on the Server?
* **Centralized Credentials:** Google Drive authentication (e.g. Service Account JSON) lives strictly on a single backup machine rather than scattered across nodes.
* **Readable Files, Not Raw Blocks:** Instead of syncing fragmented Seafile/MinIO raw chunk blocks and MySQL database dumps, `backup-seafile` exports clear, human-readable directory trees. Disaster recovery requires only `rclone copy` without needing a running Seafile or MinIO stack.
* **Mountless Headless Streaming (WebDAV):** Connects natively via Seafile's built-in WebDAV (`seafdav`). No FUSE kernel mounts or local disk cache thrashing required. Files are streamed and encrypted on-the-fly in RAM.
* **FUSE / Local Mount Support:** Alternatively supports local paths (e.g., `seaf-fuse.sh start /mnt/seafile-fuse`).

#### Usage

```bash
# Check prerequisites, status, and last backup timestamp
backup-seafile --status

# Test without writing to remote
backup-seafile --dry-run

# Run immediate backup manually
backup-seafile --force

# Install systemd timer (system-wide if root, user-level if non-root)
backup-seafile --setup-timer

# Remove timer and service
backup-seafile --remove-timer
```

#### Configuration (`/etc/seafile-backup.conf` or `~/.config/seafile-backup.conf`)

You can customize the backup by placing a config file at `/etc/seafile-backup.conf`:

```bash
# Seafile WebDAV remote or local path
SEAFILE_SOURCE="seafile-dav:"

# Rclone crypt remote destination
RCLONE_DEST="gdrive-crypt:SeafileBackup"

# Optional path to rclone.conf (e.g., if using a dedicated config)
# RCLONE_CONFIG_PATH="/etc/rclone/rclone.conf"

# Cooldown between runs (hours)
BACKUP_INTERVAL_HOURS=20

# Systemd poll interval
CHECK_INTERVAL="15m"

# Optional webhook for alerts (Slack, Discord, Telegram bot, or generic JSON endpoint)
# ALERT_WEBHOOK_URL="https://example.com/webhook"
```

#### Setting up Seafile WebDAV in Rclone

In `rclone config` (or `/etc/rclone/rclone.conf`):

```ini
[seafile-dav]
type = webdav
url = https://seafile.example.com/seafdav
vendor = other
user = admin@example.com
pass = <encrypted_password_via_rclone_obscure>

[gdrive]
type = drive
scope = drive
service_account_file = /etc/rclone/sa.json

[gdrive-crypt]
type = crypt
remote = gdrive:SeafileBackup
filename_encryption = standard
directory_name_encryption = true
password = <encrypted_password>
```
