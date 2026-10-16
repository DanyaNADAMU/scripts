# server

Scripts designed for Linux server administration, user management, container daemons (Podman/Docker), systemd units, and network services.

## Contents
* [`setup_user.sh`](./setup_user.sh) — Provision a new Linux user with Zsh, SSH keys, lingering, and rootless Podman.
* [`backup_seafile.sh`](./backup_seafile.sh) — Resilient encrypted incremental backup from Seafile (via WebDAV or local mount) to Google Drive via Rclone.
* [`languagetool_portal.py`](./languagetool_portal.py) — Self-service token portal for LanguageTool integrated with Authentik Forward Auth.

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

---

### `languagetool-portal`
Lightweight, zero-dependency self-service token portal for LanguageTool and Authentik Forward Auth.

Generates and rotates personal LanguageTool API tokens for Authentik users, updating `users.txt` dynamically without requiring server or container restarts.

#### Features
* **Zero Dependencies:** Written purely with the standard Python 3.10+ library (`http.server`, `secrets`, `os`, `tempfile`, `fcntl`, `threading`).
* **Loopback & Forward Auth:** Listens on `127.0.0.1:8012` by default. Authenticates requests via HAProxy's `X-authentik-username` header and rejects direct non-proxy access with `401 Unauthorized`.
* **Reliable Concurrency:** Protected with thread locks and `fcntl.flock` file locking to guarantee data integrity across concurrent requests.
* **Offline UI:** Dracula/GitHub Dark themed UI with embedded SVGs, quick-copy buttons (`Copied!`), confirmation dialogs, and Obsidian setup steps.
* **Monitoring:** Provides `GET /healthz` endpoint returning `200 OK` for HAProxy health checks without authentication.

#### Usage

```bash
# Run interactively (default: 127.0.0.1:8012, users file: ~/stacks/languagetool/data/users.txt)
languagetool-portal

# Run as unprivileged user (e.g. 'apps') with custom path
languagetool-portal --users-file /home/apps/stacks/languagetool/data/users.txt

# Check HTTP health and systemd status
languagetool-portal --status

# Install and start as a systemd user service (for current user, e.g. apps)
languagetool-portal --setup-service

# Or install system-wide running as user 'apps' (requires sudo)
sudo languagetool-portal --setup-service --system --run-as apps

# Remove systemd service
languagetool-portal --remove-service
```

#### Docker & Podman Quadlet Inode Pitfall

LanguageTool monitors `users.txt` via `file.lastModified()` and updates its in-memory user table on the fly when the file changes.

When deploying LanguageTool in containers (Podman/Docker), take note of how files are mounted:

##### Option 1 (Recommended): Mount the directory
Mount the parent directory rather than the single file:
```ini
# Quadlet container file (.container)
Volume=%h/stacks/languagetool/data:/LanguageTool/data:ro,Z
```
And in `config.properties`:
```properties
passwortLoginAccessListPath=/LanguageTool/data/users.txt
```
*Why this is best:* The portal's default atomic replacement (`tempfile` + `os.replace`) changes the file's inode. When the parent directory is mounted, Linux VFS notifies the container immediately of the new file version and timestamp.

##### Option 2: Single-file mount with `--in-place`
If you bind-mount the individual file directly:
```ini
Volume=%h/stacks/languagetool/data/users.txt:/LanguageTool/users.txt:ro,Z
```
A Linux bind mount pins the container to the **original inode**. If `os.replace` creates a new inode, the container will remain pinned to the unlinked old inode.
To solve this, run the portal with `--in-place` (or `LT_IN_PLACE=true`):
```bash
languagetool-portal --in-place
```
This forces direct in-place updates via `open(..., "r+")` and `fcntl.flock`, maintaining the original inode.

#### HAProxy Forward Auth Configuration Example

```haproxy
frontend fe_languagetool
    bind :443 ssl crt /etc/ssl/certs/lt.nada.mu.pem
    acl is_portal path_beg /portal

    # Check authentication with Authentik forward auth endpoint
    http-request lua.authentik-auth if is_portal

    # Forward to token portal backend
    use_backend be_lt_portal if is_portal
    default_backend be_lt_api

backend be_lt_portal
    http-request set-header X-Forwarded-Host %[req.hdr(Host)]
    server lt_portal 127.0.0.1:8012 check inter 5s

backend be_lt_api
    server lt_app 127.0.0.1:8010 check inter 5s
```

