# desktop

Scripts designed for local workstations, laptop environments, window managers (Wayland, Niri), audio systems, display configuration, and desktop workflows.

## Utilities

### `backup-seadrive`
Resilient, encrypted incremental backup from a local SeaDrive mount (`~/SeaDrive/My Libraries`) directly to Google Drive (`gdrive-crypt:SeafileBackup`) using Rclone and systemd user timers.

* **Zero-Knowledge Encryption:** Encrypted on-the-fly in RAM with XSalsa20 + Poly1305 before transmission.
* **Offline Boot Resilience:** Automatically defers execution when booting without internet or before SeaDrive is mounted, retrying every 15 minutes until connectivity is established.
* **Smart Daily Throttling:** Maintains state in `~/.local/state/scripts/backup-seadrive.last` to ensure backups run once per day (~20 hour cooldown) without duplicate runs or CPU waste.
* **Zero-Data-Loss Safety:** Verifies source directory existence and non-empty status before initiating sync to prevent accidental deletion on the remote.

```bash
# Set up resilient systemd user timer
backup-seadrive --setup-timer

# Check backup status, cooldown, and prerequisites
backup-seadrive --status

# Force immediate manual backup
backup-seadrive --force
```
