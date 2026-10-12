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

---

### `keylight`
Cyclic keyboard RGB backlight profile switcher using OpenRGB. Specially tailored for MSI Mystic Light controllers (MS-1565).

* **Hardware Quirk Workaround:** MSI MS-1565 laptop controllers are write-only (no hardware readback) and expose the 4 keyboard zones as mutually exclusive driver *modes* (`Static zone 1` .. `Static zone 4`) instead of zones. Because OpenRGB `.json` profile files only store a single active mode per device, standard profile loading fails and blanks the keyboard. `keylight` issues direct mode commands to bypass this driver flaw.
* **Stateful Cycling:** Maintains the active state in `${XDG_CACHE_HOME:-$HOME/.cache}/keylight-current-profile`, allowing rapid cycling across presets via a single hotkey.
* **Presets:**
  * `off`: Complete backlight shutoff.
  * `night`: 4-zone emerald-to-olive forest gradient at 40% brightness (`#006644`, `#006626`, `#1E6610`, `#386608`).
  * `cyan`: Static neon cyan illumination at 40% brightness (`#00FFFF`).
  * `white`: Static soft white illumination at 35% brightness (`#FFFFFF`).

```bash
# Cycle to the next profile in sequence (off -> night -> cyan -> white)
keylight

# Switch directly to a specific profile
keylight night

# View currently active profile
keylight --current

# List available profiles with active indicator
keylight --list
```

#### Window Manager Keybinding Example (Niri / Sway / Hyprland)
Bind a keyboard shortcut (e.g., `Fn + F8` or `Mod + Shift + B`) to `keylight` in your compositor configuration:
```kdl
// Niri example (~/.config/niri/config.kdl)
binds {
    Mod+Shift+B { spawn "keylight"; }
}
```
