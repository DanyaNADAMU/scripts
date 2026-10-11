# scripts

Centralized repository of automation utilities, server administration tools, workstation workflows, and cryptographic media attestation scripts for the `nada.mu` ecosystem.

All commits are cryptographically signed with SSH Ed25519 (`git@nada.mu`) and anchored into the Bitcoin blockchain via OpenTimestamps (`git-ots`).

---

## Directory Structure & Architecture

```text
scripts/
├── .github/workflows/       # CI & OpenTimestamps blockchain anchoring
├── .githooks/               # Git post-commit & pre-push hooks
├── .allowed_signers         # Canonical trusted SSH commit signers
├── SECURITY.md              # Security policy & disclosure guidelines
├── manifest.txt             # Single source of truth for all declared utilities
├── scripts                  # Unified CLI manager (install, update, list, uninstall)
├── install.sh               # Bootstrap launcher (local & curl | bash)
├── README.md                # Repository index & documentation
│
├── docs/                    # Documentation & man pages
│   ├── STANDARDS.md         # Engineering & documentation standards
│   └── man/man1/            # Troff Linux man pages (setup-user.1, scripts.1)
│
├── completions/             # Shell tab-completions
│   ├── bash/                # Bash completions
│   └── zsh/                 # Zsh completions
│
├── server/                  # Server-side administration & provisioning
│   ├── setup_user.sh        # Linux user provisioning with rootless Podman
│   └── backup_seafile.sh    # Resilient encrypted Seafile to Google Drive backup

│
├── desktop/                 # Workstation & desktop environment scripts
│   └── backup_seadrive.sh   # Automated encrypted SeaDrive to Google Drive backup
│
└── media/                   # Cryptographic media & attestation tools
    └── sign_image.py        # C2PA manifest signing & invisible watermarking
```

---

## Quick Start & Installation

### Option 1: Standalone Install via `curl | bash` (No git clone needed)
Ideal for fresh servers or remote workstations. Installs all utilities automatically without interactive prompts:

```bash
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | bash
```

**Zero-Prompt Defaults:**
* **Scope:** Automatically targets user space (`~/.local/bin`, no sudo required). If executed by `root`, automatically targets system space (`/usr/local/bin`).
* **Category:** Synchronizes `all` declared utilities.
* **Displays:** Prints a clean summary table of installed utilities, categories, and descriptions.

#### Customizing Installation:
```bash
# Install server utilities only to ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | bash -s -- --category server

# Force system-wide installation
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | sudo bash -s -- --scope system
```

---

### Option 2: Developer Workflow (Cloned Repository)
For developing and contributing to scripts:

```bash
# 1. Clone into standard projects directory
git clone https://github.com/DanyaNADAMU/scripts.git ~/projects/scripts
cd ~/projects/scripts

# 2. Link utilities into ~/.local/bin (symlinks allow live edits)
./scripts update
```

Ensure `~/.local/bin` is in your `$PATH` (in `~/.zshrc` or `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Management via the `scripts` Command

Once installed, the `scripts` manager is available anywhere in your terminal:

```bash
scripts update               # Pull upstream updates and sync all utilities (default: all)
scripts list                 # View all declared utilities and installation status
scripts autoupdate status    # Check status of automated update hooks (APT)
scripts uninstall            # Cleanly remove all utilities, man pages, and completions
scripts --help               # View command options and help
```

### Transparent Updates & Scope Protection
* **Automatic Synchronization:** `scripts update` verifies SHA-256 digests, pulls upstream changes (when inside a git clone), updates binaries, installs completions and man pages, and cleans up deprecated utilities. (Aliases `sync` and `install` are supported).
* **Scope Protection:** If you run `scripts update` and an existing installation is detected with mismatched privileges, `scripts` safely prompts you to choose the desired action rather than creating accidental duplicates.
* **Automated APT Hook:** In system scope (`/usr/local/bin`), `scripts` automatically configures an APT hook (`/etc/apt/apt.conf.d/99scripts`) so that utilities stay continuously up-to-date whenever `apt update` or `apt upgrade` runs. Manage with `sudo scripts autoupdate [status|enable|disable]`.

---

## Documentation & Manual Pages

Every utility provides multi-level documentation:
1. **Interactive CLI Help:** Run `<command> --help` or `<command> -h` for quick flags and usage.
2. **Linux Man Pages:** Installed automatically into `~/.local/share/man/man1/` or `/usr/local/share/man/man1/`:
   ```bash
   man setup-user
   man scripts
   ```
3. **Repository Specifications:** See [`docs/STANDARDS.md`](docs/STANDARDS.md) for detailed coding rules.

---

## Shell Completions (Tab Key)

Tab completion for command names works out-of-the-box in all shells (`sh`, `bash`, `zsh`, `fish`) because binaries live in `$PATH`.

Rich argument and flag completions (`setup-user --<Tab>`, `scripts <Tab>`) are installed automatically for:
* **Bash:** Installed to `~/.local/share/bash-completion/completions/` (or `/usr/share/bash-completion/completions/`)
* **Zsh:** Installed to `~/.local/share/zsh/site-functions/` (or `/usr/local/share/zsh/site-functions/`)

---

## Script Catalog

| Command | Source Path | Category | Description | Runtime / Dependencies |
| :--- | :--- | :--- | :--- | :--- |
| `scripts` | `scripts` | **Manager** | CLI package manager for the scripts ecosystem. | Bash |
| `setup-user` | `server/setup_user.sh` | **Server** | Provisions a new Linux user with Zsh, SSH keys, lingering, and rootless Podman. | Bash, `systemd`, `podman` |
| `backup-seafile` | `server/backup_seafile.sh` | **Server** | Automated encrypted incremental backup from Seafile (WebDAV/FUSE) to Google Drive. | Bash, `rclone`, `systemd` |
| `backup-seadrive` | `desktop/backup_seadrive.sh` | **Desktop** | Automated encrypted incremental backup from SeaDrive to Google Drive via Rclone. | Bash, `rclone`, `systemd` |
| `sign-image` | `media/sign_image.py` | **Media** | Signs images with C2PA manifests, DWT steganographic marks, and OpenTimestamps. | Python $\ge$ 3.11, `uv` |

