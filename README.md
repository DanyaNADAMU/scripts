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
│   └── setup_user.sh        # Linux user provisioning with rootless Podman
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
Ideal for fresh servers or remote workstations:

```bash
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | bash
```

The interactive wizard will prompt you:
1. **Scope:** User (`~/.local/bin`, no sudo) or System (`/usr/local/bin`, requires sudo).
2. **Category:** `all`, `server`, `desktop`, or `media`.

#### Unattended / Non-Interactive Install:
```bash
# Install server utilities to ~/.local/bin without prompts
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | bash -s -- --scope user --category server -y

# System-wide installation
curl -fsSL https://raw.githubusercontent.com/DanyaNADAMU/scripts/main/install.sh | sudo bash -s -- --scope system -y
```

---

### Option 2: Developer Workflow (Cloned Repository)
For developing and contributing to scripts:

```bash
# 1. Clone into standard projects directory
git clone https://github.com/DanyaNADAMU/scripts.git ~/projects/scripts
cd ~/projects/scripts

# 2. Link utilities into ~/.local/bin (symlinks allow live edits)
./scripts install --scope user -y
```

Ensure `~/.local/bin` is in your `$PATH` (in `~/.zshrc` or `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Management via the `scripts` Command

Once installed, the `scripts` manager is available anywhere in your terminal:

```bash
scripts list                 # View all declared utilities and installation status
scripts update               # Pull upstream updates and sync files with SHA-256 report
scripts uninstall            # Cleanly remove all utilities, man pages, and completions
scripts --help               # View command options and help
```

### Transparent Updates & Orphan Handling
When running `scripts update`:
* It verifies SHA-256 checksums and reports exactly what changed (`[+] Added`, `[↑] Updated`, `[=] Up to date`).
* If a script was previously installed but was deleted from the upstream repository, `scripts update` warns you and prompts whether you want to clean it up.

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
| `backup-seadrive` | `desktop/backup_seadrive.sh` | **Desktop** | Automated encrypted incremental backup from SeaDrive to Google Drive via Rclone. | Bash, `rclone`, `systemd` |
| `sign-image` | `media/sign_image.py` | **Media** | Signs images with C2PA manifests, DWT steganographic marks, and OpenTimestamps. | Python $\ge$ 3.11, `uv` |
