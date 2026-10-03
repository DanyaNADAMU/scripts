# scripts

Centralized repository of automation utilities, server administration tools, workstation workflows, and cryptographic media attestation scripts for the `nada.mu` ecosystem.

All commits are cryptographically signed with SSH Ed25519 (`git@nada.mu`) and anchored into the Bitcoin blockchain via OpenTimestamps (`git-ots`).

---

## Directory Structure & Categories

```text
scripts/
├── .github/workflows/       # CI & OpenTimestamps blockchain anchoring
├── .githooks/               # Git post-commit & pre-push hooks
├── .allowed_signers         # Canonical trusted SSH commit signers
├── SECURITY.md              # Security policy & disclosure guidelines
├── install.sh               # Symlink installer to ~/.local/bin
├── README.md                # Repository index & documentation
│
├── server/                  # Server-side administration & provisioning
│   └── setup_user.sh        # Linux user provisioning with rootless Podman
│
├── desktop/                 # Workstation & desktop environment scripts
│   └── (Wayland, Niri, audio, screenshot tools)
│
└── media/                   # Cryptographic media & attestation tools
    └── sign_image.py        # C2PA manifest signing & invisible watermarking
```

---

## Script Catalog

| Command | Source Path | Category | Description | Runtime / Dependencies |
| :--- | :--- | :--- | :--- | :--- |
| `setup-user` | `server/setup_user.sh` | **Server** | Provisions a new Linux user with Zsh, SSH keys, lingering, and rootless Podman. | Bash, `systemd`, `podman` |
| `sign-image` | `media/sign_image.py` | **Media** | Signs images with C2PA manifests, DWT steganographic marks, and OpenTimestamps. | Python $\ge$ 3.11, `uv` |

---

## Standards & Documentation Policy

To prevent "mystery scripts" that become unmaintainable over time, every script in this repository must adhere to the following rules:

### 1. Mandatory Metadata Header
Every script must begin with a standardized metadata block specifying its purpose, target environment, and usage:

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script:      example.sh
# Category:    server | desktop | media
# Description: One-line concise explanation of what this script does.
# Target:      Linux server / Desktop / Cross-platform
# Requires:    package1, package2 (or uv/python packages)
# Usage:       ./example.sh [options]
# ==============================================================================
```

### 2. Mandatory `--help` Support
Every script must support `-h` and `--help` flags:
* **Shell scripts:** Must implement a `show_help()` function and exit cleanly with status code `0`.
* **Python scripts:** Must use `argparse` or `click` to provide self-documenting CLI flags with descriptions and default values.

### 3. Language & Runtime Guidelines
* **Bash (`.sh`):** Used exclusively for lightweight system orchestration, OS provisioning, and invoking native binaries. Must enable strict error handling (`set -e` or `set -euo pipefail`).
* **Python (`.py`):** Used for complex logic, media processing, cryptographic operations, and APIs. Python scripts should be runnable via `uv run` to ensure isolated, reproducible dependency management without polluting system packages.

---

## Installation & Deployment

### Recommended Location
The canonical location for this repository on any host (server `berg`, workstation `danya`) is:
```text
~/projects/scripts
```

### Exposing Commands to `$PATH`
Executable scripts should **never** be copied directly into `/usr/local/bin` because it breaks Git tracking. Instead, symlink them into `~/.local/bin` using the included installer:

```bash
# Clone the repository
git clone https://github.com/DanyaNADAMU/scripts.git ~/projects/scripts
cd ~/projects/scripts

# Install symlinks into ~/.local/bin
./install.sh
```

Ensure `~/.local/bin` is in your shell's `$PATH` (in `~/.zshrc` or `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Once installed, scripts can be run directly from any directory:
```bash
setup-user --help
sign-image --help
```

---

## Updates & Maintenance

To keep scripts updated across machines, add an alias to your shell configuration:

```bash
# Add to ~/.zshrc or ~/.bashrc:
alias scripts-update="git -C ~/projects/scripts pull --ff-only"
```

Then run `scripts-update` anytime to pull the latest changes.
