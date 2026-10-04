# Scripts Engineering Standards

This document establishes the mandatory architectural and coding standards for all utilities maintained in the `scripts` repository.

---

## 1. Directory Structure & Organization

All scripts must reside in one of the approved category directories:

* **`server/`** — Server administration, provisioning, systemd units, network routing, and container daemons.
* **`desktop/`** — Workstation utilities, display managers (Wayland, Niri), audio systems, and local workflows.
* **`media/`** — Cryptographic attestation (C2PA), steganographic watermarking, media transformation, and timestamping.
* **`common/`** — Shared helper libraries (sourced, not directly executed).

Files must use single-word or snake_case naming for sources (`setup_user.sh`, `sign_image.py`), while installed command names must use kebab-case (`setup-user`, `sign-image`).

---

## 2. Mandatory Metadata Header

Every script must begin with a standardized header block containing:
1. Script file name.
2. Category name.
3. Concise one-line description.
4. Target operating system/environment.
5. Runtime dependencies.
6. Usage synopsis.

### Bash Example:
```bash
#!/usr/bin/env bash
# ==============================================================================
# Script:      setup_user.sh
# Category:    server
# Description: Provisions a new Linux user with Zsh, SSH keys, and rootless Podman.
# Target:      Linux server (systemd)
# Requires:    bash, systemd, podman (optional)
# Usage:       sudo ./setup_user.sh [--help]
# ==============================================================================
```

### Python Example:
```python
#!/usr/bin/env python3
"""
Script:      sign_image.py
Category:    media
Description: Embeds C2PA cryptographic manifests and invisible DWT watermarks.
Target:      Cross-platform (Linux / macOS)
Requires:    python >= 3.11, uv
Usage:       uv run sign_image.py [options] <input> <output>
"""
```

---

## 3. Mandatory CLI Self-Documentation (`--help`)

Every script must implement `-h` and `--help` flags:
* Must output a clear usage synopsis, list of arguments/flags, and examples.
* Must exit with status code `0`.
* In Bash scripts, use a `show_help()` function and `getopts` or a `case "$1"` parser.
* In Python scripts, use standard `argparse` or `click`.

---

## 4. Error Handling & Robustness

### Shell Scripts:
* Must use strict mode:
  ```bash
  set -euo pipefail
  ```
  *(Or `set -e` if pipefail/nounset is incompatible with specific external environments).*
* Must validate required inputs and tool availability (`command -v <tool>`).
* Must provide clear error messages to `stderr` (`>&2 echo "Error: ..."`).
* Must use meaningful exit codes (`0` for success, non-zero for failures).

### Python Scripts:
* Must catch anticipated exceptions gracefully and output human-readable messages.
* Must avoid polluting the system Python environment; scripts should specify dependencies in PEP 723 inline script metadata for seamless execution via `uv run`.

---

## 5. Documentation, Man Pages & Completions

For every user-facing utility added to the repository:
1. **Manifest Entry:** An entry must be added to `manifest.txt`:
   ```text
   <path_in_repo>:<installed_name>:<category>:<one_line_description>
   ```
2. **Man Page:** A corresponding troff manual page should be placed in `docs/man/man1/<installed_name>.1`.
3. **Shell Completions:** Completions should be added to `completions/bash/<installed_name>` and `completions/zsh/_<installed_name>`.
