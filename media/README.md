# media

Cryptographic media processing, attestation, and verification utilities for the `nada.mu` ecosystem.

## Utilities

### [`sign_image.py`](./sign_image.py) (`sign-image`)
Signs digital images (PNG, JPEG, WebP, AVIF, SVG, TIFF) with **C2PA Content Credentials** (Level 1 attestation).
Cryptographically embeds author declarations, policy links, and pixel hash signatures.

#### Key Features:
* **Tamper-Evident:** Validates pixel hash integrity; any altered pixel flags the asset as `Invalid`.
* **Zero Config:** Automatically generates and persists compliant ECDSA P-256 (ES256) X.509 certificate chains in `~/.config/nada/c2pa/`.
* **Universal Runner:** Runs seamlessly via `uv run` with PEP 723 inline dependency isolation.

#### Usage:
```bash
# Sign an image (creates <name>_signed.<ext>)
sign-image sign banner.png

# Sign with custom title, author, and in-place overwrite
sign-image sign --in-place -t "Logo 2026" -a "Danya <git@nada.mu>" logo.png

# Verify and inspect provenance passport
sign-image verify banner_signed.png

# Export complete raw manifest in JSON
sign-image verify --json banner_signed.png
```
