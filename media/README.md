# media

Unified cryptographic media processing, C2PA attestation, invisible watermarking, Bitcoin blockchain anchoring, and versioned asset packaging for the `nada.mu` ecosystem.

## Overview

`media` replaces and unifies separate signing and asset building tools into a single, cohesive command-line utility.

### Core Capabilities:
* **Triple-Layer Attestation:** C2PA Level 1 provenance manifest + invisible frequency-domain watermark (DWT-DCT) + OpenTimestamps proof.
* **Asset Pipeline:** Multi-tier design asset compiler (`01_source` -> `02_signed` -> `03_dist`), multi-scale WebP/PNG rendering, and multi-layer `favicon.ico` (16..256 px).
* **Zero-Disk Bitwarden Integration:** Load private keys and certificate chains directly from Bitwarden into RAM (`--bw`) with 0 secret bytes written to disk.
* **Segregated Proofs Architecture:** Automatically isolates `.ots` files into a dedicated library (`Icons-Proofs` / `SEAFILE_PROOFS`), allowing remote servers to sync and upgrade proofs with 100% zero-media exposure.
* **Non-Blocking Audit:** Diagnostic pass (`media audit`) reporting all SHA-256 mismatches, missing proofs, and orphaned files in a unified report.
* **Automated Bitcoin Timers:** Built-in systemd user timer automation (`media timer setup`).

---

## Directory Hierarchy

```text
<Icons-Library>/
└── <asset_name>/
    ├── v1/
    │   ├── 01_source/
    │   │   ├── raw/      # duck.xcf (0444 + optional .ots)
    │   │   └── master/   # duck_crop_master.png (0444 + optional .ots)
    │   ├── 02_signed/
    │   │   └── duck_1024_signed.png (C2PA + Watermark + optional .ots)
    │   └── 03_dist/
    │       ├── favicon.ico          # Multi-layer 16..256 container
    │       ├── duck_512.webp / .png # Clean, zero overhead
    │       ├── duck_256.webp / .png
    │       └── ... (128, 64, 32)
    └── latest -> v1/

# Segregated Proofs Archive (<Icons-Proofs>/ or $SEAFILE_PROOFS):
<Icons-Proofs>/
└── <asset_name>/
    ├── v1/
    │   ├── 01_source/raw/duck.xcf.ots
    │   ├── 01_source/master/duck_crop_master.png.ots
    │   └── 02_signed/duck_1024_signed.png.ots
    └── latest -> v1/
```

---

## Command Reference

### Asset Pipeline

```bash
# Initialize folder scaffolding for a new asset version
media init duck v1

# Auto-detect source files from 01_source/ and compile release
media build duck v1

# Compile with explicit source paths and Bitwarden signing
media build duck v1 -m master.png -r canvas.xcf --bw

# Run full non-blocking integrity audit across all assets
media audit duck v1
media audit

# List managed assets and active versions
media list

# Recursively upgrade pending OpenTimestamps proofs in Bitcoin
media upgrade duck v1
media upgrade
```

### File Attestation & Verification

```bash
# Sign an individual image (C2PA + Watermark + OpenTimestamps)
media sign --bw --stamp hero.png

# Verify provenance, watermark, and Bitcoin confirmation status
media verify hero_signed.png

# Anchor any arbitrary file in Bitcoin blockchain
media stamp contract.pdf
```

### Automation & Key Management

```bash
# Set up background systemd user timer for periodic OTS upgrades
media timer setup /home/apps/data/Icons-Proofs --interval 2h
media timer status
media timer remove

# Inspect active C2PA certificates
media keys show

# Generate new C2PA credentials directly into Bitwarden vault
media keys gen -d nada.mu --bw c2pa-signer
```
