# media

Unified cryptographic media processing, C2PA attestation, invisible watermarking, Bitcoin blockchain anchoring, and versioned asset packaging for the `nada.mu` ecosystem.

## Overview

`media` replaces and unifies separate signing and asset building tools into a single, cohesive command-line utility.

### Core Capabilities:
* **Triple-Layer Attestation:** C2PA Level 1 provenance manifest + invisible frequency-domain watermark (DWT-DCT) + OpenTimestamps proof.
* **Asset Pipeline:** Multi-tier design asset compiler (`source` -> `signed` -> `dist`), aspect-ratio auto-detection (1:1, 16:9, 4:3, etc.), customizable `manifest.json`, multi-scale WebP/PNG rendering, and multi-layer `favicon.ico`.
* **Zero-Disk Bitwarden Integration:** Load private keys and certificate chains directly from Bitwarden into RAM (`--bw`) with 0 secret bytes written to disk.
* **Segregated Proofs Architecture:** Automatically isolates `.ots` files into a dedicated library (`Icons-Proofs` / `SEAFILE_PROOFS`), allowing remote servers to sync and upgrade proofs with 100% zero-media exposure.
* **Non-Blocking Audit:** Diagnostic pass (`media audit`) reporting all SHA-256 mismatches, missing proofs, and orphaned files in a unified report.
* **Automated Bitcoin Timers:** Built-in systemd user timer automation (`media timer setup`).

---

## Directory Hierarchy

```text
<Icons-Library>/
└── <asset_name>/
    ├── manifest.json         # (Optional) shared asset manifest
    ├── v1/
    │   ├── manifest.json     # Target resolutions, signed showcase scales, aspect ratio & favicon config
    │   ├── source/
    │   │   ├── raw/          # duck.xcf (0444 + optional .ots)
    │   │   └── master/       # duck_master.png (0444 + optional .ots)
    │   ├── signed/
    │   │   └── duck_1024_signed.png # C2PA + Watermark + optional .ots (1024, 2048, or custom scales)
    │   └── dist/
    │       ├── favicon.ico          # Multi-layer 16..256 container (for square assets)
    │       ├── duck_512.webp / .png # Clean, zero overhead
    │       ├── duck_256.webp / .png
    │       └── ... (128, 64, 32 or 1080p, 720p for 16:9)
    └── latest -> v1/

# Segregated Proofs Archive (<Icons-Proofs>/ or $SEAFILE_PROOFS):
<Icons-Proofs>/
└── <asset_name>/
    ├── v1/
    │   ├── source/raw/duck.xcf.ots
    │   ├── source/master/duck_master.png.ots
    │   └── signed/duck_1024_signed.png.ots
    └── latest -> v1/
```

---

## Command Reference

### Asset Pipeline

```bash
# Initialize folder scaffolding and default manifest.json for a new asset version
media init duck v1

# Auto-detect source files from source/ and compile release
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

# Generate new C2PA credentials directly into Bitwarden vault (CLI RAM mode)
media keys gen -d nada.mu --bw c2pa-signer

# Bind C2PA & watermark secret to Bitwarden Desktop SSH Agent (Zero-Knowledge, Zero-Disk)
media keys gen --agent --key-name "berg-nadamuanalytics"
media keys use agent

# Build releases using Bitwarden Desktop SSH Agent
media build duck v1 --agent

# Verify image with watermark secret derived via SSH Agent
media verify duck_1024_signed.png --agent
```
