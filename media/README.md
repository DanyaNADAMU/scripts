# media

Cryptographic media processing, attestation, and verification utilities for the `nada.mu` ecosystem.

## Utilities

### [`sign_image.py`](./sign_image.py) (`sign-image`)
Signs digital images (PNG, JPEG, WebP, AVIF, SVG, TIFF) with **C2PA Content Credentials**, invisible **DWT-DCT steganographic watermarks**, and anchors them in the Bitcoin blockchain via **OpenTimestamps** (`.ots`).

#### Key Features:
* **Multi-Layer Attestation:** C2PA Level 1 provenance manifest + invisible frequency-domain watermark + OpenTimestamps proof.
* **Zero-Disk Bitwarden Integration:** Load signing keys directly from Bitwarden vault into RAM (`--bw`) with 0 secret bytes written to disk.
* **Automated OTS Upgrades:** Built-in systemd user timer automation (`--setup-timer`) and recursive directory upgrading.
* **Universal Runner:** Runs seamlessly via `uv run` with PEP 723 inline dependency isolation.

#### Usage:
```bash
# Sign an image (C2PA + Watermark + OpenTimestamps)
sign-image sign -a "Danya <git@nada.mu>" --stamp logo.png

# Sign strictly in RAM using Bitwarden credentials
sign-image sign --bw-item c2pa-signer --stamp logo.png

# Verify provenance, watermark, and Bitcoin timestamp
sign-image verify logo_signed.png

# Recursively upgrade pending .ots files in a directory
sign-image stamp --upgrade ~/SeaDrive/"My Libraries"/Icons

# Install automated systemd timer for periodic .ots upgrades
sign-image stamp --setup-timer ~/SeaDrive/"My Libraries"/Icons --timer-interval 2h
```

---

### [`build_image.py`](./build_image.py) (`build-image`)
Structured media asset pipeline for icons, logos, and UI graphics across versioned releases.

#### Standard Directory Hierarchy:
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

# Optional Segregated Proofs Archive (<Icons-Proofs>/ or $SEADRIVE_PROOFS):
<Icons-Proofs>/
└── <asset_name>/
    ├── v1/
    │   ├── 01_source/raw/duck.xcf.ots
    │   ├── 01_source/master/duck_crop_master.png.ots
    │   └── 02_signed/duck_1024_signed.png.ots
    └── latest -> v1/
```

#### Key Features:
* **Source Protection:** Immutable original canvas and master files locked with `chmod 0444` and anchored in Bitcoin.
* **Segregated Proofs Archive:** Isolate `.ots` files into an independent repository (`--proofs-dir` / `$SEADRIVE_PROOFS`). This allows running `seaf-cli` and automated Bitcoin timers on remote servers with 100% zero-media exposure (only 1 MB of Merkle trees synced, zero images on server).
* **Showcase Attestation:** 1024x1024 release signed cryptographically via C2PA, watermark, and OTS.
* **Clean Distribution:** Multi-scale WebP/PNG downscales and multi-layer ICO without metadata bloating.
* **Non-Blocking Audit:** Full diagnostic pass (`build-image audit`) reporting all hash mismatches, missing proofs, and orphaned files at once.
* **Atomic Versioning:** Manages `latest` symlink and version upgrades without cross-version contamination.

#### Usage:
```bash
# Initialize standard folder scaffolding for a new asset version
build-image init duck v1

# Drop files into 01_source/ and build with auto-detection
build-image build duck v1

# Build with explicit source paths
build-image build duck v1 --master duck_crop.png --raw duck.xcf

# Build with Bitwarden in-memory signing
build-image build duck v2 --master duck_crop.png --bw-item c2pa-signer

# Run full non-blocking integrity audit across all assets
build-image audit

# Recursively upgrade OTS proofs for a specific asset version
build-image upgrade duck v1

# List managed assets and versions
build-image list
```
