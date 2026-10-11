#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pillow>=10.0.0",
#     "c2pa-python>=0.38.0",
#     "cryptography>=43.0.0",
#     "numpy>=1.26.0",
#     "pywavelets>=1.6.0",
#     "scipy>=1.13.0",
#     "opentimestamps-client>=0.7.1",
# ]
# ///
# ==============================================================================
# Script:      build_image.py
# Category:    media
# Description: Structured asset pipeline: raw/master segregation, batch audit, C2PA signing & multi-scale dist rendering.
# Target:      Linux / macOS
# Requires:    python >= 3.11, uv
# Usage:       build-image [build|audit|upgrade|list] [options]
# ==============================================================================
from __future__ import annotations

import argparse
import binascii
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from PIL import Image

import otsclient.args
import otsclient.cmds
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import StreamDeserializationContext
from otsclient.cmds import DetachedTimestampFile

# ANSI Colors
C_BLUE = "\033[1;34m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED = "\033[1;31m"
C_CYAN = "\033[1;36m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"

APP_NAME = "build-image"
APP_VERSION = "1.0.0"


def log_info(msg: str) -> None:
    print(f"  {C_BLUE}[i]{C_RESET} {msg}")


def log_ok(msg: str) -> None:
    print(f"  {C_GREEN}[✓]{C_RESET} {msg}")


def log_warn(msg: str) -> None:
    print(f"  {C_YELLOW}[!]{C_RESET} {msg}")


def log_err(msg: str) -> None:
    print(f"  {C_RED}[✗]{C_RESET} {msg}", file=sys.stderr)


def log_head(msg: str) -> None:
    print(f"\n{C_CYAN}==>{C_RESET} {C_BOLD}{msg}{C_RESET}")


def get_default_icons_dir() -> Path:
    """Resolves base directory for asset libraries."""
    for env_var in ("SEAFILE_ICONS", "SEADRIVE_ICONS", "ICONS_DIR"):
        env_dir = os.environ.get(env_var)
        if env_dir:
            return Path(env_dir).expanduser().resolve()

    # Current working directory if named 'Icons' (case-insensitive)
    cwd = Path.cwd().resolve()
    if cwd.name.lower() == "icons":
        return cwd

    # Seafile desktop client local sync directory
    cand_seafile = Path.home() / "Seafile" / "Icons"
    if cand_seafile.is_dir():
        return cand_seafile

    # SeaDrive virtual mount
    cand_seadrive = Path.home() / "SeaDrive" / "My Libraries" / "Icons"
    if cand_seadrive.is_dir():
        return cand_seadrive

    return (Path.home() / ".local" / "share" / "icons-archive").resolve()


def get_default_proofs_dir(icons_dir: Path | None = None) -> Path | None:
    """Resolves base directory for separated OpenTimestamps proofs library."""
    for env_var in ("SEAFILE_PROOFS", "SEADRIVE_PROOFS", "PROOFS_DIR"):
        env_dir = os.environ.get(env_var)
        if env_dir:
            return Path(env_dir).expanduser().resolve()

    # Sibling directory relative to resolved icons directory
    base = icons_dir or get_default_icons_dir()
    if base.is_dir():
        cand_sibling_proofs = base.parent / f"{base.name}-Proofs"
        if cand_sibling_proofs.is_dir():
            return cand_sibling_proofs
        cand_sibling_just_proofs = base.parent / "Proofs"
        if cand_sibling_just_proofs.is_dir():
            return cand_sibling_just_proofs

    # Seafile desktop client local proofs directory
    cand_seafile = Path.home() / "Seafile" / "Icons-Proofs"
    if cand_seafile.is_dir():
        return cand_seafile
    cand_seafile_alt = Path.home() / "Seafile" / "Proofs"
    if cand_seafile_alt.is_dir():
        return cand_seafile_alt

    # SeaDrive virtual mount
    cand_seadrive = Path.home() / "SeaDrive" / "My Libraries" / "Icons-Proofs"
    if cand_seadrive.is_dir():
        return cand_seadrive
    cand_seadrive_alt = Path.home() / "SeaDrive" / "My Libraries" / "Proofs"
    if cand_seadrive_alt.is_dir():
        return cand_seadrive_alt

    return None


def inspect_ots(target_file: Path, ots_path: Path | None = None) -> dict[str, Any] | None:
    """Inspects an OpenTimestamps proof against target file."""
    candidate_ots = ots_path
    if candidate_ots is None:
        p1 = target_file.with_name(f"{target_file.name}.ots")
        p2 = target_file.with_suffix(".ots")
        if p1.is_file():
            candidate_ots = p1
        elif p2.is_file():
            candidate_ots = p2

    if candidate_ots is None or not candidate_ots.is_file():
        return None

    try:
        with open(candidate_ots, "rb") as f:
            ctx = StreamDeserializationContext(f)
            dt = DetachedTimestampFile.deserialize(ctx)

        ots_hash = binascii.hexlify(dt.file_digest).decode()
        algo = getattr(dt.file_hash_op, "HASHLIB_NAME", "sha256")

        if target_file.is_file():
            h = hashlib.new(algo)
            with open(target_file, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_hash = h.hexdigest()
            hash_matches = (ots_hash.lower() == actual_hash.lower())
        else:
            actual_hash = ""
            hash_matches = False

        btc_blocks = []
        pending_calendars = []
        for _, att in dt.timestamp.all_attestations():
            if isinstance(att, BitcoinBlockHeaderAttestation):
                btc_blocks.append(att.height)
            elif isinstance(att, PendingAttestation):
                pending_calendars.append(att.uri)

        status = "unknown"
        if not target_file.is_file():
            status = "orphaned"
        elif not hash_matches:
            status = "mismatch"
        elif btc_blocks:
            status = "confirmed"
        elif pending_calendars:
            status = "pending"

        return {
            "ots_path": str(candidate_ots),
            "target_path": str(target_file),
            "algorithm": algo,
            "ots_digest": ots_hash,
            "actual_digest": actual_hash,
            "hash_matches": hash_matches,
            "btc_blocks": btc_blocks,
            "pending_calendars": pending_calendars,
            "status": status,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "ots_path": str(candidate_ots)}


# ------------------------------------------------------------------------------
# Batch Audit & Integrity Validation
# ------------------------------------------------------------------------------
def run_audit(target_dir: Path, proofs_dir: Path | None = None) -> tuple[int, list[dict[str, str]]]:
    """Runs a full non-blocking diagnostic pass over an asset or version tree."""
    violations: list[dict[str, str]] = []

    # Map of proof file -> expected target media file
    all_ots_map: dict[Path, Path] = {}

    # 1. From external proofs_dir if provided
    if proofs_dir and proofs_dir.is_dir():
        for ots in proofs_dir.rglob("*.ots"):
            rel = ots.relative_to(proofs_dir)
            base_name = ots.name[:-4]
            expected_target = target_dir / rel.parent / base_name
            all_ots_map[ots] = expected_target

    # 2. In-place proofs within target_dir
    if target_dir.is_dir():
        for ots in target_dir.rglob("*.ots"):
            base_name = ots.name[:-4]
            expected_target = ots.parent / base_name
            all_ots_map[ots] = expected_target

    # 3. Check every OTS proof
    for ots, expected_target in all_ots_map.items():
        base_name = ots.name[:-4]
        is_external = proofs_dir and (proofs_dir == ots.parent or proofs_dir in ots.parents)
        display_path = (
            f"[proofs] {ots.relative_to(proofs_dir)}" if is_external
            else str(ots.relative_to(target_dir))
        )

        if not expected_target.is_file():
            violations.append({
                "path": display_path,
                "type": "ORPHAN_PROOF",
                "severity": "ERROR",
                "desc": f"Orphaned .ots timestamp proof without media file '{base_name}'.",
            })
            continue

        res = inspect_ots(expected_target, ots)
        target_display = str(expected_target.relative_to(target_dir))
        if not res:
            violations.append({
                "path": target_display,
                "type": "CORRUPT_PROOF",
                "severity": "ERROR",
                "desc": f"Failed to deserialize or parse .ots proof file '{ots.name}'.",
            })
        elif res["status"] == "mismatch":
            violations.append({
                "path": target_display,
                "type": "HASH_MISMATCH",
                "severity": "CRITICAL",
                "desc": (
                    f"SHA-256 mismatch! File was altered since timestamping. "
                    f"File: {res['actual_digest'][:12]}... != Proof: {res['ots_digest'][:12]}..."
                ),
            })

    # 4. Check 01_source files for missing OTS
    src_dir = target_dir / "01_source"
    if src_dir.is_dir():
        target_files_checked = set(all_ots_map.values())
        for f in src_dir.rglob("*"):
            if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith("."):
                if f not in target_files_checked:
                    violations.append({
                        "path": str(f.relative_to(target_dir)),
                        "type": "MISSING_PROOF",
                        "severity": "WARN",
                        "desc": "Source asset has not been anchored in Bitcoin blockchain (.ots missing).",
                    })

    return len([v for v in violations if v["severity"] in ("CRITICAL", "ERROR")]), violations


def print_audit_report(asset_name: str, version: str, violations: list[dict[str, str]]) -> None:
    """Renders formatted full diagnostics table."""
    log_head(f"Integrity Audit Report: '{asset_name}' ({version})")
    if not violations:
        log_ok("All asset proofs, hashes, and files are 100% verified and intact!\n")
        return

    print("  " + "-" * 88)
    print(f"  {C_BOLD}{'SEVERITY':<10} {'VIOLATION':<16} {'PATH':<30} {'DETAILS'}{C_RESET}")
    print("  " + "-" * 88)

    for v in violations:
        sev = v["severity"]
        c = C_RED if sev == "CRITICAL" else (C_YELLOW if sev == "WARN" else C_RED)
        print(f"  {c}{sev:<10}{C_RESET} {v['type']:<16} {v['path']:<30} {v['desc']}")
    print("  " + "-" * 88 + "\n")


def execute_init(
    name: str,
    version: str,
    base_dir: Path | None = None,
    proofs_dir: Path | None = None,
) -> tuple[Path, Path | None]:
    """Initializes standard asset folder hierarchy."""
    icons_dir = base_dir or get_default_icons_dir()
    resolved_proofs_dir = proofs_dir or get_default_proofs_dir(icons_dir)

    target_dir = icons_dir / name / version
    raw_dir = target_dir / "01_source" / "raw"
    master_dir = target_dir / "01_source" / "master"
    signed_dir = target_dir / "02_signed"
    dist_dir = target_dir / "03_dist"

    raw_dir.mkdir(parents=True, exist_ok=True)
    master_dir.mkdir(parents=True, exist_ok=True)
    signed_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    target_proofs_dir = None
    if resolved_proofs_dir:
        target_proofs_dir = resolved_proofs_dir / name / version
        (target_proofs_dir / "01_source" / "raw").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "01_source" / "master").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "02_signed").mkdir(parents=True, exist_ok=True)

    log_head(f"Initialized Asset Structure: {name} ({version})")
    log_ok(f"Raw Project:    {raw_dir}")
    log_ok(f"Master Image:   {master_dir}")
    log_ok(f"Signed Release: {signed_dir}")
    log_ok(f"Distribution:   {dist_dir}")
    if target_proofs_dir:
        log_ok(f"Proofs Archive: {target_proofs_dir}")

    print(f"\n  {C_BOLD}Next steps:{C_RESET}")
    print(f"    1. Place raw canvas (e.g. {name}.xcf) into: {C_CYAN}{raw_dir}/{C_RESET}")
    print(f"    2. Place square master PNG into:            {C_CYAN}{master_dir}/{C_RESET}")
    print(f"    3. Run build: {C_GREEN}build-image build {name} {version}{C_RESET}\n")

    return target_dir, target_proofs_dir


# ------------------------------------------------------------------------------
# Build Pipeline: Source -> Signed -> Dist
# ------------------------------------------------------------------------------
def execute_build(
    name: str,
    version: str,
    master_path: Path | None = None,
    raw_path: Path | None = None,
    base_dir: Path | None = None,
    proofs_dir: Path | None = None,
    sizes: list[int] | None = None,
    bw_item: str | None = None,
    no_sign: bool = False,
    no_stamp: bool = False,
    force_re_stamp: bool = False,
) -> None:
    """Executes atomic multi-scale build pipeline for an asset version."""
    icons_dir = base_dir or get_default_icons_dir()
    resolved_proofs_dir = proofs_dir or get_default_proofs_dir(icons_dir)
    target_dir = icons_dir / name / version
    src_dir = target_dir / "01_source"
    raw_dest_dir = src_dir / "raw"
    master_dest_dir = src_dir / "master"
    signed_dir = target_dir / "02_signed"
    dist_dir = target_dir / "03_dist"

    # Auto-detect existing master if not explicitly provided
    if master_path is None:
        if master_dest_dir.is_dir():
            candidates = [
                f for f in sorted(master_dest_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            if candidates:
                master_path = candidates[0]
                log_info(f"Auto-detected master image: {master_path.name}")

    # Auto-detect existing raw canvas if not explicitly provided
    if raw_path is None:
        if raw_dest_dir.is_dir():
            raw_candidates = [
                f for f in sorted(raw_dest_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            if raw_candidates:
                raw_path = raw_candidates[0]
                log_info(f"Auto-detected raw project canvas: {raw_path.name}")

    # If master is still not found, initialize directories and give guidance
    if master_path is None:
        log_warn(f"No master image provided or found for '{name}' ({version}).")
        execute_init(name, version, base_dir=icons_dir, proofs_dir=resolved_proofs_dir)
        return

    if not master_path.is_file():
        log_err(f"Master file not found: {master_path}")
        sys.exit(1)
    if raw_path and not raw_path.is_file():
        log_err(f"Raw project canvas file not found: {raw_path}")
        sys.exit(1)

    target_proofs_dir = None
    if resolved_proofs_dir:
        target_proofs_dir = resolved_proofs_dir / name / version
        (target_proofs_dir / "01_source" / "raw").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "01_source" / "master").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "02_signed").mkdir(parents=True, exist_ok=True)

    log_head(f"Building Media Asset: {name} ({version})")
    log_info(f"Target Directory: {target_dir}")
    if target_proofs_dir:
        log_info(f"Proofs Archive:   {target_proofs_dir}")
    log_info(f"Master Image:     {master_path}")
    if raw_path:
        log_info(f"Raw Project:      {raw_path}")

    # 1. Pre-flight Audit if target directory already exists
    if target_dir.is_dir():
        err_count, violations = run_audit(target_dir, target_proofs_dir)
        if err_count > 0 and not force_re_stamp:
            print_audit_report(name, version, violations)
            log_err(
                f"Build aborted due to {err_count} integrity violation(s). "
                f"Fix them or pass --force-re-stamp to overwrite."
            )
            sys.exit(1)

    raw_dest_dir.mkdir(parents=True, exist_ok=True)
    master_dest_dir.mkdir(parents=True, exist_ok=True)
    signed_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    sign_image_bin = shutil.which("sign-image")

    # 2. Stage 1: Preserve Raw Project Canvas
    if raw_path:
        dest_raw = raw_dest_dir / raw_path.name
        if dest_raw.resolve() != raw_path.resolve():
            shutil.copyfile(raw_path, dest_raw)
        if not no_stamp and sign_image_bin:
            local_ots = dest_raw.with_name(f"{dest_raw.name}.ots")
            final_ots = (
                (target_proofs_dir / "01_source" / "raw" / f"{dest_raw.name}.ots")
                if target_proofs_dir
                else local_ots
            )
            if not final_ots.is_file() or force_re_stamp:
                log_info(f"Stamping raw canvas '{raw_path.name}' in Bitcoin blockchain...")
                subprocess.run([sign_image_bin, "stamp", str(dest_raw)], check=True)
                if target_proofs_dir and local_ots.is_file():
                    shutil.move(local_ots, final_ots)
                if final_ots.is_file():
                    final_ots.chmod(0o444)
        dest_raw.chmod(0o444)
        log_ok(f"Raw canvas secured: {dest_raw.name} (0444)")

    # 3. Stage 2: Preserve Normalized Master
    dest_master = master_dest_dir / f"{name}_crop_master{master_path.suffix}"
    if dest_master.resolve() != master_path.resolve():
        shutil.copyfile(master_path, dest_master)
    if not no_stamp and sign_image_bin:
        local_ots = dest_master.with_name(f"{dest_master.name}.ots")
        final_ots = (
            (target_proofs_dir / "01_source" / "master" / f"{dest_master.name}.ots")
            if target_proofs_dir
            else local_ots
        )
        if not final_ots.is_file() or force_re_stamp:
            log_info(f"Stamping cropped master '{dest_master.name}' in Bitcoin blockchain...")
            subprocess.run([sign_image_bin, "stamp", str(dest_master)], check=True)
            if target_proofs_dir and local_ots.is_file():
                shutil.move(local_ots, final_ots)
            if final_ots.is_file():
                final_ots.chmod(0o444)
    dest_master.chmod(0o444)
    log_ok(f"Normalized master secured: {dest_master.name} (0444)")

    # 4. Stage 3: Render and Sign Showcase Release (1024x1024)
    signed_target = signed_dir / f"{name}_1024_signed.png"
    log_info("Rendering 1024x1024 showcase PNG...")
    try:
        with Image.open(master_path) as pil_master:
            showcase_img = pil_master.convert("RGBA")
            if showcase_img.width > 1024 or showcase_img.height > 1024:
                showcase_img = showcase_img.resize((1024, 1024), Image.Resampling.LANCZOS)
            showcase_tmp = target_dir / f".tmp_showcase_{name}.png"
            showcase_img.save(showcase_tmp, format="PNG")
    except Exception as e:
        log_err(f"Failed to load or resize master image: {e}")
        sys.exit(1)

    if not no_sign and sign_image_bin:
        log_info("Cryptographically signing showcase release (C2PA + Watermark + OpenTimestamps)...")
        sign_cmd = [sign_image_bin, "sign", "--stamp", "-o", str(signed_target)]
        if bw_item:
            sign_cmd.extend(["--bw-item", bw_item])
        sign_cmd.append(str(showcase_tmp))
        res_sign = subprocess.run(sign_cmd)
        if res_sign.returncode != 0:
            log_warn("sign-image signing returned non-zero code; fallback to raw copy.")
            shutil.copyfile(showcase_tmp, signed_target)
        showcase_tmp.unlink(missing_ok=True)
        # Relocate OTS to proofs_dir if segregated
        local_showcase_ots = signed_target.with_name(f"{signed_target.name}.ots")
        if target_proofs_dir and local_showcase_ots.is_file():
            final_showcase_ots = target_proofs_dir / "02_signed" / f"{signed_target.name}.ots"
            shutil.move(local_showcase_ots, final_showcase_ots)
            final_showcase_ots.chmod(0o444)
        log_ok(f"Showcase release signed: {signed_target.name}")
    else:
        shutil.move(showcase_tmp, signed_target)
        log_ok(f"Showcase release saved without signing: {signed_target.name}")

    # 5. Stage 4: Render Multi-Scale Distribution (Dist)
    target_sizes = sizes or [512, 256, 128, 64, 32]
    log_info(f"Rendering distribution assets ({target_sizes}) into 03_dist/...")

    try:
        with Image.open(master_path) as pil_master:
            rgba_base = pil_master.convert("RGBA")

            # Multi-layer favicon.ico container (16, 32, 48, 64, 128, 256)
            ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
            ico_path = dist_dir / "favicon.ico"
            rgba_base.save(ico_path, format="ICO", sizes=ico_sizes)
            log_ok("Rendered multi-resolution favicon.ico (16..256)")

            # WebP and PNG downscales
            for s in target_sizes:
                res_img = rgba_base.resize((s, s), Image.Resampling.LANCZOS)
                res_img.save(dist_dir / f"{name}_{s}.webp", format="WEBP", quality=90, method=6)
                res_img.save(dist_dir / f"{name}_{s}.png", format="PNG", optimize=True)
    except Exception as e:
        log_err(f"Failed during dist rendering: {e}")
        sys.exit(1)

    log_ok(f"Generated {len(target_sizes) * 2 + 1} distribution files in {dist_dir.name}/")

    # 6. Stage 5: Update 'latest' Symlinks
    latest_symlink = icons_dir / name / "latest"
    try:
        if latest_symlink.is_symlink() or latest_symlink.exists():
            latest_symlink.unlink()
        latest_symlink.symlink_to(version)
        log_ok(f"Updated pointer: {name}/latest -> {version}")
    except Exception as e:
        log_warn(f"Could not update symlink 'latest': {e}")

    if resolved_proofs_dir:
        proofs_latest = resolved_proofs_dir / name / "latest"
        try:
            if proofs_latest.is_symlink() or proofs_latest.exists():
                proofs_latest.unlink()
            proofs_latest.symlink_to(version)
            log_ok(f"Updated proofs pointer: {name}/latest -> {version}")
        except Exception as e:
            log_warn(f"Could not update proofs symlink 'latest': {e}")

    log_head(f"Build Complete for '{name}' ({version})")
    print(f"  {C_BOLD}Source:{C_RESET}     {src_dir}")
    print(f"  {C_BOLD}Signed:{C_RESET}     {signed_dir}")
    print(f"  {C_BOLD}Dist:{C_RESET}       {dist_dir}")
    if target_proofs_dir:
        print(f"  {C_BOLD}Proofs:{C_RESET}     {target_proofs_dir}")
    print(f"  {C_BOLD}Active:{C_RESET}     {latest_symlink}\n")


# ------------------------------------------------------------------------------
# CLI Parser
# ------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="build-image",
        description="Structured media asset pipeline: provenance auditing, C2PA signing & multi-scale dist rendering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  build-image init duck v1
  build-image build duck v1
  build-image build duck v1 --master duck_crop.png --raw duck.xcf
  build-image build duck v2 --master duck_new.png --bw-item c2pa-signer
  build-image audit duck v1
  build-image audit
  build-image upgrade duck v1
  build-image list
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command mode")

    # Command: init
    p_init = subparsers.add_parser("init", help="Initialize directory structure for an asset version")
    p_init.add_argument("name", type=str, help="Asset identifier slug (e.g. duck, logo)")
    p_init.add_argument("version", type=str, help="Version tag (e.g. v1, v2, 2026.1)")
    p_init.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_init.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: build
    p_build = subparsers.add_parser("build", help="Build and render an asset version from master")
    p_build.add_argument("name", type=str, help="Asset identifier slug (e.g. duck, logo)")
    p_build.add_argument("version", type=str, help="Version tag (e.g. v1, v2, 2026.1)")
    p_build.add_argument("-m", "--master", type=Path, default=None, help="Normalized/cropped master square image (auto-detected if present in 01_source/master/)")
    p_build.add_argument("-r", "--raw", type=Path, help="Original project canvas before cropping (auto-detected if present in 01_source/raw/)")
    p_build.add_argument("-d", "--dir", type=Path, help="Base icons library directory (default: $SEAFILE_ICONS / $SEADRIVE_ICONS)")
    p_build.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory (default: $SEAFILE_PROOFS / $SEADRIVE_PROOFS)")
    p_build.add_argument("--sizes", type=str, default="512,256,128,64,32", help="Comma-separated dist resolutions")
    p_build.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const="c2pa-signer", type=str, help="Bitwarden item name for C2PA credentials")
    p_build.add_argument("--no-sign", action="store_true", help="Skip C2PA signing of showcase release")
    p_build.add_argument("--no-stamp", action="store_true", help="Skip OpenTimestamps Bitcoin anchoring")
    p_build.add_argument("--force-re-stamp", action="store_true", help="Bypass audit mismatch and re-stamp source files")

    # Command: audit
    p_audit = subparsers.add_parser("audit", help="Run full non-blocking integrity audit across asset tree")
    p_audit.add_argument("name", type=str, nargs="?", help="Specific asset name to audit (optional)")
    p_audit.add_argument("version", type=str, nargs="?", help="Specific version to audit (optional)")
    p_audit.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_audit.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: upgrade
    p_up = subparsers.add_parser("upgrade", help="Recursively upgrade OpenTimestamps proofs in asset tree")
    p_up.add_argument("name", type=str, nargs="?", help="Asset name to upgrade")
    p_up.add_argument("version", type=str, nargs="?", help="Asset version to upgrade")
    p_up.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_up.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: list
    p_list = subparsers.add_parser("list", help="List managed assets and versions")
    p_list.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_list.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    args_list = sys.argv[1:]
    if args_list and args_list[0] not in ("build", "init", "audit", "upgrade", "list", "-h", "--help"):
        args_list.insert(0, "build")

    args = parser.parse_args(args_list)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    base_dir = args.dir or get_default_icons_dir()
    proofs_base = getattr(args, "proofs_dir", None) or get_default_proofs_dir(base_dir)

    if args.command == "init":
        execute_init(name=args.name, version=args.version, base_dir=base_dir, proofs_dir=proofs_base)

    elif args.command == "build":
        try:
            parsed_sizes = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
        except ValueError:
            parsed_sizes = [512, 256, 128, 64, 32]

        execute_build(
            name=args.name,
            version=args.version,
            master_path=args.master,
            raw_path=args.raw,
            base_dir=base_dir,
            proofs_dir=proofs_base,
            sizes=parsed_sizes,
            bw_item=args.bw_item,
            no_sign=args.no_sign,
            no_stamp=args.no_stamp,
            force_re_stamp=args.force_re_stamp,
        )

    elif args.command == "audit":
        if args.name and args.version:
            target = base_dir / args.name / args.version
            p_target = (proofs_base / args.name / args.version) if proofs_base else None
            err_count, violations = run_audit(target, p_target)
            print_audit_report(args.name, args.version, violations)
            sys.exit(1 if err_count > 0 else 0)
        elif args.name:
            asset_dir = base_dir / args.name
            total_err = 0
            for v_dir in sorted(asset_dir.iterdir()):
                if v_dir.is_dir() and not v_dir.is_symlink():
                    p_target = (proofs_base / args.name / v_dir.name) if proofs_base else None
                    err_c, viols = run_audit(v_dir, p_target)
                    print_audit_report(args.name, v_dir.name, viols)
                    total_err += err_c
            sys.exit(1 if total_err > 0 else 0)
        else:
            total_err = 0
            if not base_dir.is_dir():
                log_warn(f"Icons directory does not exist: {base_dir}")
                sys.exit(0)
            for a_dir in sorted(base_dir.iterdir()):
                if a_dir.is_dir() and not a_dir.name.startswith("."):
                    for v_dir in sorted(a_dir.iterdir()):
                        if v_dir.is_dir() and not v_dir.is_symlink():
                            p_target = (proofs_base / a_dir.name / v_dir.name) if proofs_base else None
                            err_c, viols = run_audit(v_dir, p_target)
                            print_audit_report(a_dir.name, v_dir.name, viols)
                            total_err += err_c
            sys.exit(1 if total_err > 0 else 0)

    elif args.command == "upgrade":
        sign_bin = shutil.which("sign-image")
        if not sign_bin:
            log_err("sign-image utility not found in PATH.")
            sys.exit(1)
        search_base = proofs_base or base_dir
        if args.name and args.version:
            target = search_base / args.name / args.version
        elif args.name:
            target = search_base / args.name
        else:
            target = search_base
        subprocess.run([sign_bin, "stamp", "--upgrade", str(target)], check=False)

    elif args.command == "list":
        if not base_dir.is_dir():
            log_info(f"Empty or missing library: {base_dir}")
            return
        log_head(f"Managed Asset Library: {base_dir}")
        if proofs_base:
            log_info(f"Proofs Archive:        {proofs_base}")
        for a_dir in sorted(base_dir.iterdir()):
            if a_dir.is_dir() and not a_dir.name.startswith("."):
                versions = [v.name for v in sorted(a_dir.iterdir()) if v.is_dir() and not v.is_symlink()]
                latest_p = a_dir / "latest"
                latest_target = os.readlink(latest_p) if latest_p.is_symlink() else "N/A"
                print(f"  {C_BOLD}• {a_dir.name:<20}{C_RESET} Versions: {', '.join(versions) or 'none'} (latest -> {latest_target})")
        print()


if __name__ == "__main__":
    main()
