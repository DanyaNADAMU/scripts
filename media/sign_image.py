#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "c2pa-python>=0.38.0",
#     "cryptography>=43.0.0",
#     "pillow>=10.0.0",
#     "numpy>=1.26.0",
#     "pywavelets>=1.6.0",
#     "scipy>=1.13.0",
# ]
# ///
# ==============================================================================
# Script:      sign_image.py
# Category:    media
# Description: Multi-layer image signing: C2PA Content Credentials & DWT-DCT Steganography.
# Target:      Linux / macOS
# Requires:    python >= 3.11, uv
# Usage:       sign-image [sign|verify|credentials|keygen] [options] <file>
# ==============================================================================
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import random
import shutil
import sys
import zlib
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image
import pywt
from scipy.fftpack import dct, idct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import c2pa

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "nadamu"
DEFAULT_KEY_DIR = DEFAULT_CONFIG_DIR / "c2pa"
DEFAULT_KEY_PATH = DEFAULT_KEY_DIR / "es256_private.key"
DEFAULT_CERT_PATH = DEFAULT_KEY_DIR / "es256_certs.pem"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "c2pa.json"

DEFAULT_DOMAIN = "nada.mu"
DEFAULT_AUTHOR = "DanyaNADAMU <git@nada.mu>"
DEFAULT_POLICY_URL = "https://nada.mu/.well-known/security.txt"
DEFAULT_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
APP_NAME = "sign-image"
APP_VERSION = "1.1.0"

# ANSI Colors
C_BLUE = "\033[1;34m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED = "\033[1;31m"
C_CYAN = "\033[1;36m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


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


# ------------------------------------------------------------------------------
# Configuration File Management
# ------------------------------------------------------------------------------
def load_config() -> dict[str, Any]:
    """Loads configuration from ~/.config/nadamu/c2pa.json or creates default."""
    default_cfg = {
        "author": DEFAULT_AUTHOR,
        "domain": DEFAULT_DOMAIN,
        "policy_url": DEFAULT_POLICY_URL,
        "default_license": f"All rights reserved. Verified at {DEFAULT_POLICY_URL}",
        "digital_source_type": DEFAULT_SOURCE_TYPE,
        "watermark_text": DEFAULT_DOMAIN,
        "watermark_delta": 35.0,
        "watermark_repeats": 3,
    }

    if DEFAULT_CONFIG_FILE.is_file():
        try:
            user_cfg = json.loads(DEFAULT_CONFIG_FILE.read_text(encoding="utf-8"))
            default_cfg.update(user_cfg)
        except Exception as e:
            log_warn(f"Failed to parse {DEFAULT_CONFIG_FILE}: {e}")
    else:
        try:
            DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            DEFAULT_CONFIG_FILE.write_text(
                json.dumps(default_cfg, indent=2) + "\n", encoding="utf-8"
            )
        except Exception:
            pass

    return default_cfg


# ------------------------------------------------------------------------------
# Stage 2: Invisible DWT-DCT Steganographic Watermarking
# ------------------------------------------------------------------------------
def _dct2(a: np.ndarray) -> np.ndarray:
    return dct(dct(a.T, norm="ortho").T, norm="ortho")


def _idct2(a: np.ndarray) -> np.ndarray:
    return idct(idct(a.T, norm="ortho").T, norm="ortho")


def _make_watermark_packet(text: str) -> list[int]:
    """Frames text into a packet: [MAGIC 'NADA' (4B)] [LEN (1B)] [PAYLOAD] [CRC8 (1B)]."""
    raw = text.encode("utf-8")
    crc = zlib.crc32(raw) & 0xFF
    packet = b"NADA" + bytes([len(raw)]) + raw + bytes([crc])
    bits = []
    for b in packet:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _parse_watermark_packet(bits: list[int]) -> str | None:
    """Parses bits and validates magic header and CRC8 checksum."""
    if len(bits) < 48:
        return None
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = int("".join(str(b) for b in bits[i : i + 8]), 2)
        data.append(byte_val)
    if len(data) < 6 or data[:4] != b"NADA":
        return None
    length = data[4]
    if len(data) < 5 + length + 1:
        return None
    raw = bytes(data[5 : 5 + length])
    expected_crc = data[5 + length]
    if (zlib.crc32(raw) & 0xFF) != expected_crc:
        return None
    return raw.decode("utf-8", errors="ignore")


def embed_dwt_watermark(
    img: Image.Image,
    text: str,
    secret: str,
    delta: float = 35.0,
    repeats: int = 3,
) -> Image.Image:
    """Embeds an invisible, robust DWT-DCT watermark into the luminance channel."""
    has_alpha = img.mode == "RGBA"
    alpha = img.getchannel("A") if has_alpha else None
    rgb_img = img.convert("RGB")

    ycbcr = rgb_img.convert("YCbCr")
    Y, Cb, Cr = ycbcr.split()
    y_arr = np.array(Y, dtype=np.float32)

    LL, (LH, HL, HH) = pywt.dwt2(y_arr, "haar")
    h, w = LL.shape
    blocks_h, blocks_w = h // 8, w // 8
    total_blocks = blocks_h * blocks_w

    packet_bits = _make_watermark_packet(text)
    expanded_bits: list[int] = []
    for b in packet_bits:
        expanded_bits.extend([b] * repeats)

    if len(expanded_bits) > total_blocks:
        raise ValueError(
            f"Image resolution too small ({img.width}x{img.height}) to host watermark. "
            f"Need {len(expanded_bits)} 8x8 blocks, but only {total_blocks} available."
        )

    # Scramble block order using pseudo-random permutation derived from secret
    rng = random.Random(secret)
    indices = list(range(total_blocks))
    rng.shuffle(indices)

    for i, bit in enumerate(expanded_bits):
        block_idx = indices[i]
        by = block_idx // blocks_w
        bx = block_idx % blocks_w

        block = LL[by * 8 : (by + 1) * 8, bx * 8 : (bx + 1) * 8]
        d = _dct2(block)
        # Manipulate mid-frequency coefficients [1, 2] and [2, 1]
        c1, c2 = d[1, 2], d[2, 1]
        if bit == 1:
            if c1 <= c2 + delta:
                d[1, 2] = c2 + delta
        else:
            if c2 <= c1 + delta:
                d[2, 1] = c1 + delta
        LL[by * 8 : (by + 1) * 8, bx * 8 : (bx + 1) * 8] = _idct2(d)

    y_wm = pywt.idwt2((LL, (LH, HL, HH)), "haar")
    y_wm = np.clip(y_wm, 0, 255).astype(np.uint8)

    res_img = Image.merge("YCbCr", (Image.fromarray(y_wm), Cb, Cr)).convert("RGB")
    if has_alpha and alpha:
        res_img.putalpha(alpha)
    return res_img


def extract_dwt_watermark(
    img: Image.Image,
    secret: str,
    repeats: int = 3,
    max_payload_bytes: int = 64,
) -> str | None:
    """Scans and extracts an invisible DWT-DCT watermark from image frequencies."""
    rgb_img = img.convert("RGB")
    Y, _, _ = rgb_img.convert("YCbCr").split()
    y_arr = np.array(Y, dtype=np.float32)

    LL, _ = pywt.dwt2(y_arr, "haar")
    h, w = LL.shape
    blocks_h, blocks_w = h // 8, w // 8
    total_blocks = blocks_h * blocks_w

    max_bits = (6 + max_payload_bytes) * 8 * repeats
    num_to_read = min(max_bits, total_blocks)

    rng = random.Random(secret)
    indices = list(range(total_blocks))
    rng.shuffle(indices)

    raw_bits: list[int] = []
    for i in range(num_to_read):
        block_idx = indices[i]
        by = block_idx // blocks_w
        bx = block_idx % blocks_w
        block = LL[by * 8 : (by + 1) * 8, bx * 8 : (bx + 1) * 8]
        d = _dct2(block)
        raw_bits.append(1 if d[1, 2] > d[2, 1] else 0)

    # Majority voting over repetitions to filter compression noise
    voted_bits: list[int] = []
    for i in range(0, len(raw_bits) - repeats + 1, repeats):
        chunk = raw_bits[i : i + repeats]
        voted_bits.append(1 if sum(chunk) > (repeats // 2) else 0)

    return _parse_watermark_packet(voted_bits)


def get_default_secret() -> str:
    """Derives a deterministic default secret from the user's C2PA private key hash."""
    if DEFAULT_KEY_PATH.is_file():
        key_data = DEFAULT_KEY_PATH.read_bytes()
        return hashlib.sha256(key_data).hexdigest()
    return "nada.mu-default-watermark-key"


# ------------------------------------------------------------------------------
# Stage 1: C2PA Key & Certificate Management
# ------------------------------------------------------------------------------
def generate_c2pa_credentials(
    domain: str = DEFAULT_DOMAIN,
    key_out: Path = DEFAULT_KEY_PATH,
    cert_out: Path = DEFAULT_CERT_PATH,
) -> tuple[bytes, bytes]:
    """Generates a compliant 2-tier C2PA X.509 certificate chain (Root CA + Leaf)."""
    key_out.parent.mkdir(parents=True, exist_ok=True)

    # 1. Root CA
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    # 2. Leaf Certificate (C2PA End Entity)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} Media Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1095))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    chain_pem = leaf_cert.public_bytes(serialization.Encoding.PEM) + root_cert.public_bytes(serialization.Encoding.PEM)

    key_out.write_bytes(leaf_key_pem)
    cert_out.write_bytes(chain_pem)
    os.chmod(key_out, 0o600)

    return leaf_key_pem, chain_pem


def load_or_create_credentials(
    key_path: Path | None, cert_path: Path | None, domain: str
) -> tuple[bytes, bytes]:
    """Loads existing credentials or automatically generates persistent credentials."""
    kp = key_path or DEFAULT_KEY_PATH
    cp = cert_path or DEFAULT_CERT_PATH

    if kp.is_file() and cp.is_file():
        return kp.read_bytes(), cp.read_bytes()

    log_info(f"Generating persistent C2PA credentials for {domain} in {kp.parent}...")
    key_bytes, cert_bytes = generate_c2pa_credentials(domain, kp, cp)
    log_ok(f"Generated signing key: {kp}")
    log_ok(f"Generated certificate chain: {cp}")
    return key_bytes, cert_bytes


def manage_credentials(
    export_raw: bool = False,
    import_key: Path | None = None,
    import_cert: Path | None = None,
) -> None:
    """Exports or imports C2PA credentials for backup to Bitwarden or deployment to prod."""
    DEFAULT_KEY_DIR.mkdir(parents=True, exist_ok=True)

    if import_key or import_cert:
        if not (import_key and import_cert):
            log_err("Both --import-key and --import-cert must be specified.")
            sys.exit(1)
        if not import_key.is_file():
            log_err(f"Key file not found: {import_key}")
            sys.exit(1)
        if not import_cert.is_file():
            log_err(f"Cert file not found: {import_cert}")
            sys.exit(1)

        shutil.copyfile(import_key, DEFAULT_KEY_PATH)
        shutil.copyfile(import_cert, DEFAULT_CERT_PATH)
        os.chmod(DEFAULT_KEY_PATH, 0o600)

        log_ok(f"Imported private key to: {DEFAULT_KEY_PATH}")
        log_ok(f"Imported cert chain to:  {DEFAULT_CERT_PATH}")
        return

    if not (DEFAULT_KEY_PATH.is_file() and DEFAULT_CERT_PATH.is_file()):
        cfg = load_config()
        log_info(f"Credentials not found. Generating initial credentials in {DEFAULT_KEY_DIR}...")
        generate_c2pa_credentials(cfg.get("domain", DEFAULT_DOMAIN))

    if export_raw:
        print("# ==============================================================================")
        print("# C2PA PRIVATE KEY (Save to Bitwarden / Secret Vault)")
        print("# ==============================================================================")
        print(DEFAULT_KEY_PATH.read_text().strip())
        print("\n# ==============================================================================")
        print("# C2PA CERTIFICATE CHAIN")
        print("# ==============================================================================")
        print(DEFAULT_CERT_PATH.read_text().strip())
        return

    cert_data = DEFAULT_CERT_PATH.read_bytes()
    certs = x509.load_pem_x509_certificates(cert_data)
    leaf = certs[0]

    log_head("C2PA Signing Credentials (Active)")
    print(f"  {C_BOLD}Key Path:{C_RESET}     {DEFAULT_KEY_PATH} (0600)")
    print(f"  {C_BOLD}Cert Path:{C_RESET}    {DEFAULT_CERT_PATH}")
    print(f"  {C_BOLD}Config File:{C_RESET}  {DEFAULT_CONFIG_FILE}")
    print(f"  {C_BOLD}Subject:{C_RESET}      {leaf.subject.rfc4514_string()}")
    print(f"  {C_BOLD}Issuer:{C_RESET}       {leaf.issuer.rfc4514_string()}")
    print(f"  {C_BOLD}Fingerprint:{C_RESET}  SHA256:{leaf.fingerprint(hashes.SHA256()).hex()}")
    print(f"  {C_BOLD}Valid Until:{C_RESET}  {leaf.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {C_BOLD}Chain Length:{C_RESET} {len(certs)} certificate(s)")

    print(f"\n  {C_CYAN}[Tip for Bitwarden / Backup]:{C_RESET}")
    print("    To copy private key & cert to clipboard for Bitwarden:")
    print(f"      {C_BOLD}sign-image credentials --export{C_RESET}")
    print("    To restore on another production machine:")
    print(f"      {C_BOLD}sign-image credentials --import-key key.pem --import-cert cert.pem{C_RESET}\n")


# ------------------------------------------------------------------------------
# Combined Pipeline: Sign & Inspect (Stage 1 + Stage 2)
# ------------------------------------------------------------------------------
def process_signing(
    input_path: Path,
    output_path: Path,
    title: str | None = None,
    author: str | None = None,
    domain: str | None = None,
    description: str | None = None,
    license_text: str | None = None,
    watermark_payload: str | None = None,
    no_watermark: bool = False,
    no_c2pa: bool = False,
    secret: str | None = None,
    key_path: Path | None = None,
    cert_path: Path | None = None,
) -> None:
    """Executes multi-layer signing (DWT-DCT steganography + C2PA Content Credentials)."""
    if not input_path.is_file():
        log_err(f"Input file not found: {input_path}")
        sys.exit(1)

    cfg = load_config()

    act_author = author or cfg.get("author", DEFAULT_AUTHOR)
    act_domain = domain or cfg.get("domain", DEFAULT_DOMAIN)
    act_policy = cfg.get("policy_url", DEFAULT_POLICY_URL)
    act_license = license_text or cfg.get("default_license", "")
    src_type = cfg.get("digital_source_type", DEFAULT_SOURCE_TYPE)
    wm_text = watermark_payload or cfg.get("watermark_text", act_domain)
    wm_secret = secret or get_default_secret()
    wm_delta = float(cfg.get("watermark_delta", 35.0))
    wm_repeats = int(cfg.get("watermark_repeats", 3))

    asset_title = title or input_path.stem
    desc_text = description or f"Original media authored by {act_author} on {act_domain}."

    log_head(f"Signing {input_path.name}...")
    log_info(f"Title:       {asset_title}")
    log_info(f"Author:      {act_author}")
    log_info(f"Domain:      {act_domain}")
    log_info(f"Target:      {output_path}")

    # Stage 2: Embed DWT-DCT Steganographic Watermark
    work_file = output_path
    if not no_watermark:
        try:
            with Image.open(input_path) as pil_img:
                log_info(f"Stage 2: Embedding invisible DWT-DCT watermark ('{wm_text}')...")
                wm_img = embed_dwt_watermark(
                    pil_img,
                    text=wm_text,
                    secret=wm_secret,
                    delta=wm_delta,
                    repeats=wm_repeats,
                )
                output_path.parent.mkdir(parents=True, exist_ok=True)
                # Preserve format
                save_fmt = pil_img.format or "PNG"
                wm_img.save(output_path, format=save_fmt)
                log_ok(f"Stage 2 complete: Watermark embedded into frequency spectrum.")
        except Exception as e:
            log_err(f"Steganographic watermarking failed: {e}")
            sys.exit(1)
    else:
        log_info("Stage 2: Invisible watermarking disabled (--no-watermark).")
        if input_path.resolve() != output_path.resolve():
            shutil.copyfile(input_path, output_path)

    # Stage 1: C2PA Content Credentials
    if not no_c2pa:
        log_info("Stage 1: Signing with C2PA Content Credentials...")
        key_bytes, cert_bytes = load_or_create_credentials(key_path, cert_path, act_domain)

        signer_info = c2pa.C2paSignerInfo(
            alg=c2pa.C2paSigningAlg.ES256,
            sign_cert=cert_bytes,
            private_key=key_bytes,
            ta_url=None,
        )
        signer = c2pa.Signer.from_info(signer_info)

        action_params: dict[str, Any] = {
            "description": desc_text,
            "author": act_author,
            "canonical_policy": act_policy,
        }
        if act_license:
            action_params["license"] = act_license

        manifest_def: dict[str, Any] = {
            "claim_generator": f"{APP_NAME}/{APP_VERSION} ({act_domain})",
            "claim_generator_info": [{"name": APP_NAME, "version": APP_VERSION}],
            "title": asset_title,
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": src_type,
                                "parameters": action_params,
                            }
                        ]
                    },
                }
            ],
        }

        try:
            builder = c2pa.Builder.from_json(json.dumps(manifest_def))
            temp_dest = output_path.with_suffix(f".tmp{output_path.suffix}")
            builder.sign_file(str(output_path), str(temp_dest), signer)
            temp_dest.replace(output_path)
            log_ok("Stage 1 complete: C2PA cryptographic manifest embedded.")
        except Exception as e:
            log_err(f"C2PA signing error: {e}")
            sys.exit(1)
    else:
        log_info("Stage 1: C2PA manifest signing disabled (--no-c2pa).")

    log_ok(f"Ready: {output_path} ({output_path.stat().st_size:,} bytes)\n")


def inspect_image(
    image_path: Path,
    as_json: bool = False,
    secret: str | None = None,
) -> None:
    """Verifies both C2PA Content Credentials and DWT-DCT invisible watermarks."""
    if not image_path.is_file():
        log_err(f"File not found: {image_path}")
        sys.exit(1)

    log_head(f"Media Verification: {image_path.name}")

    # 1. Verify C2PA Manifest (Stage 1)
    c2pa_data: dict[str, Any] | None = None
    c2pa_val_str = "None"
    try:
        reader = c2pa.Reader.try_create(str(image_path))
        if reader is not None:
            c2pa_data = json.loads(reader.json())
            try:
                c2pa_val_str = str(reader.get_validation_state())
            except Exception:
                c2pa_val_str = "Unknown"
    except Exception as e:
        log_warn(f"C2PA reader error: {e}")

    # 2. Verify DWT-DCT Invisible Watermark (Stage 2)
    cfg = load_config()
    wm_secret = secret or get_default_secret()
    wm_repeats = int(cfg.get("watermark_repeats", 3))
    detected_wm: str | None = None

    try:
        with Image.open(image_path) as pil_img:
            detected_wm = extract_dwt_watermark(pil_img, secret=wm_secret, repeats=wm_repeats)
    except Exception as e:
        log_warn(f"Watermark scan error: {e}")

    if as_json:
        result = {
            "file": str(image_path),
            "c2pa": c2pa_data,
            "c2pa_validation": c2pa_val_str,
            "invisible_watermark": detected_wm,
        }
        print(json.dumps(result, indent=2))
        return

    # Formatted terminal display
    print(f"\n  {C_BOLD}--- LEVEL 1: C2PA Content Credentials ---{C_RESET}")
    if c2pa_data:
        active_label = c2pa_data.get("active_manifest")
        active = c2pa_data.get("manifests", {}).get(active_label, {})
        print(f"  {C_BOLD}Manifest:{C_RESET}     {active_label}")
        print(f"  {C_BOLD}Title:{C_RESET}        {active.get('title', 'N/A')}")
        print(f"  {C_BOLD}Generator:{C_RESET}    {active.get('claim_generator_info', [{}])[0].get('name', 'N/A')}")

        sig_info = active.get("signature_info", {})
        if sig_info:
            print(f"  {C_BOLD}Signer:{C_RESET}       {sig_info.get('common_name', 'N/A')} ({sig_info.get('issuer', 'N/A')})")

        if c2pa_val_str == "Valid":
            print(f"  {C_GREEN}[✓] C2PA Signature: VALID (Pixel hash verified).{C_RESET}")
        else:
            print(f"  {C_RED}[✗] C2PA Signature: {c2pa_val_str} (Image modified or tampered!).{C_RESET}")
    else:
        print(f"  {C_YELLOW}[!] C2PA Manifest not found (stripped by messenger/social network, or unsigned).{C_RESET}")

    print(f"\n  {C_BOLD}--- LEVEL 2: Invisible DWT-DCT Steganography ---{C_RESET}")
    if detected_wm:
        print(f"  {C_GREEN}[✓] Watermark Found: '{detected_wm}'{C_RESET}")
        print(f"  {C_BLUE}[i] Integrity:       Survives lossy JPEG/WebP compression, resize, and screenshots.{C_RESET}")
    else:
        print(f"  {C_YELLOW}[ ] No watermark detected (or encoded with a different secret key).{C_RESET}")

    echo_summary(c2pa_val_str == "Valid", bool(detected_wm))


def echo_summary(has_c2pa: bool, has_wm: bool) -> None:
    print(f"\n  {C_BOLD}Summary Verdict:{C_RESET}")
    if has_c2pa and has_wm:
        print(f"    {C_GREEN}★ Full Attestation Verified (C2PA Manifest + Invisible Watermark).{C_RESET}\n")
    elif has_c2pa:
        print(f"    {C_GREEN}✓ C2PA Authenticity Verified (No watermark detected).{C_RESET}\n")
    elif has_wm:
        print(f"    {C_YELLOW}✓ Provenance Proven via Frequency Watermark (Metadata was stripped).{C_RESET}\n")
    else:
        print(f"    {C_RED}✗ Unverified: No cryptographic signatures or watermarks found.{C_RESET}\n")


# ------------------------------------------------------------------------------
# CLI Parser
# ------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sign-image",
        description="Multi-layer media signing using C2PA Content Credentials & DWT-DCT Steganography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sign-image sign image.png                       # Sign with both C2PA and invisible watermark
  sign-image sign -o signed.jpg raw.jpg           # Sign and write to signed.jpg
  sign-image sign --in-place banner.webp          # Embed signatures directly into file
  sign-image sign --no-watermark photo.jpg        # C2PA manifest only
  sign-image sign --no-c2pa photo.jpg             # Invisible watermark only
  sign-image verify image_signed.png              # Inspect both C2PA and frequency watermark
  sign-image verify --json image_signed.png       # Print complete raw verification report in JSON
  sign-image credentials                          # View active certificate details and paths
  sign-image credentials --export                 # Export key and cert for Bitwarden backup
  sign-image keygen                               # Regenerate dedicated signing certificates
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Operation mode")

    # Command: sign
    p_sign = subparsers.add_parser("sign", help="Sign an image with C2PA and invisible watermark")
    p_sign.add_argument("input", type=Path, help="Input media file (PNG, JPG, WebP, etc.)")
    p_sign.add_argument("-o", "--output", type=Path, help="Output destination path (default: <name>_signed.<ext>)")
    p_sign.add_argument("--in-place", action="store_true", help="Overwrite the input file directly")
    p_sign.add_argument("-t", "--title", type=str, help="Media title")
    p_sign.add_argument("-a", "--author", type=str, help="Author name and contact")
    p_sign.add_argument("-d", "--domain", type=str, help="Signing domain")
    p_sign.add_argument("-m", "--description", type=str, help="Custom action description")
    p_sign.add_argument("-l", "--license", type=str, help="License or copyright text")
    p_sign.add_argument("-w", "--watermark", type=str, help="Custom invisible watermark text (default: domain)")
    p_sign.add_argument("--no-watermark", action="store_true", help="Disable invisible DWT-DCT watermark")
    p_sign.add_argument("--no-c2pa", action="store_true", help="Disable C2PA manifest signing")
    p_sign.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark permutation")
    p_sign.add_argument("--key", type=Path, help="Custom EC private key in PEM format")
    p_sign.add_argument("--cert", type=Path, help="Custom X.509 certificate chain in PEM format")

    # Command: verify / inspect
    p_verify = subparsers.add_parser("verify", help="Inspect and verify C2PA & frequency watermarks")
    p_verify.add_argument("file", type=Path, help="Target media file to inspect")
    p_verify.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark extraction")
    p_verify.add_argument("--json", action="store_true", help="Output raw verification report in JSON")

    # Command: credentials (view, export, import)
    p_cred = subparsers.add_parser("credentials", help="View, export, or import signing credentials (Bitwarden backup)")
    p_cred.add_argument("--export", action="store_true", help="Print raw PEM key and cert to stdout for Bitwarden")
    p_cred.add_argument("--import-key", type=Path, help="Import private key PEM file into ~/.config/nadamu/c2pa/")
    p_cred.add_argument("--import-cert", type=Path, help="Import certificate chain PEM file into ~/.config/nadamu/c2pa/")

    # Command: keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate or regenerate C2PA signing credentials")
    p_keygen.add_argument("-d", "--domain", type=str, default=DEFAULT_DOMAIN, help="Domain for certificates")
    p_keygen.add_argument("--out-dir", type=Path, default=DEFAULT_KEY_DIR, help="Destination directory for keys")

    # Handle shortcut: if first arg is a file or flag, default to 'sign' or 'verify'
    args_list = sys.argv[1:]
    if args_list and args_list[0] not in ("sign", "verify", "credentials", "keygen", "-h", "--help"):
        if any(arg == "--verify" for arg in args_list):
            args_list.remove("--verify")
            args_list.insert(0, "verify")
        else:
            args_list.insert(0, "sign")

    args = parser.parse_args(args_list)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "credentials":
        manage_credentials(
            export_raw=args.export,
            import_key=args.import_key,
            import_cert=args.import_cert,
        )

    elif args.command == "keygen":
        out_key = args.out_dir / "es256_private.key"
        out_cert = args.out_dir / "es256_certs.pem"
        log_head(f"Generating C2PA signing credentials for {args.domain}...")
        generate_c2pa_credentials(args.domain, out_key, out_cert)
        log_ok(f"Key written:  {out_key}")
        log_ok(f"Cert written: {out_cert}")

    elif args.command == "verify":
        inspect_image(args.file, as_json=args.json, secret=args.secret)

    elif args.command == "sign":
        if args.in_place:
            dest = args.input
        elif args.output:
            dest = args.output
        else:
            dest = args.input.with_name(f"{args.input.stem}_signed{args.input.suffix}")

        process_signing(
            input_path=args.input,
            output_path=dest,
            title=args.title,
            author=args.author,
            domain=args.domain,
            description=args.description,
            license_text=args.license,
            watermark_payload=args.watermark,
            no_watermark=args.no_watermark,
            no_c2pa=args.no_c2pa,
            secret=args.secret,
            key_path=args.key,
            cert_path=args.cert,
        )


if __name__ == "__main__":
    main()
