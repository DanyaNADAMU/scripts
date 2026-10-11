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
#     "opentimestamps-client>=0.7.1",
# ]
# ///
# ==============================================================================
# Script:      sign_image.py
# Category:    media
# Description: Multi-layer media signing: C2PA Content Credentials, DWT-DCT Steganography & OpenTimestamps.
# Target:      Linux / macOS
# Requires:    python >= 3.11, uv
# Usage:       sign-image [sign|verify|stamp|credentials|keygen] [options] <file>
# ==============================================================================
from __future__ import annotations

import argparse
import binascii
import datetime
import hashlib
import io
import json
import os
import random
import re
import shutil
import subprocess
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

import otsclient.args
import otsclient.cmds
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import StreamDeserializationContext
from otsclient.cmds import DetachedTimestampFile

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "nadamu"
DEFAULT_KEY_DIR = DEFAULT_CONFIG_DIR / "c2pa"
DEFAULT_KEY_PATH = DEFAULT_KEY_DIR / "es256_private.key"
DEFAULT_CERT_PATH = DEFAULT_KEY_DIR / "es256_certs.pem"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "c2pa.json"

DEFAULT_DOMAIN = "nada.mu"
DEFAULT_AUTHOR = "DanyaNADAMU <git@nada.mu>"
DEFAULT_POLICY_URL = "https://nada.mu/.well-known/security.txt"
DEFAULT_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
DEFAULT_WATERMARK = "NADAMU"
DEFAULT_BW_ITEM = "c2pa-signer"
APP_NAME = "sign-image"
APP_VERSION = "1.4.0"

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
        "watermark_text": DEFAULT_WATERMARK,
        "watermark_delta": 35.0,
        "watermark_repeats": 3,
        "auto_stamp": False,
        "bitwarden_item": None,
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


PRIMARY_MAGIC = b"NADAMU"
VALID_MAGICS = (b"NADAMU", b"nada.mu", b"mu.nada", b"NADA")


def _make_watermark_packet(text: str) -> list[int]:
    """Frames text into a packet: [MAGIC 'NADAMU' (6B)] [LEN (1B)] [PAYLOAD] [CRC8 (1B)]."""
    raw = text.encode("utf-8")
    crc = zlib.crc32(raw) & 0xFF
    packet = PRIMARY_MAGIC + bytes([len(raw)]) + raw + bytes([crc])
    bits = []
    for b in packet:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _parse_watermark_packet(bits: list[int]) -> str | None:
    """Parses bits and validates magic header (NADAMU, nada.mu, mu.nada, NADA) and CRC8."""
    if len(bits) < 48:
        return None
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = int("".join(str(b) for b in bits[i : i + 8]), 2)
        data.append(byte_val)

    # Check supported magic prefixes in order of priority
    matched_magic: bytes | None = None
    for magic in VALID_MAGICS:
        if data.startswith(magic):
            matched_magic = magic
            break

    if not matched_magic:
        return None

    m_len = len(matched_magic)
    if len(data) < m_len + 2:
        return None

    payload_len = data[m_len]
    if len(data) < m_len + 1 + payload_len + 1:
        return None

    raw = bytes(data[m_len + 1 : m_len + 1 + payload_len])
    expected_crc = data[m_len + 1 + payload_len]
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

    # Adapt repeats if image resolution limits capacity but can still fit lower redundancy
    if repeats > 1 and len(packet_bits) * repeats > total_blocks >= len(packet_bits):
        repeats = max(1, total_blocks // len(packet_bits))

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

    max_bits = (16 + max_payload_bytes) * 8 * repeats
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

    # Try configured repetition first, then fallback to 1 (unrepeated) if needed
    repeats_candidates = [repeats] if repeats == 1 else [repeats, 1]
    for rep in repeats_candidates:
        voted_bits: list[int] = []
        for i in range(0, len(raw_bits) - rep + 1, rep):
            chunk = raw_bits[i : i + rep]
            voted_bits.append(1 if sum(chunk) > (rep // 2) else 0)

        res = _parse_watermark_packet(voted_bits)
        if res is not None:
            return res

    return None


def get_default_secret() -> str:
    """Derives a deterministic default secret from the user's C2PA private key hash."""
    if DEFAULT_KEY_PATH.is_file():
        key_data = DEFAULT_KEY_PATH.read_bytes()
        return hashlib.sha256(key_data).hexdigest()
    return "NADAMU-default-watermark-key"


# ------------------------------------------------------------------------------
# Stage 1: C2PA Key & Certificate Management
# ------------------------------------------------------------------------------
def generate_c2pa_credentials(
    domain: str = DEFAULT_DOMAIN,
    key_out: Path | None = DEFAULT_KEY_PATH,
    cert_out: Path | None = DEFAULT_CERT_PATH,
) -> tuple[bytes, bytes]:
    """Generates a compliant 2-tier C2PA X.509 certificate chain (Root CA + Leaf).
    If key_out and cert_out are None, credentials exist strictly in memory without writing to disk.
    """
    if key_out:
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

    if key_out:
        key_out.write_bytes(leaf_key_pem)
        os.chmod(key_out, 0o600)
    if cert_out:
        cert_out.write_bytes(chain_pem)

    return leaf_key_pem, chain_pem


# ------------------------------------------------------------------------------
# Bitwarden & In-Memory Vault Integration
# ------------------------------------------------------------------------------
def parse_pem_bundle(text: str) -> tuple[bytes | None, bytes | None]:
    """Extracts private key and certificate chain PEM blocks from text."""
    key_match = re.search(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
        text,
    )
    cert_matches = re.findall(
        r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
        text,
    )
    key_bytes = key_match.group(0).strip().encode("utf-8") if key_match else None
    cert_bytes = "\n".join(c.strip() for c in cert_matches).encode("utf-8") if cert_matches else None
    return key_bytes, cert_bytes


def fetch_bitwarden_credentials(item_name: str) -> tuple[bytes, bytes]:
    """Fetches C2PA private key and certificate chain directly from Bitwarden into RAM.
    Zero bytes are written to disk.
    """
    if not shutil.which("bw"):
        log_err("Bitwarden CLI ('bw') is not installed or not found on PATH.")
        log_info("Install 'bw' from https://bitwarden.com/help/cli/ to enable in-memory vault loading.")
        sys.exit(1)

    bw_session = os.environ.get("BW_SESSION")
    if not bw_session:
        res_status = subprocess.run(["bw", "status"], capture_output=True, text=True)
        try:
            status_data = json.loads(res_status.stdout)
            if status_data.get("status") != "unlocked":
                log_err("Bitwarden vault is locked or BW_SESSION is not set.")
                log_info("Unlock your vault in your shell and export the session token:")
                log_info(f"  {C_BOLD}export BW_SESSION=$(bw unlock --raw){C_RESET}")
                sys.exit(1)
        except Exception:
            log_err("Bitwarden vault is locked or BW_SESSION is not set.")
            log_info(f"  {C_BOLD}export BW_SESSION=$(bw unlock --raw){C_RESET}")
            sys.exit(1)

    log_info(f"Retrieving signing credentials from Bitwarden item '{item_name}' into RAM...")
    cmd = ["bw", "get", "item", item_name]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        log_err(f"Bitwarden item '{item_name}' not found or inaccessible: {res.stderr.strip()}")
        sys.exit(1)

    try:
        item = json.loads(res.stdout)
    except json.JSONDecodeError as e:
        log_err(f"Failed to parse Bitwarden JSON output: {e}")
        sys.exit(1)

    key_bytes: bytes | None = None
    cert_bytes: bytes | None = None

    # 1. Custom fields
    fields = item.get("fields", [])
    for field in fields:
        fname = (field.get("name") or "").lower().strip()
        fval = field.get("value") or ""
        if fname in ("key", "private_key", "privkey", "c2pa_key", "es256_key"):
            key_bytes = fval.strip().encode("utf-8")
        elif fname in ("cert", "certs", "certificate", "c2pa_cert", "chain"):
            cert_bytes = fval.strip().encode("utf-8")

    # 2. Secure Note body (e.g. pasted output of 'sign-image credentials --export')
    notes = item.get("notes") or ""
    if not key_bytes or not cert_bytes:
        k_extracted, c_extracted = parse_pem_bundle(notes)
        if not key_bytes and k_extracted:
            key_bytes = k_extracted
        if not cert_bytes and c_extracted:
            cert_bytes = c_extracted

    # 3. Item attachments
    if not key_bytes or not cert_bytes:
        item_id = item.get("id")
        attachments = item.get("attachments", [])
        for att in attachments:
            aname = att.get("fileName", "").lower()
            aid = att.get("id")
            if not key_bytes and (".key" in aname or "priv" in aname):
                log_info(f"Fetching key attachment '{att.get('fileName')}' into memory...")
                att_res = subprocess.run(
                    ["bw", "get", "attachment", aid, "--itemid", item_id, "--raw"],
                    capture_output=True,
                )
                if att_res.returncode == 0:
                    key_bytes = att_res.stdout.strip()
            elif not cert_bytes and (".pem" in aname or ".crt" in aname or "cert" in aname):
                log_info(f"Fetching certificate attachment '{att.get('fileName')}' into memory...")
                att_res = subprocess.run(
                    ["bw", "get", "attachment", aid, "--itemid", item_id, "--raw"],
                    capture_output=True,
                )
                if att_res.returncode == 0:
                    cert_bytes = att_res.stdout.strip()

    if not key_bytes or not cert_bytes:
        log_err(f"Could not find valid EC private key and certificate chain in Bitwarden item '{item_name}'.")
        log_info("Ensure the item in Bitwarden contains:")
        log_info("  • Custom fields named 'key' and 'cert'")
        log_info("  • Or a Secure Note containing PEM blocks (from 'sign-image credentials --export')")
        log_info("  • Or attachments 'es256_private.key' and 'es256_certs.pem'")
        sys.exit(1)

    log_ok("Loaded credentials from Bitwarden strictly in-memory (0 bytes stored on disk).")
    return key_bytes, cert_bytes


def save_credentials_to_bitwarden(item_name: str, key_pem: bytes, cert_pem: bytes, domain: str) -> None:
    """Stores credentials directly into Bitwarden vault as a Secure Note (zero disk writes)."""
    if not shutil.which("bw"):
        log_err("Bitwarden CLI ('bw') is required to save credentials directly to Bitwarden.")
        sys.exit(1)

    template_res = subprocess.run(["bw", "get", "template", "item"], capture_output=True, text=True)
    if template_res.returncode != 0:
        log_err(f"Failed to get Bitwarden item template: {template_res.stderr.strip()}")
        sys.exit(1)

    item_tpl = json.loads(template_res.stdout)
    item_tpl["name"] = item_name
    item_tpl["type"] = 2  # Secure Note
    item_tpl["secureNote"] = {"type": 0}
    item_tpl["notes"] = f"{key_pem.decode('utf-8').strip()}\n\n{cert_pem.decode('utf-8').strip()}\n"
    item_tpl["fields"] = [
        {"name": "key", "value": key_pem.decode("utf-8").strip(), "type": 1},
        {"name": "cert", "value": cert_pem.decode("utf-8").strip(), "type": 0},
        {"name": "domain", "value": domain, "type": 0},
    ]

    encoded_res = subprocess.run(["bw", "encode"], input=json.dumps(item_tpl), capture_output=True, text=True)
    payload = encoded_res.stdout.strip() if encoded_res.returncode == 0 else json.dumps(item_tpl)

    create_res = subprocess.run(["bw", "create", "item", payload], capture_output=True, text=True)
    if create_res.returncode != 0:
        log_err(f"Failed to create Bitwarden item: {create_res.stderr.strip()}")
        sys.exit(1)

    log_ok(f"Created Bitwarden Secure Note '{item_name}' with signing keys (Zero files written to disk).")


def load_env_credentials() -> tuple[bytes, bytes] | None:
    """Reads C2PA private key and certificate chain from environment variables if present."""
    k = os.environ.get("C2PA_PRIVATE_KEY")
    c = os.environ.get("C2PA_CERT") or os.environ.get("C2PA_CERTS")
    if k and c:
        return k.strip().encode("utf-8"), c.strip().encode("utf-8")
    return None


def load_or_create_credentials(
    key_path: Path | None = None,
    cert_path: Path | None = None,
    domain: str = DEFAULT_DOMAIN,
    bw_item: str | None = None,
) -> tuple[bytes, bytes]:
    """Loads existing credentials or fetches from Bitwarden/environment.
    If Bitwarden or environment variables are used, keys are stored strictly in memory.
    """
    # 1. Environment variables
    env_creds = load_env_credentials()
    if env_creds:
        log_info("Using C2PA credentials from environment variables (in-memory, 0 disk files).")
        return env_creds

    # 2. Bitwarden in-memory
    cfg = load_config()
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")
    if target_bw:
        return fetch_bitwarden_credentials(target_bw)

    # 3. Explicit local files
    if key_path and cert_path:
        if not key_path.is_file():
            log_err(f"Key file not found: {key_path}")
            sys.exit(1)
        if not cert_path.is_file():
            log_err(f"Cert file not found: {cert_path}")
            sys.exit(1)
        return key_path.read_bytes(), cert_path.read_bytes()

    # 4. Local disk default paths
    kp = key_path or DEFAULT_KEY_PATH
    cp = cert_path or DEFAULT_CERT_PATH

    if kp.is_file() and cp.is_file():
        return kp.read_bytes(), cp.read_bytes()

    # 5. Default generation on disk
    log_info(f"Generating persistent C2PA credentials for {domain} in {kp.parent}...")
    key_bytes, cert_bytes = generate_c2pa_credentials(domain, kp, cp)
    log_ok(f"Generated signing key: {kp}")
    log_ok(f"Generated certificate chain: {cp}")
    return key_bytes, cert_bytes


def manage_credentials(
    export_raw: bool = False,
    import_key: Path | None = None,
    import_cert: Path | None = None,
    bw_item: str | None = None,
    bw_push: str | None = None,
) -> None:
    """Exports, imports, pushes or inspects C2PA credentials in Bitwarden or local storage."""
    cfg = load_config()
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")

    if bw_push:
        # Push active credentials into Bitwarden
        if DEFAULT_KEY_PATH.is_file() and DEFAULT_CERT_PATH.is_file():
            k_bytes = DEFAULT_KEY_PATH.read_bytes()
            c_bytes = DEFAULT_CERT_PATH.read_bytes()
        else:
            log_info(f"Generating new in-memory credentials for {cfg.get('domain', DEFAULT_DOMAIN)}...")
            k_bytes, c_bytes = generate_c2pa_credentials(cfg.get("domain", DEFAULT_DOMAIN), None, None)
        save_credentials_to_bitwarden(bw_push, k_bytes, c_bytes, cfg.get("domain", DEFAULT_DOMAIN))
        log_info("Tip: You can now delete local files to keep keys strictly in Bitwarden:")
        log_info(f"  rm -f {DEFAULT_KEY_PATH} {DEFAULT_CERT_PATH}")
        return

    if target_bw and not (import_key or import_cert):
        k_bytes, c_bytes = fetch_bitwarden_credentials(target_bw)
        if export_raw:
            print("# ==============================================================================")
            print(f"# C2PA PRIVATE KEY (Bitwarden: {target_bw})")
            print("# ==============================================================================")
            print(k_bytes.decode("utf-8").strip())
            print("\n# ==============================================================================")
            print(f"# C2PA CERTIFICATE CHAIN (Bitwarden: {target_bw})")
            print("# ==============================================================================")
            print(c_bytes.decode("utf-8").strip())
            return

        certs = x509.load_pem_x509_certificates(c_bytes)
        leaf = certs[0]
        log_head(f"C2PA Signing Credentials (Active - Bitwarden: {target_bw})")
        print(f"  {C_BOLD}Key Storage:{C_RESET}  Bitwarden Vault [In-Memory Only, 0 files on disk]")
        print(f"  {C_BOLD}Subject:{C_RESET}      {leaf.subject.rfc4514_string()}")
        print(f"  {C_BOLD}Issuer:{C_RESET}       {leaf.issuer.rfc4514_string()}")
        print(f"  {C_BOLD}Fingerprint:{C_RESET}  SHA256:{leaf.fingerprint(hashes.SHA256()).hex()}")
        print(f"  {C_BOLD}Valid Until:{C_RESET}  {leaf.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  {C_BOLD}Chain Length:{C_RESET} {len(certs)} certificate(s)\n")
        return

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

    log_head("C2PA Signing Credentials (Active - Local Disk)")
    print(f"  {C_BOLD}Key Path:{C_RESET}     {DEFAULT_KEY_PATH} (0600)")
    print(f"  {C_BOLD}Cert Path:{C_RESET}    {DEFAULT_CERT_PATH}")
    print(f"  {C_BOLD}Config File:{C_RESET}  {DEFAULT_CONFIG_FILE}")
    print(f"  {C_BOLD}Subject:{C_RESET}      {leaf.subject.rfc4514_string()}")
    print(f"  {C_BOLD}Issuer:{C_RESET}       {leaf.issuer.rfc4514_string()}")
    print(f"  {C_BOLD}Fingerprint:{C_RESET}  SHA256:{leaf.fingerprint(hashes.SHA256()).hex()}")
    print(f"  {C_BOLD}Valid Until:{C_RESET}  {leaf.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {C_BOLD}Chain Length:{C_RESET} {len(certs)} certificate(s)")

    print(f"\n  {C_CYAN}[Bitwarden In-Memory Usage]:{C_RESET}")
    print("    To push local keys to Bitwarden and stop storing them on disk:")
    print(f"      {C_BOLD}sign-image credentials --bw-push c2pa-signer{C_RESET}")
    print(f"      {C_BOLD}rm -f {DEFAULT_KEY_PATH} {DEFAULT_CERT_PATH}{C_RESET}")
    print("    To sign directly with Bitwarden in RAM (zero disk files):")
    print(f"      {C_BOLD}sign-image sign --bw photo.png{C_RESET}\n")


# ------------------------------------------------------------------------------
# Stage 3: OpenTimestamps Blockchain Anchoring (Bitcoin)
# ------------------------------------------------------------------------------
DEFAULT_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
]


def stamp_media_file(
    target_file: Path,
    wait: bool = False,
    force: bool = False,
) -> Path:
    """Submits file SHA-256 to OpenTimestamps Bitcoin calendar pools and writes .ots proof."""
    if not target_file.is_file():
        log_err(f"File not found for timestamping: {target_file}")
        sys.exit(1)

    ots_path = target_file.with_name(f"{target_file.name}.ots")
    if ots_path.is_file():
        if force:
            backup_path = ots_path.with_suffix(".ots.bak")
            shutil.copyfile(ots_path, backup_path)
            ots_path.unlink()
            log_info(f"Existing timestamp backed up to {backup_path.name}")
        else:
            log_warn(f"Timestamp proof already exists: {ots_path.name} (use --force to overwrite)")
            return ots_path

    log_info(f"Stage 3: Anchoring {target_file.name} in Bitcoin blockchain (OpenTimestamps)...")

    cli_args = ["stamp"]
    if wait:
        cli_args.append("--wait")
    cli_args.append(str(target_file))

    try:
        parsed_args = otsclient.args.parse_ots_args(cli_args)
        parsed_args.cmd_func(parsed_args)
        log_ok(f"Stage 3 complete: Blockchain proof generated: {ots_path.name}")
        return ots_path
    except Exception as e:
        log_err(f"OpenTimestamps stamping failed: {e}")
        raise


def upgrade_ots_file(target_file: Path) -> bool:
    """Upgrades a pending .ots proof file, or recursively upgrades all .ots files in a directory."""
    if target_file.is_dir():
        ots_files = sorted(target_file.rglob("*.ots"))
        if not ots_files:
            log_warn(f"No .ots files found in directory: {target_file}")
            return True

        log_head(f"Upgrading {len(ots_files)} OpenTimestamps Proof(s) in {target_file}...")
        confirmed_count = 0
        pending_count = 0
        error_count = 0

        for ots_path in ots_files:
            rel_display = str(ots_path.relative_to(target_file))
            cli_args = ["upgrade", str(ots_path)]
            try:
                parsed_args = otsclient.args.parse_ots_args(cli_args)
                try:
                    parsed_args.cmd_func(parsed_args)
                    log_ok(f"Confirmed in Bitcoin: {rel_display}")
                    confirmed_count += 1
                except SystemExit as se:
                    if se.code == 0:
                        log_ok(f"Confirmed in Bitcoin: {rel_display}")
                        confirmed_count += 1
                    else:
                        log_info(f"Still pending:        {rel_display}")
                        pending_count += 1
            except Exception as e:
                log_warn(f"Failed {rel_display}: {e}")
                error_count += 1

        print(f"\n  {C_BOLD}Upgrade Summary:{C_RESET}")
        print(f"    {C_GREEN}[✓] Confirmed: {confirmed_count}{C_RESET}")
        print(f"    {C_BLUE}[i] Pending:   {pending_count}{C_RESET}")
        if error_count:
            print(f"    {C_RED}[✗] Errors:    {error_count}{C_RESET}\n")
        else:
            print()
        return error_count == 0

    ots_path = target_file if target_file.name.endswith(".ots") else target_file.with_name(f"{target_file.name}.ots")
    if not ots_path.is_file():
        log_err(f"Timestamp file not found: {ots_path}")
        sys.exit(1)

    log_head(f"Upgrading OpenTimestamps Proof: {ots_path.name}")
    cli_args = ["upgrade", str(ots_path)]

    try:
        parsed_args = otsclient.args.parse_ots_args(cli_args)
        try:
            parsed_args.cmd_func(parsed_args)
            log_ok("Timestamp upgraded successfully!")
            return True
        except SystemExit as se:
            if se.code == 0:
                log_ok("Timestamp confirmed complete in Bitcoin blockchain!")
                return True
            else:
                log_warn("Timestamp still pending confirmation in Bitcoin blockchain (calendars batch within 1-2 hours).")
                return False
    except Exception as e:
        log_err(f"Upgrade failed: {e}")
        return False


def setup_ots_timer(target_dir: Path | None, interval: str = "2h") -> None:
    """Installs and enables a systemd user timer to periodically upgrade .ots files in a directory."""
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_user_dir.mkdir(parents=True, exist_ok=True)

    chosen_dir: Path
    if target_dir is None or str(target_dir) in ("DEFAULT", "None"):
        for cand in [
            Path.home() / "Seafile" / "Icons-Proofs",
            Path.home() / "Seafile" / "Icons",
            Path.home() / "SeaDrive" / "My Libraries" / "Icons-Proofs",
            Path.home() / "SeaDrive" / "My Libraries" / "Icons",
        ]:
            if cand.is_dir():
                chosen_dir = cand
                break
        else:
            chosen_dir = Path.home() / ".config" / "nadamu"
    else:
        chosen_dir = target_dir

    chosen_dir = chosen_dir.expanduser().resolve()
    service_path = systemd_user_dir / "sign-image-ots.service"
    timer_path = systemd_user_dir / "sign-image-ots.timer"

    bin_path = shutil.which("sign-image") or str(Path(__file__).resolve())

    service_content = f"""[Unit]
Description=Periodic OpenTimestamps Proof Upgrade ({chosen_dir})
Documentation=man:sign-image(1)
After=network.target network-online.target

[Service]
Type=oneshot
ExecStart={bin_path} stamp --upgrade "{chosen_dir}"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""

    timer_content = f"""[Unit]
Description=Periodic OpenTimestamps Upgrade Timer ({interval})
Documentation=man:sign-image(1)

[Timer]
OnBootSec=5m
OnUnitActiveSec={interval}
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
"""

    service_path.write_text(service_content, encoding="utf-8")
    timer_path.write_text(timer_content, encoding="utf-8")

    log_head("OpenTimestamps Systemd User Timer Configured")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "--user", "enable", "--now", "sign-image-ots.timer"], check=False)
        log_ok("Timer successfully enabled and started.")
        print(f"  {C_BOLD}Timer Unit:{C_RESET}    {timer_path}")
        print(f"  {C_BOLD}Service Unit:{C_RESET}  {service_path}")
        print(f"  {C_BOLD}Target Folder:{C_RESET} {chosen_dir}")
        print(f"  {C_BOLD}Interval:{C_RESET}      every {interval}")
        print(f"  {C_BOLD}Status Command:{C_RESET} sign-image stamp --timer-status\n")
    else:
        log_ok(f"Unit files written to {systemd_user_dir} (systemctl not available in current session).\n")


def remove_ots_timer() -> None:
    """Disables and removes the systemd user timer for .ots upgrades."""
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    service_path = systemd_user_dir / "sign-image-ots.service"
    timer_path = systemd_user_dir / "sign-image-ots.timer"

    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", "sign-image-ots.timer"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "--user", "stop", "sign-image-ots.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    service_path.unlink(missing_ok=True)
    timer_path.unlink(missing_ok=True)

    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)

    log_ok("Systemd user timer sign-image-ots.timer removed.\n")


def show_ots_timer_status() -> None:
    """Displays the status of the systemd user timer for .ots upgrades."""
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    timer_path = systemd_user_dir / "sign-image-ots.timer"

    if not timer_path.is_file():
        log_warn("Systemd user timer is not installed.")
        print("  Install it via: sign-image stamp --setup-timer [DIR]\n")
        return

    log_head("OpenTimestamps Upgrade Timer Status")
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "status", "sign-image-ots.timer", "--no-pager"], check=False)
    else:
        print(timer_path.read_text(encoding="utf-8"))
    print()


def inspect_ots_proof(target_file: Path, ots_path: Path | None = None) -> dict[str, Any] | None:
    """Inspects and verifies an OpenTimestamps proof file for a media asset."""
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

        h = hashlib.new(algo)
        with open(target_file, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        actual_hash = h.hexdigest()

        hash_matches = (ots_hash.lower() == actual_hash.lower())

        btc_blocks = []
        pending_calendars = []
        for _, att in dt.timestamp.all_attestations():
            if isinstance(att, BitcoinBlockHeaderAttestation):
                btc_blocks.append(att.height)
            elif isinstance(att, PendingAttestation):
                pending_calendars.append(att.uri)

        status = "unknown"
        if not hash_matches:
            status = "mismatch"
        elif btc_blocks:
            status = "confirmed"
        elif pending_calendars:
            status = "pending"

        return {
            "ots_path": str(candidate_ots),
            "algorithm": algo,
            "ots_digest": ots_hash,
            "actual_digest": actual_hash,
            "hash_matches": hash_matches,
            "btc_blocks": btc_blocks,
            "pending_calendars": pending_calendars,
            "status": status,
        }
    except Exception as e:
        log_warn(f"OpenTimestamps inspection warning: {e}")
        return None


# ------------------------------------------------------------------------------
# Combined Pipeline: Sign & Inspect (Stage 1 + Stage 2 + Stage 3)
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
    stamp: bool = False,
    secret: str | None = None,
    key_path: Path | None = None,
    cert_path: Path | None = None,
    bw_item: str | None = None,
) -> None:
    """Executes multi-layer signing (DWT-DCT steganography + C2PA Credentials + OpenTimestamps)."""
    if not input_path.is_file():
        log_err(f"Input file not found: {input_path}")
        sys.exit(1)

    cfg = load_config()

    act_author = author or cfg.get("author", DEFAULT_AUTHOR)
    act_domain = domain or cfg.get("domain", DEFAULT_DOMAIN)
    act_policy = cfg.get("policy_url", DEFAULT_POLICY_URL)
    act_license = license_text or cfg.get("default_license", "")
    src_type = cfg.get("digital_source_type", DEFAULT_SOURCE_TYPE)
    wm_text = watermark_payload or cfg.get("watermark_text", DEFAULT_WATERMARK)
    wm_delta = float(cfg.get("watermark_delta", 35.0))
    wm_repeats = int(cfg.get("watermark_repeats", 3))

    asset_title = title or input_path.stem
    desc_text = description or f"Original media authored by {act_author} on {act_domain}."

    log_head(f"Signing {input_path.name}...")
    log_info(f"Title:       {asset_title}")
    log_info(f"Author:      {act_author}")
    log_info(f"Domain:      {act_domain}")
    log_info(f"Target:      {output_path}")

    # Load credentials in advance (strictly in RAM if using Bitwarden or env vars)
    key_bytes: bytes | None = None
    cert_bytes: bytes | None = None
    if not no_c2pa:
        key_bytes, cert_bytes = load_or_create_credentials(
            key_path=key_path,
            cert_path=cert_path,
            domain=act_domain,
            bw_item=bw_item,
        )

    # Derive watermark permutation secret from key bytes if not explicitly provided
    wm_secret = secret
    if not wm_secret:
        if key_bytes:
            wm_secret = hashlib.sha256(key_bytes).hexdigest()
        else:
            wm_secret = get_default_secret()

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
                save_fmt = pil_img.format or "PNG"
                wm_img.save(output_path, format=save_fmt)
                log_ok("Stage 2 complete: Watermark embedded into frequency spectrum.")
        except Exception as e:
            log_err(f"Steganographic watermarking failed: {e}")
            sys.exit(1)
    else:
        log_info("Stage 2: Invisible watermarking disabled (--no-watermark).")
        if input_path.resolve() != output_path.resolve():
            shutil.copyfile(input_path, output_path)

    # Stage 1: C2PA Content Credentials
    if not no_c2pa and key_bytes and cert_bytes:
        log_info("Stage 1: Signing with C2PA Content Credentials...")

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
        if no_c2pa:
            log_info("Stage 1: C2PA manifest signing disabled (--no-c2pa).")

    # Stage 3: OpenTimestamps Blockchain Anchoring
    if stamp or cfg.get("auto_stamp", False):
        try:
            stamp_media_file(output_path, force=True)
        except Exception as e:
            log_warn(f"Stage 3 (OpenTimestamps) encountered an issue: {e}")

    log_ok(f"Ready: {output_path} ({output_path.stat().st_size:,} bytes)\n")


def inspect_image(
    image_path: Path,
    as_json: bool = False,
    secret: str | None = None,
    ots_path: Path | None = None,
    bw_item: str | None = None,
) -> None:
    """Verifies C2PA Content Credentials, DWT-DCT invisible watermarks, and OpenTimestamps."""
    if not image_path.is_file():
        log_err(f"File not found: {image_path}")
        sys.exit(1)

    if not as_json:
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
    wm_secret = secret
    if not wm_secret:
        env_creds = load_env_credentials()
        if env_creds:
            wm_secret = hashlib.sha256(env_creds[0]).hexdigest()
    if not wm_secret:
        target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")
        if target_bw:
            try:
                k_bytes, _ = fetch_bitwarden_credentials(target_bw)
                wm_secret = hashlib.sha256(k_bytes).hexdigest()
            except Exception:
                pass
    if not wm_secret:
        wm_secret = get_default_secret()
    wm_repeats = int(cfg.get("watermark_repeats", 3))
    detected_wm: str | None = None

    try:
        with Image.open(image_path) as pil_img:
            detected_wm = extract_dwt_watermark(pil_img, secret=wm_secret, repeats=wm_repeats)
    except Exception as e:
        log_warn(f"Watermark scan error: {e}")

    # 3. Verify OpenTimestamps Proof (Stage 3)
    ots_data = inspect_ots_proof(image_path, ots_path=ots_path)

    if as_json:
        result = {
            "file": str(image_path),
            "c2pa": c2pa_data,
            "c2pa_validation": c2pa_val_str,
            "invisible_watermark": detected_wm,
            "opentimestamps": ots_data,
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

    print(f"\n  {C_BOLD}--- LEVEL 3: OpenTimestamps (Bitcoin Blockchain) ---{C_RESET}")
    if ots_data:
        proof_name = Path(ots_data["ots_path"]).name
        print(f"  {C_BOLD}Proof File:{C_RESET}   {proof_name}")
        print(f"  {C_BOLD}Target Hash:{C_RESET}  {ots_data['ots_digest']} ({ots_data['algorithm']})")
        if ots_data["hash_matches"]:
            print(f"  {C_GREEN}[✓] File Hash:    MATCH (Content verified against timestamp).{C_RESET}")
        else:
            print(f"  {C_RED}[✗] File Hash:    MISMATCH (File has been altered since timestamping!).{C_RESET}")

        if ots_data["status"] == "confirmed":
            blocks_str = ", ".join(f"#{b}" for b in ots_data["btc_blocks"])
            print(f"  {C_GREEN}[✓] Blockchain:   CONFIRMED in Bitcoin Block(s): {blocks_str}{C_RESET}")
        elif ots_data["status"] == "pending":
            print(f"  {C_BLUE}[i] Blockchain:   PENDING confirmation (aggregated across {len(ots_data['pending_calendars'])} calendars).{C_RESET}")
            print(f"                    Run '{C_BOLD}sign-image stamp --upgrade {proof_name}{C_RESET}' once mined.")
        elif ots_data["status"] == "mismatch":
            print(f"  {C_RED}[✗] Blockchain:   UNVERIFIED due to file hash mismatch.{C_RESET}")
    else:
        print(f"  {C_YELLOW}[ ] No OpenTimestamps proof found (<name>.ots).{C_RESET}")

    echo_summary(
        c2pa_val_str == "Valid",
        bool(detected_wm),
        ots_data["status"] if ots_data else None,
    )


def echo_summary(has_c2pa: bool, has_wm: bool, ots_status: str | None = None) -> None:
    print(f"\n  {C_BOLD}Summary Verdict:{C_RESET}")
    ots_valid = (ots_status in ("confirmed", "pending"))

    if has_c2pa and has_wm and ots_valid:
        print(f"    {C_GREEN}★ Full Triple-Layer Attestation Verified (C2PA + Steganography + OpenTimestamps).{C_RESET}\n")
    elif has_c2pa and has_wm:
        print(f"    {C_GREEN}★ Dual-Layer Provenance Verified (C2PA Manifest + Invisible Watermark).{C_RESET}\n")
    elif has_c2pa and ots_valid:
        print(f"    {C_GREEN}✓ C2PA Authenticity & Blockchain Timestamp Verified.{C_RESET}\n")
    elif has_wm and ots_valid:
        print(f"    {C_YELLOW}✓ Provenance Proven via Frequency Watermark & Blockchain Timestamp (Metadata was stripped).{C_RESET}\n")
    elif has_c2pa:
        print(f"    {C_GREEN}✓ C2PA Authenticity Verified (No watermark or blockchain timestamp).{C_RESET}\n")
    elif has_wm:
        print(f"    {C_YELLOW}✓ Provenance Proven via Frequency Watermark (Metadata was stripped).{C_RESET}\n")
    elif ots_valid:
        print(f"    {C_BLUE}✓ Blockchain Existence Verified at Timestamp (No C2PA or watermark).{C_RESET}\n")
    else:
        print(f"    {C_RED}✗ Unverified: No cryptographic signatures, watermarks, or timestamps found.{C_RESET}\n")


# ------------------------------------------------------------------------------
# CLI Parser
# ------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sign-image",
        description="Multi-layer media signing: C2PA Content Credentials, DWT-DCT Steganography & OpenTimestamps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sign-image sign image.png                       # Sign with C2PA and invisible watermark
  sign-image sign --bw image.png                  # Sign using keys directly from Bitwarden into RAM (0 disk files)
  sign-image sign --bw-item "my-key" image.png    # Use custom Bitwarden item
  sign-image sign --stamp image.png               # Sign with all 3 layers (C2PA + Watermark + OpenTimestamps)
  sign-image sign -o signed.jpg raw.jpg           # Sign and write to custom destination
  sign-image sign --in-place banner.webp          # Embed signatures directly into file
  sign-image sign --no-watermark photo.jpg        # C2PA manifest only
  sign-image sign --no-c2pa photo.jpg             # Invisible watermark only
  sign-image verify image_signed.png              # Inspect all 3 attestation layers
  sign-image verify --bw image_signed.png         # Verify watermark using secret key in Bitwarden
  sign-image verify --json image_signed.png       # Print complete raw verification report in JSON
  sign-image stamp photo.png                      # Anchor existing image into Bitcoin blockchain
  sign-image stamp --upgrade photo.png.ots        # Upgrade pending timestamp to confirmed Bitcoin block
  sign-image credentials                          # View active certificate details and paths
  sign-image credentials --bw                     # View credentials stored in Bitwarden
  sign-image credentials --bw-push c2pa-signer    # Push local credentials directly into Bitwarden vault
  sign-image credentials --export                 # Export key and cert for Bitwarden backup
  sign-image keygen --bw                          # Generate keys directly in Bitwarden (0 disk files)
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
    p_sign.add_argument("-w", "--watermark", type=str, help="Custom invisible watermark text (default: NADAMU)")
    p_sign.add_argument("--no-watermark", action="store_true", help="Disable invisible DWT-DCT watermark")
    p_sign.add_argument("--no-c2pa", action="store_true", help="Disable C2PA manifest signing")
    p_sign.add_argument("--stamp", action="store_true", help="Anchor signed file in Bitcoin blockchain via OpenTimestamps")
    p_sign.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark permutation")
    p_sign.add_argument("--key", type=Path, help="Custom EC private key in PEM format")
    p_sign.add_argument("--cert", type=Path, help="Custom X.509 certificate chain in PEM format")
    p_sign.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Fetch C2PA credentials strictly from Bitwarden into RAM (zero local disk storage)")

    # Command: verify / inspect
    p_verify = subparsers.add_parser("verify", help="Inspect and verify C2PA, watermarks & OpenTimestamps")
    p_verify.add_argument("file", type=Path, help="Target media file to inspect")
    p_verify.add_argument("--ots", type=Path, help="Path to custom or detached .ots proof file")
    p_verify.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark extraction")
    p_verify.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Fetch watermark secret from Bitwarden into RAM for verification")
    p_verify.add_argument("--json", action="store_true", help="Output raw verification report in JSON")

    # Command: stamp (standalone OpenTimestamps anchoring, upgrading, and scheduling)
    p_stamp = subparsers.add_parser("stamp", help="Anchor, upgrade, or schedule timers in Bitcoin blockchain (OpenTimestamps)")
    p_stamp.add_argument("file", type=Path, nargs="?", default=None, help="Target media file, directory, or .ots proof file")
    p_stamp.add_argument("--upgrade", action="store_true", help="Upgrade pending .ots proof against Bitcoin calendars (file or directory)")
    p_stamp.add_argument("--wait", action="store_true", help="Wait until confirmation block is available")
    p_stamp.add_argument("-f", "--force", action="store_true", help="Overwrite existing .ots file")
    p_stamp.add_argument("--setup-timer", nargs="?", const="DEFAULT", type=Path, help="Install and enable systemd user timer to periodically upgrade .ots files in a directory")
    p_stamp.add_argument("--remove-timer", action="store_true", help="Disable and remove the systemd user timer for .ots upgrades")
    p_stamp.add_argument("--timer-status", action="store_true", help="Check status of systemd user timer for .ots upgrades")
    p_stamp.add_argument("--timer-interval", type=str, default="2h", help="Interval for systemd timer (default: 2h)")

    # Command: credentials (view, export, import, bitwarden)
    p_cred = subparsers.add_parser("credentials", help="View, export, import, or push signing credentials (Bitwarden vault)")
    p_cred.add_argument("--export", action="store_true", help="Print raw PEM key and cert to stdout for Bitwarden")
    p_cred.add_argument("--import-key", type=Path, help="Import private key PEM file into ~/.config/nadamu/c2pa/")
    p_cred.add_argument("--import-cert", type=Path, help="Import certificate chain PEM file into ~/.config/nadamu/c2pa/")
    p_cred.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Inspect or export credentials stored in Bitwarden vault")
    p_cred.add_argument("--bw-push", type=str, help="Push local credentials directly into Bitwarden vault as Secure Note")

    # Command: keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate or regenerate C2PA signing credentials")
    p_keygen.add_argument("-d", "--domain", type=str, default=DEFAULT_DOMAIN, help="Domain for certificates")
    p_keygen.add_argument("--out-dir", type=Path, default=DEFAULT_KEY_DIR, help="Destination directory for keys")
    p_keygen.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Store generated credentials directly in Bitwarden vault without writing to disk")

    # Handle shortcut: if first arg is a file or flag, default to 'sign' or 'verify'
    args_list = sys.argv[1:]
    if args_list and args_list[0] not in ("sign", "verify", "stamp", "credentials", "keygen", "-h", "--help"):
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
            bw_item=args.bw_item,
            bw_push=args.bw_push,
        )

    elif args.command == "keygen":
        if args.bw_item:
            log_head(f"Generating C2PA signing credentials for {args.domain} (Bitwarden: {args.bw_item})...")
            k_bytes, c_bytes = generate_c2pa_credentials(args.domain, key_out=None, cert_out=None)
            save_credentials_to_bitwarden(args.bw_item, k_bytes, c_bytes, args.domain)
        else:
            out_key = args.out_dir / "es256_private.key"
            out_cert = args.out_dir / "es256_certs.pem"
            log_head(f"Generating C2PA signing credentials for {args.domain}...")
            generate_c2pa_credentials(args.domain, out_key, out_cert)
            log_ok(f"Key written:  {out_key}")
            log_ok(f"Cert written: {out_cert}")

    elif args.command == "stamp":
        if args.setup_timer is not None:
            setup_ots_timer(args.setup_timer, interval=args.timer_interval)
        elif args.remove_timer:
            remove_ots_timer()
        elif args.timer_status:
            show_ots_timer_status()
        elif args.upgrade:
            if not args.file:
                log_err("Please specify a target file or directory: sign-image stamp --upgrade <path>")
                sys.exit(1)
            upgrade_ots_file(args.file)
        else:
            if not args.file:
                log_err("Please specify a file to timestamp: sign-image stamp <file>")
                sys.exit(1)
            stamp_media_file(args.file, wait=args.wait, force=args.force)

    elif args.command == "verify":
        inspect_image(args.file, as_json=args.json, secret=args.secret, ots_path=args.ots, bw_item=args.bw_item)

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
            stamp=args.stamp,
            secret=args.secret,
            key_path=args.key,
            cert_path=args.cert,
            bw_item=args.bw_item,
        )


if __name__ == "__main__":
    main()
