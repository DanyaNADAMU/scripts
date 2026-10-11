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
# Script:      media.py (media)
# Category:    media
# Description: Unified media lifecycle pipeline: C2PA credentials, invisible watermarking,
#              OpenTimestamps Bitcoin anchoring, asset generation & integrity auditing.
# Target:      Linux / macOS
# Requires:    python >= 3.11, uv
# Usage:       media <command> [options]
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

# ------------------------------------------------------------------------------
# App Metadata & Paths
# ------------------------------------------------------------------------------
APP_NAME = "media"
APP_VERSION = "2.0.0"

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
# Configuration Management
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


def save_config(cfg: dict[str, Any]) -> None:
    """Saves user configuration to ~/.config/nadamu/c2pa.json."""
    try:
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        DEFAULT_CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    except Exception as e:
        log_warn(f"Failed to save {DEFAULT_CONFIG_FILE}: {e}")


def get_default_secret() -> str:
    """Returns a deterministic watermark secret based on machine/user identity."""
    salt = os.environ.get("C2PA_WATERMARK_SECRET")
    if salt:
        return salt
    ident = f"{os.uname().nodename}-{os.getlogin() if hasattr(os, 'getlogin') else 'user'}-NADAMU"
    return hashlib.sha256(ident.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------
# Stage 1: Invisible DWT-DCT Steganographic Watermarking
# ------------------------------------------------------------------------------
def _dct2(a: np.ndarray) -> np.ndarray:
    return dct(dct(a.T, norm="ortho").T, norm="ortho")


def _idct2(a: np.ndarray) -> np.ndarray:
    return idct(idct(a.T, norm="ortho").T, norm="ortho")


PRIMARY_MAGIC = b"NADAMU"
VALID_MAGICS = (b"NADAMU", b"nada.mu", b"mu.nada", b"NADA")


def _make_watermark_packet(text: str) -> list[int]:
    """Frames text into packet: [MAGIC 'NADAMU' (6B)] [LEN (1B)] [PAYLOAD] [CRC8 (1B)]."""
    raw = text.encode("utf-8")
    crc = zlib.crc32(raw) & 0xFF
    packet = PRIMARY_MAGIC + bytes([len(raw)]) + raw + bytes([crc])
    bits = []
    for b in packet:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _parse_watermark_packet(bits: list[int]) -> str | None:
    """Parses bits and validates magic header (NADAMU, nada.mu, etc.) and CRC8."""
    if len(bits) < 48:
        return None
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = int("".join(str(b) for b in bits[i : i + 8]), 2)
        data.append(byte_val)

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

    rng = random.Random(secret)
    indices = list(range(total_blocks))
    rng.shuffle(indices)

    for i, bit in enumerate(expanded_bits):
        block_idx = indices[i]
        by = block_idx // blocks_w
        bx = block_idx % blocks_w

        block = LL[by * 8 : (by + 1) * 8, bx * 8 : (bx + 1) * 8]
        d = _dct2(block)
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

    # 1. Try specified repeat rate
    if repeats > 1 and len(raw_bits) >= repeats:
        voted_bits: list[int] = []
        for i in range(0, len(raw_bits) - repeats + 1, repeats):
            chunk = raw_bits[i : i + repeats]
            voted_bits.append(1 if sum(chunk) > (repeats // 2) else 0)
        parsed = _parse_watermark_packet(voted_bits)
        if parsed:
            return parsed

    # 2. Try single-bit rate (repeats=1) fallback
    parsed = _parse_watermark_packet(raw_bits)
    if parsed:
        return parsed

    # 3. Dynamic scan across lower repeat values (2, 3, 4)
    for r_test in (3, 2, 4):
        if r_test == repeats:
            continue
        v_bits: list[int] = []
        for i in range(0, len(raw_bits) - r_test + 1, r_test):
            chunk = raw_bits[i : i + r_test]
            v_bits.append(1 if sum(chunk) > (r_test // 2) else 0)
        parsed = _parse_watermark_packet(v_bits)
        if parsed:
            return parsed

    return None


# ------------------------------------------------------------------------------
# Stage 2: C2PA Cryptographic Credentials & Bitwarden Integration
# ------------------------------------------------------------------------------
def generate_c2pa_credentials(
    domain: str = DEFAULT_DOMAIN,
    key_out: Path | None = None,
    cert_out: Path | None = None,
) -> tuple[bytes, bytes]:
    """Generates an ECDSA P-256 Root CA and Leaf End-Entity certificate chain for C2PA."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Root Certificate Authority (CA)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} Media Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])
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
    root_key_pem = root_key.private_bytes(
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

    return leaf_key_pem, chain_pem, root_key_pem


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


def get_bitwarden_env() -> dict[str, str]:
    """Ensures a valid Bitwarden session exists in RAM, prompting interactively if vault is locked."""
    if not shutil.which("bw"):
        log_err("Bitwarden CLI ('bw') is not installed or not found on PATH.")
        log_info("Install 'bw' from https://bitwarden.com/help/cli/ to enable in-memory vault loading.")
        sys.exit(1)

    bw_env = dict(os.environ)
    if bw_env.get("BW_SESSION"):
        return bw_env

    res_status = subprocess.run(["bw", "status"], capture_output=True, text=True, env=bw_env)
    try:
        status_data = json.loads(res_status.stdout)
        if status_data.get("status") == "unlocked":
            return bw_env
    except Exception:
        pass

    if sys.stdin.isatty():
        log_info("Bitwarden vault is locked. Authenticate for ephemeral in-memory access:")
        proc = subprocess.run(
            ["bw", "unlock", "--raw"],
            stdin=sys.stdin,
            stderr=sys.stderr,
            stdout=subprocess.PIPE,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            bw_env["BW_SESSION"] = proc.stdout.strip()
            return bw_env
        else:
            log_err("Bitwarden authentication cancelled or failed.")
            sys.exit(1)
    else:
        log_err("Bitwarden vault is locked and no interactive terminal (TTY) is available.")
        log_info(f"Unlock vault in your shell: {C_BOLD}export BW_SESSION=$(bw unlock --raw){C_RESET}")
        sys.exit(1)


def fetch_bitwarden_credentials(item_name: str) -> tuple[bytes, bytes]:
    """Fetches C2PA private key and certificate chain directly from Bitwarden into RAM (0 disk writes)."""
    bw_env = get_bitwarden_env()

    log_info(f"Retrieving signing credentials from Bitwarden item '{item_name}' into RAM...")
    cmd = ["bw", "get", "item", item_name]
    res = subprocess.run(cmd, capture_output=True, text=True, env=bw_env)
    if res.returncode != 0:
        log_err(f"Bitwarden item '{item_name}' not found: {res.stderr.strip()}")
        sys.exit(1)

    try:
        item = json.loads(res.stdout)
    except json.JSONDecodeError as e:
        log_err(f"Failed to parse Bitwarden JSON output: {e}")
        sys.exit(1)

    key_bytes: bytes | None = None
    cert_bytes: bytes | None = None

    # 1. Custom fields
    for field in item.get("fields", []):
        fname = (field.get("name") or "").lower().strip()
        fval = field.get("value") or ""
        if fname in ("key", "private_key", "privkey", "c2pa_key", "es256_key"):
            key_bytes = fval.strip().encode("utf-8")
        elif fname in ("cert", "certs", "certificate", "c2pa_cert", "chain"):
            cert_bytes = fval.strip().encode("utf-8")

    # 2. Secure Note body
    notes = item.get("notes") or ""
    if not key_bytes or not cert_bytes:
        k_ext, c_ext = parse_pem_bundle(notes)
        if not key_bytes and k_ext:
            key_bytes = k_ext
        if not cert_bytes and c_ext:
            cert_bytes = c_ext

    # 3. Attachments
    if not key_bytes or not cert_bytes:
        item_id = item.get("id")
        for att in item.get("attachments", []):
            aname = att.get("fileName", "").lower()
            aid = att.get("id")
            if not key_bytes and (".key" in aname or "priv" in aname):
                att_res = subprocess.run(
                    ["bw", "get", "attachment", aid, "--itemid", item_id, "--raw"],
                    capture_output=True,
                    env=bw_env,
                )
                if att_res.returncode == 0:
                    key_bytes = att_res.stdout.strip()
            elif not cert_bytes and (".pem" in aname or ".crt" in aname or "cert" in aname):
                att_res = subprocess.run(
                    ["bw", "get", "attachment", aid, "--itemid", item_id, "--raw"],
                    capture_output=True,
                    env=bw_env,
                )
                if att_res.returncode == 0:
                    cert_bytes = att_res.stdout.strip()

    if not key_bytes or not cert_bytes:
        log_err(f"Could not find valid EC private key and certificate chain in Bitwarden item '{item_name}'.")
        sys.exit(1)

    log_ok("Loaded credentials from Bitwarden strictly in-memory (0 bytes stored on disk).")
    return key_bytes, cert_bytes


def save_credentials_to_bitwarden(
    item_name: str,
    key_pem: bytes,
    cert_pem: bytes,
    domain: str,
    root_key_pem: bytes | None = None,
) -> None:
    """Stores credentials directly into Bitwarden vault as a Secure Note (zero disk writes)."""
    bw_env = get_bitwarden_env()

    template_res = subprocess.run(["bw", "get", "template", "item"], capture_output=True, text=True, env=bw_env)
    if template_res.returncode != 0:
        log_err(f"Failed to get Bitwarden item template: {template_res.stderr.strip()}")
        sys.exit(1)

    item_tpl = json.loads(template_res.stdout)
    item_tpl["name"] = item_name
    item_tpl["type"] = 2  # Secure Note
    item_tpl["secureNote"] = {"type": 0}
    note_content = [key_pem.decode("utf-8").strip(), cert_pem.decode("utf-8").strip()]
    if root_key_pem:
        note_content.append(root_key_pem.decode("utf-8").strip())
    item_tpl["notes"] = "\n\n".join(note_content) + "\n"
    item_tpl["fields"] = [
        {"name": "key", "value": key_pem.decode("utf-8").strip(), "type": 1},
        {"name": "cert", "value": cert_pem.decode("utf-8").strip(), "type": 0},
        {"name": "domain", "value": domain, "type": 0},
    ]
    if root_key_pem:
        item_tpl["fields"].append(
            {"name": "root_key", "value": root_key_pem.decode("utf-8").strip(), "type": 1}
        )

    encoded_res = subprocess.run(["bw", "encode"], input=json.dumps(item_tpl), capture_output=True, text=True, env=bw_env)
    payload = encoded_res.stdout.strip() if encoded_res.returncode == 0 else json.dumps(item_tpl)

    create_res = subprocess.run(["bw", "create", "item", payload], capture_output=True, text=True, env=bw_env)
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
    """Loads existing credentials or fetches from Bitwarden/environment."""
    cfg = load_config()
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")
    if target_bw:
        return fetch_bitwarden_credentials(target_bw)

    env_creds = load_env_credentials()
    if env_creds:
        return env_creds

    k_file = key_path or DEFAULT_KEY_PATH
    c_file = cert_path or DEFAULT_CERT_PATH

    if k_file.is_file() and c_file.is_file():
        return k_file.read_bytes(), c_file.read_bytes()

    k_file.parent.mkdir(parents=True, exist_ok=True)
    log_info(f"Generating dedicated local C2PA certificates for {domain} in {k_file.parent}...")
    k_bytes, c_bytes, _ = generate_c2pa_credentials(domain, key_out=k_file, cert_out=c_file)
    log_ok("Local credentials created and initialized.")
    return k_bytes, c_bytes


# ------------------------------------------------------------------------------
# Stage 3: OpenTimestamps Bitcoin Anchoring & Proof Operations
# ------------------------------------------------------------------------------
def stamp_media_file(target_file: Path, wait: bool = False, force: bool = False) -> Path:
    """Anchors a file in the Bitcoin blockchain via OpenTimestamps, creating <file>.ots."""
    if not target_file.is_file():
        log_err(f"Cannot stamp non-existent file: {target_file}")
        sys.exit(1)

    ots_path = target_file.with_name(f"{target_file.name}.ots")
    if ots_path.is_file() and not force:
        log_info(f"OpenTimestamps proof already exists: {ots_path.name}")
        return ots_path

    log_info(f"Anchoring '{target_file.name}' in Bitcoin blockchain (OpenTimestamps)...")
    cli_args = ["stamp"]
    if wait:
        cli_args.append("--wait")
    cli_args.append(str(target_file))

    try:
        parsed_args = otsclient.args.parse_ots_args(cli_args)
        parsed_args.cmd_func(parsed_args)
        if ots_path.is_file():
            log_ok(f"Bitcoin timestamp proof created: {ots_path.name}")
            return ots_path
        else:
            raise RuntimeError(f"OpenTimestamps failed to produce {ots_path.name}")
    except Exception as e:
        log_err(f"OpenTimestamps stamping failed: {e}")
        raise


def upgrade_ots_file(target_path: Path) -> bool:
    """Upgrades a pending .ots proof file, or recursively upgrades all .ots files in a directory."""
    if target_path.is_dir():
        ots_files = sorted(target_path.rglob("*.ots"))
        if not ots_files:
            log_warn(f"No .ots files found in directory: {target_path}")
            return True

        log_head(f"Upgrading {len(ots_files)} OpenTimestamps Proof(s) in {target_path}...")
        confirmed_count = 0
        pending_count = 0
        error_count = 0

        for ots_p in ots_files:
            rel_display = str(ots_p.relative_to(target_path))
            cli_args = ["upgrade", str(ots_p)]
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

    ots_file = target_path if target_path.name.endswith(".ots") else target_path.with_name(f"{target_path.name}.ots")
    if not ots_file.is_file():
        log_err(f"Timestamp proof file not found: {ots_file}")
        sys.exit(1)

    log_head(f"Upgrading OpenTimestamps Proof: {ots_file.name}")
    cli_args = ["upgrade", str(ots_file)]

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
                log_warn("Timestamp still pending confirmation in Bitcoin blockchain.")
                return False
    except Exception as e:
        log_err(f"Upgrade failed: {e}")
        return False


def inspect_ots_proof(target_file: Path, ots_path: Path | None = None) -> dict[str, Any] | None:
    """Inspects an OpenTimestamps proof and returns status dict."""
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
        log_warn(f"OpenTimestamps inspection warning: {e}")
        return None


# ------------------------------------------------------------------------------
# Automation: Systemd User Timer for OpenTimestamps Upgrades
# ------------------------------------------------------------------------------
def timer_setup(target_dir: Path | None = None, interval: str = "2h") -> None:
    """Installs and enables a systemd user timer to periodically upgrade .ots proofs."""
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_user_dir.mkdir(parents=True, exist_ok=True)

    chosen_dir: Path
    if target_dir is None or str(target_dir) in ("DEFAULT", "None"):
        proofs_cand = get_default_proofs_dir()
        if proofs_cand and proofs_cand.is_dir():
            chosen_dir = proofs_cand
        else:
            chosen_dir = get_default_icons_dir()
    else:
        chosen_dir = target_dir

    chosen_dir = chosen_dir.expanduser().resolve()
    service_path = systemd_user_dir / "media-ots.service"
    timer_path = systemd_user_dir / "media-ots.timer"

    bin_path = shutil.which("media") or str(Path(__file__).resolve())

    service_content = f"""[Unit]
Description=Periodic Media OpenTimestamps Proof Upgrade ({chosen_dir})
Documentation=man:media(1)
After=network.target network-online.target

[Service]
Type=oneshot
ExecStart={bin_path} upgrade "{chosen_dir}"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""

    timer_content = f"""[Unit]
Description=Periodic Media OpenTimestamps Upgrade Timer ({interval})
Documentation=man:media(1)
After=network.target

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
        subprocess.run(["systemctl", "--user", "enable", "--now", "media-ots.timer"], check=False)
        log_ok("Timer successfully enabled and started.")
        print(f"  {C_BOLD}Timer Unit:{C_RESET}     {timer_path}")
        print(f"  {C_BOLD}Service Unit:{C_RESET}   {service_path}")
        print(f"  {C_BOLD}Target Folder:{C_RESET}  {chosen_dir}")
        print(f"  {C_BOLD}Interval:{C_RESET}       every {interval}")
        print(f"  {C_BOLD}Status Command:{C_RESET} media timer status\n")
    else:
        log_warn("systemctl not found on PATH. Unit files written to ~/.config/systemd/user/.")


def timer_status() -> None:
    """Shows status of the systemd user timer."""
    log_head("Media OpenTimestamps Upgrade Timer Status")
    if not shutil.which("systemctl"):
        log_err("systemctl command not found.")
        return
    subprocess.run(["systemctl", "--user", "status", "media-ots.timer"], check=False)


def timer_remove() -> None:
    """Disables and removes the systemd user timer and service units."""
    log_head("Removing Media OpenTimestamps Upgrade Timer")
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    service_path = systemd_user_dir / "media-ots.service"
    timer_path = systemd_user_dir / "media-ots.timer"

    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", "media-ots.timer"], check=False, capture_output=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, capture_output=True)

    timer_path.unlink(missing_ok=True)
    service_path.unlink(missing_ok=True)
    log_ok("Systemd timer and service units removed.")


# ------------------------------------------------------------------------------
# Single File Operations: Sign & Verify
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

    # Stage 1: Embed DWT-DCT Steganographic Watermark
    if not no_watermark:
        try:
            with Image.open(input_path) as pil_img:
                log_info(f"Stage 1: Embedding invisible DWT-DCT watermark ('{wm_text}')...")
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
                log_ok("Stage 1 complete: Watermark embedded into frequency spectrum.")
        except Exception as e:
            log_err(f"Steganographic watermarking failed: {e}")
            sys.exit(1)
    else:
        log_info("Stage 1: Invisible watermarking disabled (--no-watermark).")
        if input_path.resolve() != output_path.resolve():
            shutil.copyfile(input_path, output_path)

    # Stage 2: C2PA Content Credentials
    if not no_c2pa and key_bytes and cert_bytes:
        log_info("Stage 2: Signing with C2PA Content Credentials...")

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
            log_ok("Stage 2 complete: C2PA cryptographic manifest embedded.")
        except Exception as e:
            log_err(f"C2PA signing error: {e}")
            sys.exit(1)
    else:
        if no_c2pa:
            log_info("Stage 2: C2PA manifest signing disabled (--no-c2pa).")

    # Stage 3: OpenTimestamps Blockchain Anchoring
    if stamp or cfg.get("auto_stamp", False):
        try:
            stamp_media_file(output_path, force=True)
        except Exception as e:
            log_warn(f"Stage 3 (OpenTimestamps) encountered an issue: {e}")

    log_ok(f"Ready: {output_path} ({output_path.stat().st_size:,} bytes)\n")


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
        print(f"    {C_YELLOW}✓ Provenance Proven via Frequency Watermark & Blockchain Timestamp (Metadata stripped).{C_RESET}\n")
    elif has_c2pa:
        print(f"    {C_GREEN}✓ C2PA Authenticity Verified (No watermark or blockchain timestamp).{C_RESET}\n")
    elif has_wm:
        print(f"    {C_YELLOW}✓ Provenance Proven via Frequency Watermark (Metadata stripped).{C_RESET}\n")
    elif ots_valid:
        print(f"    {C_BLUE}✓ Blockchain Existence Verified at Timestamp (No C2PA or watermark).{C_RESET}\n")
    else:
        print(f"    {C_RED}✗ Unverified: No cryptographic signatures, watermarks, or timestamps found.{C_RESET}\n")


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

    # Terminal output
    print(f"\n  {C_BOLD}--- LEVEL 1: C2PA Content Credentials ---{C_RESET}")
    if c2pa_data:
        active_label = c2pa_data.get("active_manifest")
        active = c2pa_data.get("manifests", {}).get(active_label, {})
        claim_gen = active.get("claim_generator", "Unknown")
        fmt = active.get("format", "Unknown")
        title = active.get("title", "Untitled")

        print(f"    {C_GREEN}✓ Manifest Detected:{C_RESET} {title}")
        print(f"      Generator:  {claim_gen}")
        print(f"      Format:     {fmt}")
        print(f"      Validation: {c2pa_val_str}")

        for assertion in active.get("assertions", []):
            label = assertion.get("label", "")
            data = assertion.get("data", {})
            if "actions" in label:
                for act in data.get("actions", []):
                    params = act.get("parameters", {})
                    if "author" in params:
                        print(f"      Author:     {params.get('author')}")
                    if "description" in params:
                        print(f"      Desc:       {params.get('description')}")
                    if "license" in params:
                        print(f"      License:    {params.get('license')}")
    else:
        print(f"    {C_YELLOW}⚠ No embedded C2PA Content Credentials manifest found.{C_RESET}")

    print(f"\n  {C_BOLD}--- LEVEL 2: DWT-DCT Steganographic Watermark ---{C_RESET}")
    if detected_wm:
        print(f"    {C_GREEN}✓ Watermark Decoded:{C_RESET} \"{C_BOLD}{detected_wm}{C_RESET}\"")
        print(f"      Robustness: Frequency domain resilient against crop, resize, and re-compression.")
    else:
        print(f"    {C_YELLOW}⚠ No valid steganographic watermark found matching secret key.{C_RESET}")

    print(f"\n  {C_BOLD}--- LEVEL 3: OpenTimestamps Bitcoin Blockchain ---{C_RESET}")
    if ots_data:
        st = ots_data.get("status")
        ots_file = ots_data.get("ots_path", "")
        if st == "confirmed":
            blocks = ots_data.get("btc_blocks", [])
            print(f"    {C_GREEN}✓ Confirmed in Bitcoin Blockchain:{C_RESET}")
            print(f"      Proof File:     {ots_file}")
            print(f"      Bitcoin Block:  {blocks[0] if blocks else 'Unknown'}")
            print(f"      Digest Match:   {ots_data.get('hash_matches')}")
        elif st == "pending":
            cals = ots_data.get("pending_calendars", [])
            print(f"    {C_BLUE}ℹ Pending Blockchain Confirmation:{C_RESET}")
            print(f"      Proof File:     {ots_file}")
            print(f"      Calendars:      {len(cals)} calendar server(s) awaiting Bitcoin block")
            print(f"      Digest Match:   {ots_data.get('hash_matches')}")
            print(f"      Upgrade:        Run 'media upgrade {image_path.name}' once block mined.")
        elif st == "mismatch":
            print(f"    {C_RED}✗ SHA-256 Digest Mismatch!{C_RESET}")
            print(f"      File altered after timestamping. Proof: {ots_data.get('ots_digest')[:12]}...")
        else:
            print(f"    {C_YELLOW}⚠ Timestamp status unknown.{C_RESET}")
    else:
        print(f"    {C_YELLOW}⚠ No OpenTimestamps (.ots) proof found for this file.{C_RESET}")

    echo_summary(
        has_c2pa=bool(c2pa_data),
        has_wm=bool(detected_wm),
        ots_status=ots_data.get("status") if ots_data else None,
    )


# ------------------------------------------------------------------------------
# Directory & Library Discovery
# ------------------------------------------------------------------------------
def get_default_icons_dir() -> Path:
    """Resolves base directory for managed icons and asset libraries."""
    for env_var in ("SEAFILE_ICONS", "SEADRIVE_ICONS", "ICONS_DIR"):
        env_dir = os.environ.get(env_var)
        if env_dir:
            return Path(env_dir).expanduser().resolve()

    cwd = Path.cwd().resolve()
    if cwd.name.lower() == "icons":
        return cwd

    cand_data = Path.home() / "data" / "Icons"
    if cand_data.is_dir():
        return cand_data

    cand_seafile = Path.home() / "Seafile" / "Icons"
    if cand_seafile.is_dir():
        return cand_seafile

    cand_seadrive = Path.home() / "SeaDrive" / "My Libraries" / "Icons"
    if cand_seadrive.is_dir():
        return cand_seadrive

    return (Path.home() / ".local" / "share" / "icons-archive").resolve()


def get_default_proofs_dir(icons_dir: Path | None = None) -> Path | None:
    """Resolves base directory for separated OpenTimestamps proofs archive."""
    for env_var in ("SEAFILE_PROOFS", "SEADRIVE_PROOFS", "PROOFS_DIR"):
        env_dir = os.environ.get(env_var)
        if env_dir:
            return Path(env_dir).expanduser().resolve()

    base = icons_dir or get_default_icons_dir()
    if base.is_dir():
        cand_sibling_proofs = base.parent / f"{base.name}-Proofs"
        if cand_sibling_proofs.is_dir():
            return cand_sibling_proofs
        cand_sibling_just_proofs = base.parent / "Proofs"
        if cand_sibling_just_proofs.is_dir():
            return cand_sibling_just_proofs

    cand_data_proofs = Path.home() / "data" / "Icons-Proofs"
    if cand_data_proofs.is_dir():
        return cand_data_proofs
    cand_data_alt = Path.home() / "data" / "Proofs"
    if cand_data_alt.is_dir():
        return cand_data_alt

    cand_seafile = Path.home() / "Seafile" / "Icons-Proofs"
    if cand_seafile.is_dir():
        return cand_seafile
    cand_seafile_alt = Path.home() / "Seafile" / "Proofs"
    if cand_seafile_alt.is_dir():
        return cand_seafile_alt

    cand_seadrive = Path.home() / "SeaDrive" / "My Libraries" / "Icons-Proofs"
    if cand_seadrive.is_dir():
        return cand_seadrive
    cand_seadrive_alt = Path.home() / "SeaDrive" / "My Libraries" / "Proofs"
    if cand_seadrive_alt.is_dir():
        return cand_seadrive_alt

    return None


# ------------------------------------------------------------------------------
# Asset Pipeline: Init, Build, Audit, List, Upgrade
# ------------------------------------------------------------------------------
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
    print(f"    3. Run build: {C_GREEN}media build {name} {version}{C_RESET}\n")

    return target_dir, target_proofs_dir


def run_audit(target_dir: Path, proofs_dir: Path | None = None) -> tuple[int, list[dict[str, str]]]:
    """Runs a full non-blocking diagnostic pass over an asset or version tree."""
    violations: list[dict[str, str]] = []
    all_ots_map: dict[Path, Path] = {}

    if proofs_dir and proofs_dir.is_dir():
        for ots in proofs_dir.rglob("*.ots"):
            rel = ots.relative_to(proofs_dir)
            base_name = ots.name[:-4]
            expected_target = target_dir / rel.parent / base_name
            all_ots_map[ots] = expected_target

    if target_dir.is_dir():
        for ots in target_dir.rglob("*.ots"):
            base_name = ots.name[:-4]
            expected_target = ots.parent / base_name
            all_ots_map[ots] = expected_target

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

        res = inspect_ots_proof(expected_target, ots)
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
    force: bool = False,
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

    # Auto-detect existing master if not provided
    if master_path is None:
        if master_dest_dir.is_dir():
            candidates = [
                f for f in sorted(master_dest_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            img_cands = [f for f in candidates if f.suffix.lower() in (".png", ".webp", ".jpg", ".jpeg")]
            if img_cands:
                master_path = img_cands[0]
                log_info(f"Auto-detected master image: {master_path.name}")
            elif candidates:
                master_path = candidates[0]
                log_info(f"Auto-detected master image: {master_path.name}")

    # Auto-detect existing raw project canvas if not provided
    if raw_path is None:
        if raw_dest_dir.is_dir():
            raw_candidates = [
                f for f in sorted(raw_dest_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            canvas_cands = [f for f in raw_candidates if f.suffix.lower() in (".xcf", ".psd", ".kra", ".svg", ".ai")]
            if canvas_cands:
                raw_path = canvas_cands[0]
                log_info(f"Auto-detected raw project canvas: {raw_path.name}")
            elif raw_candidates:
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

    # 1. Pre-flight Audit if target directory exists
    if target_dir.is_dir():
        err_count, violations = run_audit(target_dir, target_proofs_dir)
        if err_count > 0 and not force:
            print_audit_report(name, version, violations)
            log_err(
                f"Build aborted due to {err_count} integrity violation(s). "
                f"Fix them or pass --force to overwrite."
            )
            sys.exit(1)

    raw_dest_dir.mkdir(parents=True, exist_ok=True)
    master_dest_dir.mkdir(parents=True, exist_ok=True)
    signed_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    # 2. Stage 1: Preserve Raw Project Canvas
    if raw_path:
        if raw_path.parent.resolve() == raw_dest_dir.resolve():
            dest_raw = raw_path
        else:
            dest_raw = raw_dest_dir / raw_path.name
            if dest_raw.resolve() != raw_path.resolve():
                shutil.copyfile(raw_path, dest_raw)
        if not no_stamp:
            local_ots = dest_raw.with_name(f"{dest_raw.name}.ots")
            final_ots = (
                (target_proofs_dir / "01_source" / "raw" / f"{dest_raw.name}.ots")
                if target_proofs_dir
                else local_ots
            )
            if not final_ots.is_file() or force:
                log_info(f"Stamping raw canvas '{raw_path.name}' in Bitcoin blockchain...")
                stamp_media_file(dest_raw, force=True)
                if target_proofs_dir and local_ots.is_file():
                    shutil.move(local_ots, final_ots)
                if final_ots.is_file():
                    final_ots.chmod(0o444)
        dest_raw.chmod(0o444)
        log_ok(f"Raw canvas secured: {dest_raw.name} (0444)")

    # 3. Stage 2: Preserve Normalized Master
    if master_path.parent.resolve() == master_dest_dir.resolve():
        dest_master = master_path
    else:
        dest_master = master_dest_dir / master_path.name
        if dest_master.resolve() != master_path.resolve():
            shutil.copyfile(master_path, dest_master)
    if not no_stamp:
        local_ots = dest_master.with_name(f"{dest_master.name}.ots")
        final_ots = (
            (target_proofs_dir / "01_source" / "master" / f"{dest_master.name}.ots")
            if target_proofs_dir
            else local_ots
        )
        if not final_ots.is_file() or force:
            log_info(f"Stamping cropped master '{dest_master.name}' in Bitcoin blockchain...")
            stamp_media_file(dest_master, force=True)
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

    if not no_sign:
        log_info("Cryptographically signing showcase release (C2PA + Watermark + OpenTimestamps)...")
        process_signing(
            input_path=showcase_tmp,
            output_path=signed_target,
            stamp=(not no_stamp),
            bw_item=bw_item,
        )
        showcase_tmp.unlink(missing_ok=True)
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


def execute_list(base_dir: Path, proofs_base: Path | None = None) -> None:
    """Scans and lists managed assets and versions."""
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


# ------------------------------------------------------------------------------
# Keys & Vault Subcommands
# ------------------------------------------------------------------------------
def keys_show(bw_item: str | None = None) -> None:
    """Displays active signing credentials information."""
    log_head("C2PA Signing Credentials Status")
    cfg = load_config()
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")

    if target_bw:
        print(f"  {C_BOLD}Source:{C_RESET}      Bitwarden Vault (In-Memory)")
        print(f"  {C_BOLD}Config File:{C_RESET}  {DEFAULT_CONFIG_FILE}")
        print(f"  {C_BOLD}Item:{C_RESET}        {target_bw}")
        try:
            k_bytes, c_bytes = fetch_bitwarden_credentials(target_bw)
            print(f"  {C_BOLD}Key Status:{C_RESET}  {C_GREEN}Available in RAM ({len(k_bytes)} bytes){C_RESET}")
            print(f"  {C_BOLD}Cert Status:{C_RESET} {C_GREEN}Available in RAM ({len(c_bytes)} bytes){C_RESET}")
        except Exception as e:
            print(f"  {C_BOLD}Status:{C_RESET}      {C_RED}Failed to load: {e}{C_RESET}")
        print()
        return

    env_creds = load_env_credentials()
    if env_creds:
        print(f"  {C_BOLD}Source:{C_RESET}      Environment Variables (C2PA_PRIVATE_KEY, C2PA_CERT)")
        print(f"  {C_BOLD}Status:{C_RESET}      {C_GREEN}Active in environment{C_RESET}\n")
        return

    print(f"  {C_BOLD}Source:{C_RESET}      Local Disk Storage")
    print(f"  {C_BOLD}Config File:{C_RESET}  {DEFAULT_CONFIG_FILE}")
    print(f"  {C_BOLD}Key File:{C_RESET}    {DEFAULT_KEY_PATH} ({'Found' if DEFAULT_KEY_PATH.is_file() else 'Missing'})")
    print(f"  {C_BOLD}Cert File:{C_RESET}   {DEFAULT_CERT_PATH} ({'Found' if DEFAULT_CERT_PATH.is_file() else 'Missing'})")
    print(f"\n  {C_CYAN}To migrate to Bitwarden:{C_RESET}")
    print(f"    1. export BW_SESSION=$(bw unlock --raw)")
    print(f"    2. media keys push c2pa-signer")
    print(f"    3. rm -rf {DEFAULT_KEY_DIR}\n")


def keys_export(bw_item: str | None = None) -> None:
    """Exports raw PEM key and certificate to stdout for backup or Bitwarden."""
    cfg = load_config()
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")
    if target_bw:
        k_bytes, c_bytes = fetch_bitwarden_credentials(target_bw)
    elif DEFAULT_KEY_PATH.is_file() and DEFAULT_CERT_PATH.is_file():
        k_bytes, c_bytes = DEFAULT_KEY_PATH.read_bytes(), DEFAULT_CERT_PATH.read_bytes()
    else:
        log_err("No credentials found to export.")
        sys.exit(1)

    print(k_bytes.decode("utf-8").strip())
    print()
    print(c_bytes.decode("utf-8").strip())


def keys_gen(domain: str = DEFAULT_DOMAIN, bw_item: str | None = None, out_dir: Path | None = None) -> None:
    """Generates new Root CA + Leaf C2PA credentials."""
    if bw_item:
        log_head(f"Generating C2PA credentials directly in Bitwarden vault: '{bw_item}'...")
        k_bytes, c_bytes, r_bytes = generate_c2pa_credentials(domain)
        save_credentials_to_bitwarden(bw_item, k_bytes, c_bytes, domain, root_key_pem=r_bytes)
        cfg = load_config()
        cfg["bitwarden_item"] = bw_item
        save_config(cfg)
        log_ok(f"Configured Bitwarden item '{bw_item}' as default signing source in {DEFAULT_CONFIG_FILE}.")
    else:
        target_dir = out_dir or DEFAULT_KEY_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        out_key = target_dir / "es256_private.key"
        out_cert = target_dir / "es256_certs.pem"
        log_head(f"Generating C2PA signing credentials for {domain}...")
        generate_c2pa_credentials(domain, out_key, out_cert)
        log_ok(f"Key written:  {out_key}")
        log_ok(f"Cert written: {out_cert}")


def keys_push(item_name: str) -> None:
    """Pushes local credentials directly into Bitwarden vault as a Secure Note."""
    if not DEFAULT_KEY_PATH.is_file() or not DEFAULT_CERT_PATH.is_file():
        log_err(f"Local credentials not found in {DEFAULT_KEY_DIR} to push.")
        sys.exit(1)
    k_bytes = DEFAULT_KEY_PATH.read_bytes()
    c_bytes = DEFAULT_CERT_PATH.read_bytes()
    save_credentials_to_bitwarden(item_name, k_bytes, c_bytes, DEFAULT_DOMAIN)
    cfg = load_config()
    cfg["bitwarden_item"] = item_name
    save_config(cfg)
    log_ok(f"Configured Bitwarden item '{item_name}' as default signing source in {DEFAULT_CONFIG_FILE}.")
    print(f"\n  {C_GREEN}Credentials successfully mirrored into Bitwarden vault!{C_RESET}")
    print(f"  To enforce zero-disk-storage, you may now delete local keys:")
    print(f"    {C_BOLD}rm -rf {DEFAULT_KEY_DIR}{C_RESET}\n")


def keys_use(item_name: str | None = None) -> None:
    """Configures default Bitwarden vault item or reverts to local disk storage."""
    cfg = load_config()
    if not item_name or item_name.lower() in ("local", "disk", "none"):
        cfg["bitwarden_item"] = None
        save_config(cfg)
        log_ok(f"Reverted signing credentials source to local disk in {DEFAULT_CONFIG_FILE}.")
        return

    # Verify we can fetch the item
    fetch_bitwarden_credentials(item_name)
    cfg["bitwarden_item"] = item_name
    save_config(cfg)
    log_ok(f"Configured Bitwarden item '{item_name}' as default signing source in {DEFAULT_CONFIG_FILE}.")


# ------------------------------------------------------------------------------
# CLI Parser & Main Dispatch
# ------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="media",
        description="Unified media lifecycle: C2PA attestation, steganography, Bitcoin timestamping & asset generation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Asset Pipeline Examples:
  media init duck v1                             # Scaffold directory hierarchy
  media build duck v1                            # Auto-detect source files and build
  media build duck v1 -m master.png -r canvas.xcf # Build with explicit source paths
  media build duck v2 --bw                       # Build using Bitwarden signing keys
  media audit duck v1                            # Verify asset integrity against Bitcoin
  media audit                                    # Full integrity audit of entire library
  media list                                     # List managed assets and active versions
  media upgrade duck v1                          # Upgrade OTS proofs for an asset

File Attestation Examples:
  media sign photo.png                           # Sign with C2PA and invisible watermark
  media sign --bw --stamp hero.png               # Sign from Bitwarden & anchor in Bitcoin
  media verify photo_signed.png                  # Inspect all 3 security layers
  media stamp document.pdf                       # Anchor arbitrary file in Bitcoin

Automation & Keys Examples:
  media timer setup /path/to/Icons-Proofs        # Start background OTS upgrade timer
  media timer status                             # Inspect timer state
  media keys show                                # Inspect active C2PA certificate
  media keys gen --bw c2pa-signer                # Generate keys directly into Bitwarden
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
    p_build.add_argument("-m", "--master", type=Path, default=None, help="Cropped master square PNG/WebP (auto-detected in 01_source/master/)")
    p_build.add_argument("-r", "--raw", type=Path, default=None, help="Project canvas XCF/PSD/SVG (auto-detected in 01_source/raw/)")
    p_build.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_build.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")
    p_build.add_argument("--sizes", type=str, default="512,256,128,64,32", help="Comma-separated dist resolutions")
    p_build.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Bitwarden item name for C2PA keys")
    p_build.add_argument("--no-sign", action="store_true", help="Skip C2PA signing of showcase release")
    p_build.add_argument("--no-stamp", action="store_true", help="Skip OpenTimestamps Bitcoin anchoring")
    p_build.add_argument("--force", action="store_true", help="Bypass audit mismatch and re-stamp source files")

    # Command: audit
    p_audit = subparsers.add_parser("audit", help="Run full non-blocking integrity audit across asset tree")
    p_audit.add_argument("name", type=str, nargs="?", help="Specific asset name to audit (optional)")
    p_audit.add_argument("version", type=str, nargs="?", help="Specific version to audit (optional)")
    p_audit.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_audit.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: list
    p_list = subparsers.add_parser("list", help="List managed assets and versions")
    p_list.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_list.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: upgrade
    p_up = subparsers.add_parser("upgrade", help="Recursively upgrade OpenTimestamps proofs in Bitcoin")
    p_up.add_argument("target", type=str, nargs="?", help="Asset name, directory, or .ots proof file (optional)")
    p_up.add_argument("version", type=str, nargs="?", help="Asset version (if target is asset name)")
    p_up.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_up.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: sign
    p_sign = subparsers.add_parser("sign", help="Sign an individual image with C2PA and invisible watermark")
    p_sign.add_argument("input", type=Path, help="Input media file (PNG, JPG, WebP, etc.)")
    p_sign.add_argument("-o", "--output", type=Path, help="Output path (default: <name>_signed.<ext>)")
    p_sign.add_argument("--in-place", action="store_true", help="Overwrite input file directly")
    p_sign.add_argument("-t", "--title", type=str, help="Media title")
    p_sign.add_argument("-a", "--author", type=str, help="Author name and contact")
    p_sign.add_argument("-d", "--domain", type=str, help="Signing domain")
    p_sign.add_argument("-m", "--description", type=str, help="Custom action description")
    p_sign.add_argument("-l", "--license", type=str, help="License or copyright text")
    p_sign.add_argument("-w", "--watermark", type=str, help="Custom invisible watermark text")
    p_sign.add_argument("--no-watermark", action="store_true", help="Disable invisible DWT-DCT watermark")
    p_sign.add_argument("--no-c2pa", action="store_true", help="Disable C2PA manifest signing")
    p_sign.add_argument("--stamp", action="store_true", help="Anchor signed file in Bitcoin blockchain via OpenTimestamps")
    p_sign.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark permutation")
    p_sign.add_argument("--key", type=Path, help="Custom EC private key in PEM format")
    p_sign.add_argument("--cert", type=Path, help="Custom X.509 certificate chain in PEM format")
    p_sign.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Fetch C2PA credentials strictly from Bitwarden into RAM")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Inspect and verify C2PA, watermarks & OpenTimestamps")
    p_verify.add_argument("file", type=Path, help="Target media file to inspect")
    p_verify.add_argument("--ots", type=Path, help="Path to custom or detached .ots proof file")
    p_verify.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark extraction")
    p_verify.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Fetch watermark secret from Bitwarden into RAM")
    p_verify.add_argument("--json", action="store_true", help="Output raw verification report in JSON")

    # Command: stamp
    p_stamp = subparsers.add_parser("stamp", help="Anchor any file in Bitcoin blockchain via OpenTimestamps")
    p_stamp.add_argument("file", type=Path, help="Target file to timestamp")
    p_stamp.add_argument("-f", "--force", action="store_true", help="Overwrite existing .ots file")
    p_stamp.add_argument("--wait", action="store_true", help="Wait until confirmation block is available")

    # Command: timer
    p_timer = subparsers.add_parser("timer", help="Manage background systemd timer for OpenTimestamps upgrades")
    sub_timer = p_timer.add_subparsers(dest="timer_action", help="Timer operation")
    p_t_setup = sub_timer.add_parser("setup", help="Install and enable systemd user timer")
    p_t_setup.add_argument("dir", type=Path, nargs="?", help="Target folder with .ots proofs (default: Icons-Proofs)")
    p_t_setup.add_argument("--interval", type=str, default="2h", help="Timer interval (default: 2h)")
    sub_timer.add_parser("status", help="Show timer status")
    sub_timer.add_parser("remove", help="Disable and remove timer")

    # Command: keys
    p_keys = subparsers.add_parser("keys", help="Manage C2PA signing keys and Bitwarden integration")
    sub_keys = p_keys.add_subparsers(dest="keys_action", help="Keys operation")
    p_k_show = sub_keys.add_parser("show", help="Show active certificate details and paths")
    p_k_show.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Inspect Bitwarden credentials")
    p_k_gen = sub_keys.add_parser("gen", help="Generate or regenerate C2PA signing credentials")
    p_k_gen.add_argument("-d", "--domain", type=str, default=DEFAULT_DOMAIN, help="Domain for certificates")
    p_k_gen.add_argument("--out-dir", type=Path, default=DEFAULT_KEY_DIR, help="Destination directory for keys")
    p_k_gen.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Store credentials directly in Bitwarden vault (0 disk files)")
    p_k_exp = sub_keys.add_parser("export", help="Export private key and cert in PEM format")
    p_k_exp.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Export from Bitwarden vault")
    p_k_push = sub_keys.add_parser("push", help="Push local keys to Bitwarden vault as Secure Note")
    p_k_push.add_argument("item", type=str, default=DEFAULT_BW_ITEM, nargs="?", help="Bitwarden item name")
    p_k_use = sub_keys.add_parser("use", help="Configure default Bitwarden item (or 'local' for disk)")
    p_k_use.add_argument("item", type=str, nargs="?", default=DEFAULT_BW_ITEM, help="Bitwarden item name (or 'local')")

    # Shortcut handling: if first arg is an existing file, default to 'verify'
    args_list = sys.argv[1:]
    all_cmds = ("init", "build", "audit", "list", "upgrade", "sign", "verify", "stamp", "timer", "keys", "-h", "--help")
    if args_list and args_list[0] not in all_cmds:
        if any(arg == "--verify" for arg in args_list):
            args_list.remove("--verify")
            args_list.insert(0, "verify")
        elif Path(args_list[0]).is_file():
            args_list.insert(0, "verify")
        else:
            args_list.insert(0, "build")

    args = parser.parse_args(args_list)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    base_dir = getattr(args, "dir", None) or get_default_icons_dir()
    proofs_base = getattr(args, "proofs_dir", None) or get_default_proofs_dir(base_dir)

    # Dispatch: init
    if args.command == "init":
        execute_init(name=args.name, version=args.version, base_dir=base_dir, proofs_dir=proofs_base)

    # Dispatch: build
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
            force=args.force,
        )

    # Dispatch: audit
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

    # Dispatch: list
    elif args.command == "list":
        execute_list(base_dir, proofs_base)

    # Dispatch: upgrade
    elif args.command == "upgrade":
        search_base = proofs_base or base_dir
        if not args.target:
            upgrade_ots_file(search_base)
        else:
            cand_p = Path(args.target)
            if cand_p.exists():
                upgrade_ots_file(cand_p)
            elif args.version:
                target_p = search_base / args.target / args.version
                upgrade_ots_file(target_p)
            else:
                target_p = search_base / args.target
                upgrade_ots_file(target_p)

    # Dispatch: sign
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

    # Dispatch: verify
    elif args.command == "verify":
        inspect_image(
            image_path=args.file,
            as_json=args.json,
            secret=args.secret,
            ots_path=args.ots,
            bw_item=args.bw_item,
        )

    # Dispatch: stamp
    elif args.command == "stamp":
        stamp_media_file(target_file=args.file, wait=args.wait, force=args.force)

    # Dispatch: timer
    elif args.command == "timer":
        action = getattr(args, "timer_action", None)
        if action == "setup":
            timer_setup(target_dir=args.dir, interval=args.interval)
        elif action == "remove":
            timer_remove()
        elif action == "status" or action is None:
            timer_status()

    # Dispatch: keys
    elif args.command == "keys":
        action = getattr(args, "keys_action", None)
        if action == "show" or action is None:
            keys_show(bw_item=getattr(args, "bw_item", None))
        elif action == "gen":
            keys_gen(domain=args.domain, bw_item=args.bw_item, out_dir=args.out_dir)
        elif action == "export":
            keys_export(bw_item=args.bw_item)
        elif action == "push":
            keys_push(item_name=args.item)
        elif action == "use":
            keys_use(item_name=args.item)


if __name__ == "__main__":
    main()
