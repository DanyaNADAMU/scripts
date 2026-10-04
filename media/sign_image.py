#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "c2pa-python>=0.38.0",
#     "cryptography>=43.0.0",
#     "pillow>=10.0.0",
# ]
# ///
# ==============================================================================
# Script:      sign_image.py
# Category:    media
# Description: Sign and inspect media files using C2PA Content Credentials.
# Target:      Linux / macOS
# Requires:    python >= 3.11, uv
# Usage:       sign-image [sign|verify|credentials|keygen] [options] <file>
# ==============================================================================
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

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
APP_VERSION = "1.0.0"

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
    }

    if DEFAULT_CONFIG_FILE.is_file():
        try:
            user_cfg = json.loads(DEFAULT_CONFIG_FILE.read_text(encoding="utf-8"))
            default_cfg.update(user_cfg)
        except Exception as e:
            log_warn(f"Failed to parse {DEFAULT_CONFIG_FILE}: {e}")
    else:
        # Create default config file for easy customization
        try:
            DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            DEFAULT_CONFIG_FILE.write_text(
                json.dumps(default_cfg, indent=2) + "\n", encoding="utf-8"
            )
        except Exception:
            pass

    return default_cfg


# ------------------------------------------------------------------------------
# Key & Certificate Management
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
    # Set secure 0600 permissions for private key
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

    # Import Mode
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

    # Check existence
    if not (DEFAULT_KEY_PATH.is_file() and DEFAULT_CERT_PATH.is_file()):
        cfg = load_config()
        log_info(f"Credentials not found. Generating initial credentials in {DEFAULT_KEY_DIR}...")
        generate_c2pa_credentials(cfg.get("domain", DEFAULT_DOMAIN))

    if export_raw:
        # Raw PEM dump to stdout (convenient for pipes or pasting into Bitwarden)
        print("# ==============================================================================")
        print("# C2PA PRIVATE KEY (Save to Bitwarden / Secret Vault)")
        print("# ==============================================================================")
        print(DEFAULT_KEY_PATH.read_text().strip())
        print("\n# ==============================================================================")
        print("# C2PA CERTIFICATE CHAIN")
        print("# ==============================================================================")
        print(DEFAULT_CERT_PATH.read_text().strip())
        return

    # Formatted display
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
# Core C2PA Operations: Sign & Inspect
# ------------------------------------------------------------------------------
def sign_image(
    input_path: Path,
    output_path: Path,
    title: str | None = None,
    author: str | None = None,
    domain: str | None = None,
    description: str | None = None,
    license_text: str | None = None,
    key_path: Path | None = None,
    cert_path: Path | None = None,
) -> None:
    """Embeds a C2PA manifest with author declarations into the image."""
    if not input_path.is_file():
        log_err(f"Input file not found: {input_path}")
        sys.exit(1)

    cfg = load_config()

    act_author = author or cfg.get("author", DEFAULT_AUTHOR)
    act_domain = domain or cfg.get("domain", DEFAULT_DOMAIN)
    act_policy = cfg.get("policy_url", DEFAULT_POLICY_URL)
    act_license = license_text or cfg.get("default_license", "")
    src_type = cfg.get("digital_source_type", DEFAULT_SOURCE_TYPE)

    key_bytes, cert_bytes = load_or_create_credentials(key_path, cert_path, act_domain)

    signer_info = c2pa.C2paSignerInfo(
        alg=c2pa.C2paSigningAlg.ES256,
        sign_cert=cert_bytes,
        private_key=key_bytes,
        ta_url=None,
    )
    signer = c2pa.Signer.from_info(signer_info)

    asset_title = title or input_path.stem
    desc_text = description or f"Original media authored by {act_author} on {act_domain}."

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

    log_head(f"Signing {input_path.name} with C2PA...")
    log_info(f"Title:       {asset_title}")
    log_info(f"Author:      {act_author}")
    log_info(f"Domain:      {act_domain}")
    log_info(f"Target:      {output_path}")

    try:
        builder = c2pa.Builder.from_json(json.dumps(manifest_def))
        is_inplace = input_path.resolve() == output_path.resolve()
        temp_dest = output_path.with_suffix(f".tmp{output_path.suffix}") if is_inplace else output_path

        builder.sign_file(str(input_path), str(temp_dest), signer)

        if is_inplace:
            temp_dest.replace(output_path)

        log_ok(f"Successfully signed: {output_path} ({output_path.stat().st_size:,} bytes)")
    except Exception as e:
        log_err(f"C2PA signing error: {e}")
        sys.exit(1)


def inspect_image(image_path: Path, as_json: bool = False) -> None:
    """Reads and displays C2PA manifest provenance information."""
    if not image_path.is_file():
        log_err(f"File not found: {image_path}")
        sys.exit(1)

    try:
        reader = c2pa.Reader.try_create(str(image_path))
    except Exception as e:
        log_err(f"Error reading C2PA data: {e}")
        sys.exit(1)

    if reader is None:
        log_warn(f"No C2PA manifest found in {image_path.name}.")
        return

    raw_json_str = reader.json()
    if as_json:
        print(raw_json_str)
        return

    manifest_data = json.loads(raw_json_str)
    active_label = manifest_data.get("active_manifest")
    manifests = manifest_data.get("manifests", {})
    active = manifests.get(active_label, {})

    log_head(f"C2PA Content Credentials: {image_path.name}")
    print(f"  {C_BOLD}Active Manifest:{C_RESET} {active_label}")
    print(f"  {C_BOLD}Title:{C_RESET}           {active.get('title', 'N/A')}")
    print(f"  {C_BOLD}Generator:{C_RESET}       {active.get('claim_generator_info', [{}])[0].get('name', 'N/A')}")

    sig_info = active.get("signature_info", {})
    if sig_info:
        print(f"  {C_BOLD}Signer:{C_RESET}          {sig_info.get('common_name', 'N/A')} ({sig_info.get('issuer', 'N/A')})")
        print(f"  {C_BOLD}Algorithm:{C_RESET}       {sig_info.get('alg', 'N/A')}")

    assertions = active.get("assertions", [])
    if assertions:
        print(f"\n  {C_BOLD}Assertions ({len(assertions)}):{C_RESET}")
        for ass in assertions:
            label = ass.get("label", "unknown")
            print(f"    - {C_CYAN}{label}{C_RESET}")
            if "actions" in label:
                actions = ass.get("data", {}).get("actions", [])
                for act in actions:
                    act_name = act.get("action", "")
                    src_type = act.get("digitalSourceType", "")
                    params = act.get("parameters", {})
                    print(f"        Action: {C_GREEN}{act_name}{C_RESET} (Source: {src_type})")
                    for k, v in params.items():
                        print(f"        {k}: {v}")

    # Check validation state and pixel integrity
    try:
        val_state = reader.get_validation_state()
        val_str = str(val_state)
    except Exception:
        val_str = "Unknown"

    if val_str == "Valid":
        print(f"\n  {C_GREEN}[✓] Provenance manifest verified (Pixel hash & claim signature valid).{C_RESET}\n")
    else:
        print(f"\n  {C_RED}[✗] WARNING: Manifest validation state: {val_str}. Image has been altered or tampered with!{C_RESET}\n")


# ------------------------------------------------------------------------------
# CLI Parser
# ------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sign-image",
        description="Cryptographic media signing and verification using C2PA Content Credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sign-image sign image.png                       # Sign image with default nada.mu credentials
  sign-image sign -o signed.jpg raw.jpg           # Sign and write to signed.jpg
  sign-image sign --in-place banner.webp          # Embed C2PA manifest directly into file
  sign-image verify image_signed.png              # Inspect embedded Content Credentials
  sign-image verify --json image_signed.png       # Print complete raw C2PA manifest in JSON
  sign-image credentials                          # View active certificate details and paths
  sign-image credentials --export                 # Export key and cert for Bitwarden backup
  sign-image keygen                               # Regenerate dedicated signing certificates
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Operation mode")

    # Command: sign
    p_sign = subparsers.add_parser("sign", help="Sign an image with C2PA manifest")
    p_sign.add_argument("input", type=Path, help="Input media file (PNG, JPG, WebP, etc.)")
    p_sign.add_argument("-o", "--output", type=Path, help="Output destination path (default: <name>_signed.<ext>)")
    p_sign.add_argument("--in-place", action="store_true", help="Overwrite the input file directly")
    p_sign.add_argument("-t", "--title", type=str, help="Media title")
    p_sign.add_argument("-a", "--author", type=str, help="Author name and contact")
    p_sign.add_argument("-d", "--domain", type=str, help="Signing domain")
    p_sign.add_argument("-m", "--description", type=str, help="Custom action description")
    p_sign.add_argument("-l", "--license", type=str, help="License or copyright text")
    p_sign.add_argument("--key", type=Path, help="Custom EC private key in PEM format")
    p_sign.add_argument("--cert", type=Path, help="Custom X.509 certificate chain in PEM format")

    # Command: verify / inspect
    p_verify = subparsers.add_parser("verify", help="Inspect and verify C2PA Content Credentials")
    p_verify.add_argument("file", type=Path, help="Target media file to inspect")
    p_verify.add_argument("--json", action="store_true", help="Output raw manifest JSON")

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
        inspect_image(args.file, as_json=args.json)

    elif args.command == "sign":
        if args.in_place:
            dest = args.input
        elif args.output:
            dest = args.output
        else:
            dest = args.input.with_name(f"{args.input.stem}_signed{args.input.suffix}")

        sign_image(
            input_path=args.input,
            output_path=dest,
            title=args.title,
            author=args.author,
            domain=args.domain,
            description=args.description,
            license_text=args.license,
            key_path=args.key,
            cert_path=args.cert,
        )


if __name__ == "__main__":
    main()
