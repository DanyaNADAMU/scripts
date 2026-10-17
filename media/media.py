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
#     "resvg-py>=0.2.0",
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
import base64
import json
import math
import os
import random
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageSequence
import pywt
from scipy.fftpack import dct, idct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
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
DEFAULT_AUTHOR = "DanyaNADAMU <danya@nada.mu>"
DEFAULT_POLICY_URL = "https://nada.mu/.well-known/security.txt"
DEFAULT_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
DEFAULT_WATERMARK = "NADAMU"
DEFAULT_BW_ITEM = "c2pa-signer"
DEFAULT_WATERMARK_CHALLENGE = b"c2pa:watermark:seed:v1:nada.mu"

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
# Vector Asset Utilities (SVG Inspection & Rasterization)
# ------------------------------------------------------------------------------
def get_svg_dimensions(svg_path: Path) -> tuple[int, int]:
    """Extracts width and height or aspect ratio dimensions from an SVG file."""
    try:
        tree = ET.parse(svg_path)
        root = tree.getroot()
        vb = root.attrib.get("viewBox") or root.attrib.get("viewbox")
        if vb:
            parts = [float(p) for p in re.split(r"[\s,]+", vb.strip()) if p]
            if len(parts) == 4 and parts[2] > 0 and parts[3] > 0:
                return int(round(parts[2])), int(round(parts[3]))

        def _parse_val(val: str | None) -> float | None:
            if not val:
                return None
            m = re.match(r"^([\d.]+)", val.strip())
            return float(m.group(1)) if m else None

        w = _parse_val(root.attrib.get("width"))
        h = _parse_val(root.attrib.get("height"))
        if w and h:
            return int(round(w)), int(round(h))
    except Exception as e:
        log_warn(f"Failed to inspect SVG dimensions for {svg_path.name}: {e}")
    return 0, 0


def render_svg_to_image(svg_path: Path, width: int, height: int) -> Image.Image:
    """Renders an SVG vector asset directly to a PIL RGBA Image at exact pixel dimensions."""
    # 1. Preferred: resvg-py (standalone Rust engine, zero C library requirements)
    try:
        import resvg_py
        png_bytes = resvg_py.svg_to_bytes(svg_path=str(svg_path), width=width, height=height)
        return Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    except ImportError:
        pass
    except Exception as e:
        log_warn(f"resvg-py rendering failed for {svg_path.name}: {e}")

    # 2. Fallback: cairosvg (requires libcairo-2 system library)
    try:
        import cairosvg
        png_bytes = cairosvg.svg2png(url=str(svg_path), output_width=width, output_height=height)
        return Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    except ImportError:
        pass
    except Exception as e:
        log_warn(f"cairosvg rendering failed for {svg_path.name}: {e}")

    # 3. Fallback: rsvg-convert CLI utility
    if shutil.which("rsvg-convert"):
        try:
            cmd = ["rsvg-convert", "-w", str(width), "-h", str(height), "-f", "png", str(svg_path)]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return Image.open(io.BytesIO(res.stdout)).convert("RGBA")
        except Exception as e:
            log_warn(f"rsvg-convert CLI failed for {svg_path.name}: {e}")

    raise RuntimeError(
        f"Unable to rasterize SVG '{svg_path.name}'. "
        f"Please install 'resvg-py' (recommended via uv) or install 'librsvg2-bin' (rsvg-convert)."
    )


def parse_pad_color(val: str | None) -> tuple[int, int, int, int]:
    """Parses color string ('transparent', '#HEX', 'white', etc.) to RGBA 4-tuple."""
    if not val or str(val).lower() in ("transparent", "none", "alpha"):
        return (0, 0, 0, 0)
    try:
        from PIL import ImageColor

        return ImageColor.getcolor(val, "RGBA")
    except Exception:
        return (0, 0, 0, 0)


# ------------------------------------------------------------------------------
# Media Format Categorization & Video Utilities
# ------------------------------------------------------------------------------
ANIMATED_IMAGE_EXTENSIONS = {".gif"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv"}
RASTER_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".avif", ".tif", ".tiff"}
VECTOR_EXTENSIONS = {".svg"}
MEDIA_MASTER_EXTENSIONS = (
    ".svg", ".png", ".webp", ".jpg", ".jpeg", ".gif",
    ".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv"
)


def is_video_path(p: Path) -> bool:
    """Checks whether path points to a supported video format."""
    return p.suffix.lower() in VIDEO_EXTENSIONS


def is_animated_image_path(p: Path) -> bool:
    """Checks whether path points to an animated image (GIF, animated WebP/PNG)."""
    sfx = p.suffix.lower()
    if sfx in ANIMATED_IMAGE_EXTENSIONS:
        return True
    if sfx in (".webp", ".png"):
        try:
            with Image.open(p) as im:
                return getattr(im, "is_animated", False) and getattr(im, "n_frames", 1) > 1
        except Exception:
            return False
    return False


def get_video_dimensions(video_path: Path) -> tuple[int, int]:
    """Extracts width and height from video file using ffprobe."""
    try:
        cmd = [
            "ffprobe", "-v", "error",
            "-select_streams", "v:0",
            "-show_entries", "stream=width,height",
            "-of", "json",
            str(video_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        streams = data.get("streams", [])
        if streams:
            stream = streams[0]
            return int(stream.get("width", 0)), int(stream.get("height", 0))
    except Exception as e:
        log_warn(f"Could not read video dimensions from {video_path.name}: {e}")
    return 0, 0


def extract_video_frame_to_image(video_path: Path) -> Image.Image:
    """Extracts a representative RGBA frame from video using ffmpeg."""
    tmp_frame = tempfile.mktemp(suffix=".png")
    try:
        cmd = ["ffmpeg", "-y", "-ss", "00:00:00.5", "-i", str(video_path), "-vframes", "1", tmp_frame]
        res = subprocess.run(cmd, capture_output=True)
        if res.returncode != 0 or not os.path.exists(tmp_frame):
            cmd2 = ["ffmpeg", "-y", "-i", str(video_path), "-vframes", "1", tmp_frame]
            subprocess.run(cmd2, capture_output=True, check=True)
        with Image.open(tmp_frame) as im:
            return im.convert("RGBA")
    except Exception as e:
        log_warn(f"Failed to extract video frame from {video_path.name}: {e}")
        return Image.new("RGBA", (512, 512), (0, 0, 0, 255))
    finally:
        if os.path.exists(tmp_frame):
            try:
                os.unlink(tmp_frame)
            except Exception:
                pass


def render_video_to_target(
    src_path: Path,
    dst_path: Path,
    tw: int,
    th: int,
    resize_mode: str = "pad",
    pad_color: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> None:
    """Scales a video asset to exact target resolution using ffmpeg with specified fitting policy."""
    tw = tw if tw % 2 == 0 else tw + 1
    th = th if th % 2 == 0 else th + 1
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if dst_path.is_file():
        dst_path.unlink()

    pad_hex = "black"
    if len(pad_color) >= 3 and pad_color[3] > 0:
        pad_hex = f"0x{pad_color[0]:02x}{pad_color[1]:02x}{pad_color[2]:02x}"

    mode = (resize_mode or "pad").lower()
    if mode in ("pad", "contain", "letterbox"):
        vf = f"scale={tw}:{th}:force_original_aspect_ratio=decrease,pad={tw}:{th}:(ow-iw)/2:(oh-ih)/2:color={pad_hex}"
    elif mode in ("crop", "cover"):
        vf = f"scale={tw}:{th}:force_original_aspect_ratio=increase,crop={tw}:{th}"
    else:
        vf = f"scale={tw}:{th}"

    out_sfx = dst_path.suffix.lower()
    if out_sfx in (".webm", ".mkv"):
        cmd = [
            "ffmpeg", "-y", "-i", str(src_path),
            "-vf", vf,
            "-c:v", "libvpx", "-b:v", "1M",
            "-c:a", "libvorbis",
            str(dst_path),
        ]
    else:
        cmd = [
            "ffmpeg", "-y", "-i", str(src_path),
            "-vf", vf,
            "-c:v", "libx264", "-preset", "slow", "-crf", "22",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "128k",
            "-movflags", "+faststart",
            str(dst_path),
        ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"ffmpeg video render failed for {dst_path.name}: {res.stderr}")


def discover_sources(
    search_dir: Path,
    explicit_master: Path | None = None,
) -> list[dict[str, Any]]:
    """Discovers all vector, video, animated and raster source media in directory with dimensions and aspect ratios."""
    sources: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()

    def _add_source(f: Path) -> None:
        if f.resolve() in seen_paths or not f.is_file():
            return
        if f.name.startswith(".") or f.name.endswith(".ots"):
            return
        sfx = f.suffix.lower()
        if sfx not in MEDIA_MASTER_EXTENSIONS:
            return

        seen_paths.add(f.resolve())
        is_vec = sfx == ".svg"
        is_vid = is_video_path(f)
        is_anim = sfx == ".gif" or (sfx in (".webp", ".png") and is_animated_image_path(f))

        if is_vec:
            w, h = get_svg_dimensions(f)
        elif is_vid:
            w, h = get_video_dimensions(f)
        else:
            try:
                with Image.open(f) as im:
                    w, h = im.size
            except Exception:
                w, h = 0, 0

        sources.append({
            "path": f,
            "name": f.name,
            "stem": f.stem,
            "suffix": sfx,
            "is_vector": is_vec,
            "is_video": is_vid,
            "is_animated": is_anim,
            "width": w,
            "height": h,
            "aspect_ratio": (w / h) if (w > 0 and h > 0) else 1.0,
        })

    if explicit_master and explicit_master.is_file():
        _add_source(explicit_master)

    if search_dir.is_dir():
        for f in sorted(search_dir.iterdir()):
            _add_source(f)

    return sources


def select_best_source(
    sources: list[dict[str, Any]],
    target_width: int,
    target_height: int,
    explicit_name: str | None = None,
) -> dict[str, Any]:
    """Selects the best matching source image for target dimensions and policy.

    Matching priority:
    1. Explicit source filename / stem match if provided in manifest/target.
    2. Minimal aspect ratio divergence |R_source - R_target|.
    3. Vector format preference (SVG renders sharp at arbitrary target resolutions).
    4. Minimal downscale/upscale penalty (prefers sources larger than target).
    """
    if not sources:
        raise ValueError("No candidate source images available for rendering.")

    if explicit_name:
        clean_exp = explicit_name.strip()
        for s in sources:
            if s["name"] == clean_exp or s["stem"] == clean_exp or s["path"].name == clean_exp:
                return s
        log_warn(
            f"Explicit source '{explicit_name}' not found; falling back to automatic aspect ratio matching."
        )

    target_ratio = (target_width / target_height) if target_height > 0 else 1.0

    def score(src: dict[str, Any]) -> tuple[float, int, int, int]:
        ratio_diff = abs(src["aspect_ratio"] - target_ratio)
        ratio_bucket = round(ratio_diff, 2)
        vector_penalty = 0 if src["is_vector"] else 1
        src_area = src["width"] * src["height"]
        target_area = target_width * target_height
        upscale_penalty = 1 if (src_area < target_area and not src["is_vector"]) else 0
        return (ratio_bucket, vector_penalty, upscale_penalty, -src_area)

    return min(sources, key=score)


def render_pil_to_canvas(
    rgba: Image.Image,
    tw: int,
    th: int,
    resize_mode: str = "pad",
    pad_color: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> Image.Image:
    """Resizes a PIL RGBA Image to exact (tw, th) canvas according to fitting policy."""
    mode = (resize_mode or "pad").lower()
    tw = max(1, tw)
    th = max(1, th)
    sw, sh = rgba.size
    r_src = (sw / sh) if (sw > 0 and sh > 0) else (tw / th)
    r_target = tw / th

    if abs(r_src - r_target) < 0.01:
        return rgba.resize((tw, th), Image.Resampling.LANCZOS)

    if mode in ("pad", "contain", "letterbox"):
        if r_src > r_target:
            rw = tw
            rh = max(1, round(tw / r_src))
        else:
            rh = th
            rw = max(1, round(th * r_src))
        scaled = rgba.resize((rw, rh), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", (tw, th), pad_color)
        canvas.paste(scaled, ((tw - rw) // 2, (th - rh) // 2), scaled)
        return canvas

    elif mode in ("crop", "cover"):
        if r_src > r_target:
            rh = th
            rw = max(tw, round(th * r_src))
            scaled = rgba.resize((rw, rh), Image.Resampling.LANCZOS)
            left = (rw - tw) // 2
            return scaled.crop((left, 0, left + tw, th))
        else:
            rw = tw
            rh = max(th, round(tw / r_src))
            scaled = rgba.resize((rw, rh), Image.Resampling.LANCZOS)
            top = (rh - th) // 2
            return scaled.crop((0, top, tw, top + th))

    elif mode in ("stretch", "fill"):
        return rgba.resize((tw, th), Image.Resampling.LANCZOS)

    else:  # "fit" without canvas padding
        if r_src > r_target:
            rw = tw
            rh = max(1, round(tw / r_src))
        else:
            rh = th
            rw = max(1, round(th * r_src))
        return rgba.resize((rw, rh), Image.Resampling.LANCZOS)


def render_source_to_canvas(
    src: dict[str, Any],
    tw: int,
    th: int,
    resize_mode: str = "pad",
    pad_color: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> Image.Image:
    """Renders a vector, video frame, or raster source into an exact (tw, th) PIL RGBA canvas using the specified policy."""
    mode = (resize_mode or "pad").lower()
    tw = max(1, tw)
    th = max(1, th)

    if src["is_vector"]:
        sw, sh = src["width"], src["height"]
        r_src = (sw / sh) if (sw > 0 and sh > 0) else (tw / th)
        r_target = tw / th

        if abs(r_src - r_target) < 0.01:
            return render_svg_to_image(src["path"], tw, th)

        if mode in ("pad", "contain", "letterbox"):
            if r_src > r_target:
                rw = tw
                rh = max(1, round(tw / r_src))
            else:
                rh = th
                rw = max(1, round(th * r_src))
            rendered = render_svg_to_image(src["path"], rw, rh)
            canvas = Image.new("RGBA", (tw, th), pad_color)
            canvas.paste(rendered, ((tw - rw) // 2, (th - rh) // 2), rendered)
            return canvas

        elif mode in ("crop", "cover"):
            if r_src > r_target:
                rh = th
                rw = max(tw, round(th * r_src))
                rendered = render_svg_to_image(src["path"], rw, rh)
                left = (rw - tw) // 2
                return rendered.crop((left, 0, left + tw, th))
            else:
                rw = tw
                rh = max(th, round(tw / r_src))
                rendered = render_svg_to_image(src["path"], rw, rh)
                top = (rh - th) // 2
                return rendered.crop((0, top, tw, top + th))

        elif mode in ("stretch", "fill"):
            rendered = render_svg_to_image(src["path"], tw, th)
            if rendered.size != (tw, th):
                rendered = rendered.resize((tw, th), Image.Resampling.LANCZOS)
            return rendered

        else:  # "fit" without canvas padding
            return render_svg_to_image(src["path"], tw, th)

    elif src.get("is_video"):
        rgba = extract_video_frame_to_image(src["path"])
        return render_pil_to_canvas(rgba, tw, th, resize_mode=mode, pad_color=pad_color)

    else:
        # Raster source or animated image (extract first frame)
        with Image.open(src["path"]) as im:
            rgba = im.convert("RGBA")
        return render_pil_to_canvas(rgba, tw, th, resize_mode=mode, pad_color=pad_color)



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
            # Automatic purge: if in ssh-agent mode, remove plaintext watermark_secret from disk
            if default_cfg.get("signing_mode") == "ssh-agent" and "watermark_secret" in user_cfg:
                user_cfg.pop("watermark_secret", None)
                DEFAULT_CONFIG_FILE.write_text(
                    json.dumps(user_cfg, indent=2) + "\n", encoding="utf-8"
                )
                default_cfg.pop("watermark_secret", None)
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
    """Returns a deterministic watermark secret based on machine/user identity or SSH agent."""
    salt = os.environ.get("C2PA_WATERMARK_SECRET")
    if salt:
        return salt
    cfg = load_config()
    if cfg.get("signing_mode") == "ssh-agent":
        try:
            derived = derive_watermark_secret_from_ssh_agent(key_name=cfg.get("ssh_key_name"))
            if derived:
                return derived
        except Exception:
            pass
    if cfg.get("watermark_secret"):
        return str(cfg["watermark_secret"])
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
    orig_w, orig_h = img.size
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
    y_wm = y_wm[:orig_h, :orig_w]
    y_wm = np.clip(y_wm, 0, 255).astype(np.uint8)

    y_img = Image.fromarray(y_wm)
    if y_img.size != (orig_w, orig_h):
        y_img = y_img.resize((orig_w, orig_h), Image.Resampling.LANCZOS)
    if Cb.size != (orig_w, orig_h):
        Cb = Cb.resize((orig_w, orig_h), Image.Resampling.LANCZOS)
    if Cr.size != (orig_w, orig_h):
        Cr = Cr.resize((orig_w, orig_h), Image.Resampling.LANCZOS)

    res_img = Image.merge("YCbCr", (y_img, Cb, Cr)).convert("RGB")
    if has_alpha and alpha:
        if alpha.size != res_img.size:
            alpha = alpha.resize(res_img.size, Image.Resampling.LANCZOS)
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


def generate_c2pa_certs_for_public_key(
    pub_key: Any,
    domain: str = DEFAULT_DOMAIN,
) -> tuple[bytes, bytes, bytes]:
    """Generates a Root CA and issues a Leaf End-Entity certificate for an existing public key (e.g. from SSH agent)."""
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

    # 2. Leaf Certificate (C2PA End Entity) for pub_key
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} Media Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1095))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub_key),
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

    root_key_pem = root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    chain_pem = leaf_cert.public_bytes(serialization.Encoding.PEM) + root_cert.public_bytes(serialization.Encoding.PEM)
    return chain_pem, root_key_pem, root_cert.public_bytes(serialization.Encoding.PEM)


def find_ssh_agent_socket() -> Path | None:
    """Discovers standard SSH agent socket path."""
    cfg = load_config()
    cfg_sock = cfg.get("ssh_agent_sock")
    if cfg_sock:
        p = Path(cfg_sock).expanduser()
        if p.exists():
            return p

    env_sock = os.environ.get("SSH_AUTH_SOCK")
    if env_sock:
        p = Path(env_sock).expanduser()
        if p.exists():
            return p

    # Standard fallback locations (Bitwarden, OpenSSH, Flatpak, systemd)
    standard_paths = [
        Path.home() / ".bitwarden-ssh-agent.sock",
        Path.home() / ".ssh" / "bitwarden-agent.sock",
        Path.home() / ".var" / "app" / "com.bitwarden.desktop" / "data" / ".bitwarden-ssh-agent.sock",
        Path.home() / ".snap" / "bitwarden" / "current" / ".bitwarden-ssh-agent.sock",
    ]
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        standard_paths.extend([
            Path(xdg_runtime) / "ssh-agent.socket",
            Path(xdg_runtime) / "keyring" / "ssh",
        ])

    for cand in standard_paths:
        if cand.exists():
            return cand
    return None


def extract_public_key_from_blob(key_blob: bytes, key_type: str) -> Any:
    """Parses an OpenSSH public key blob into a cryptography public key object."""
    line = f"{key_type} {base64.b64encode(key_blob).decode('ascii')}".encode("ascii")
    return serialization.load_ssh_public_key(line)


def ssh_agent_communicate(sock_path: Path, msg_type: int, payload: bytes = b"") -> tuple[int, bytes]:
    """Sends a request to an OpenSSH agent socket and receives the response."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(str(sock_path))
        req = struct.pack(">IB", len(payload) + 1, msg_type) + payload
        s.sendall(req)
        resp_len_hdr = s.recv(4)
        if len(resp_len_hdr) < 4:
            raise RuntimeError("SSH agent closed connection unexpectedly.")
        resp_len = struct.unpack(">I", resp_len_hdr)[0]
        data = bytearray()
        while len(data) < resp_len:
            chunk = s.recv(min(4096, resp_len - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) < 1:
            raise RuntimeError("Empty response from SSH agent.")
        return data[0], bytes(data[1:])
    finally:
        s.close()


def ssh_agent_list_keys(sock_path: Path) -> list[tuple[bytes, str, str]]:
    """Returns list of (key_blob, key_type, comment) from SSH agent."""
    resp_type, payload = ssh_agent_communicate(sock_path, 11)  # SSH2_AGENTC_REQUEST_IDENTITIES = 11
    if resp_type != 12:  # SSH2_AGENTC_IDENTITIES_ANSWER = 12
        return []
    if len(payload) < 4:
        return []
    num_keys = struct.unpack(">I", payload[:4])[0]
    keys = []
    offset = 4
    for _ in range(num_keys):
        if offset + 4 > len(payload):
            break
        k_len = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4
        k_blob = payload[offset : offset + k_len]
        offset += k_len

        if offset + 4 > len(payload):
            break
        c_len = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4
        comment = payload[offset : offset + c_len].decode("utf-8", errors="ignore")
        offset += c_len

        type_len = struct.unpack(">I", k_blob[:4])[0] if len(k_blob) >= 4 else 0
        k_type = k_blob[4 : 4 + type_len].decode("ascii", errors="ignore") if type_len > 0 else ""
        keys.append((k_blob, k_type, comment))
    return keys


def ssh_agent_sign(sock_path: Path, key_blob: bytes, key_type: str, data: bytes) -> bytes:
    """Signs data via SSH agent and returns DER-encoded signature (or raw for Ed25519)."""
    # SSH2_AGENTC_SIGN_REQUEST = 13
    payload = struct.pack(">I", len(key_blob)) + key_blob
    payload += struct.pack(">I", len(data)) + data
    payload += struct.pack(">I", 0)  # flags
    resp_type, resp_payload = ssh_agent_communicate(sock_path, 13, payload)
    if resp_type == 5:  # SSH_AGENT_FAILURE = 5
        raise RuntimeError("SSH signature request was denied or cancelled by user.")
    if resp_type != 14:  # SSH2_AGENTC_SIGN_RESPONSE = 14
        raise RuntimeError(f"Unexpected SSH agent response type: {resp_type}")

    if len(resp_payload) < 4:
        raise RuntimeError("Invalid signature payload from SSH agent.")
    sig_blob_len = struct.unpack(">I", resp_payload[:4])[0]
    sig_blob = resp_payload[4 : 4 + sig_blob_len]

    fmt_len = struct.unpack(">I", sig_blob[:4])[0]
    fmt = sig_blob[4 : 4 + fmt_len].decode("ascii", errors="ignore")
    sig_data_len = struct.unpack(">I", sig_blob[4 + fmt_len : 8 + fmt_len])[0]
    sig_data = sig_blob[8 + fmt_len : 8 + fmt_len + sig_data_len]

    if "ecdsa" in fmt:
        r_len = struct.unpack(">I", sig_data[:4])[0]
        r_bytes = sig_data[4 : 4 + r_len]
        s_len = struct.unpack(">I", sig_data[4 + r_len : 8 + r_len])[0]
        s_bytes = sig_data[8 + r_len : 8 + r_len + s_len]
        r = int.from_bytes(r_bytes, "big")
        s = int.from_bytes(s_bytes, "big")
        return encode_dss_signature(r, s)
    elif "ed25519" in fmt:
        return sig_data
    else:
        return sig_data


def _encode_der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    len_bytes = []
    while length > 0:
        len_bytes.append(length & 0xFF)
        length >>= 8
    len_bytes.reverse()
    return bytes([0x80 | len(len_bytes)] + len_bytes)


def _encode_der_sequence(content: bytes) -> bytes:
    return b"\x30" + _encode_der_length(len(content)) + content


def _encode_der_bit_string(data: bytes) -> bytes:
    return b"\x03" + _encode_der_length(len(data) + 1) + b"\x00" + data


def _get_tbs_and_template(builder: x509.CertificateBuilder, parent_pub_key: Any) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod, ed25519 as ed25519_mod
    if isinstance(parent_pub_key, ec_mod.EllipticCurvePublicKey):
        dummy_parent = ec_mod.generate_private_key(parent_pub_key.curve)
        dummy_cert = builder.sign(dummy_parent, hashes.SHA256())
    elif isinstance(parent_pub_key, ed25519_mod.Ed25519PublicKey):
        dummy_parent = ed25519_mod.Ed25519PrivateKey.generate()
        dummy_cert = builder.sign(dummy_parent, None)
    else:
        raise ValueError(f"Unsupported key type for session signing: {type(parent_pub_key).__name__}")

    tbs_bytes = dummy_cert.tbs_certificate_bytes
    dummy_der = dummy_cert.public_bytes(serialization.Encoding.DER)
    after_tbs = dummy_der[dummy_der.find(tbs_bytes) + len(tbs_bytes) :]
    dummy_sig = dummy_cert.signature
    bit_str_hdr = b"\x03" + _encode_der_length(len(dummy_sig) + 1) + b"\x00" + dummy_sig
    sig_algo_bytes = after_tbs[: after_tbs.find(bit_str_hdr)]
    return tbs_bytes, sig_algo_bytes


def _assemble_signed_cert(tbs_bytes: bytes, sig_algo_bytes: bytes, signature: bytes) -> x509.Certificate:
    leaf_der = _encode_der_sequence(tbs_bytes + sig_algo_bytes + _encode_der_bit_string(signature))
    return x509.load_der_x509_certificate(leaf_der)


def create_c2pa_session_signer_from_ssh_agent(
    sock_path: Path | None = None,
    key_comment: str | None = None,
    cert_chain_pem: bytes | None = None,
    domain: str = DEFAULT_DOMAIN,
) -> c2pa.Signer:
    """Creates a c2pa.Signer backed by an ephemeral in-memory session key authorized once via SSH Agent.

    Generates an ephemeral EC SECP256R1 session key and requests a single signature authorization
    from the SSH Agent (e.g. Bitwarden Desktop) to sign a subordinate session certificate.
    All subsequent image signatures during the build session use this ephemeral key in RAM
    with zero disk storage and zero additional authorization prompts.
    """
    sock = sock_path or find_ssh_agent_socket()
    if not sock:
        log_err("SSH agent socket not found.")
        log_info("Ensure Bitwarden Desktop is running with SSH agent enabled ($SSH_AUTH_SOCK).")
        sys.exit(1)

    keys = ssh_agent_list_keys(sock)
    if not keys:
        log_err(f"No SSH keys available in agent at {sock}.")
        log_info("Ensure Bitwarden Desktop is unlocked and contains an SSH key.")
        sys.exit(1)

    target_blob = None
    target_type = None
    target_comment = None

    cfg = load_config()
    wanted = key_comment or cfg.get("ssh_key_name") or "c2pa-signer"
    for k_blob, k_type, comm in keys:
        if wanted.lower() in comm.lower():
            target_blob, target_type, target_comment = k_blob, k_type, comm
            break

    if not target_blob:
        for k_blob, k_type, comm in keys:
            if "ecdsa" in k_type or "ed25519" in k_type:
                target_blob, target_type, target_comment = k_blob, k_type, comm
                break

    if not target_blob:
        log_err(f"Could not find an ECDSA or Ed25519 key in SSH agent at {sock}.")
        sys.exit(1)

    c_bytes = cert_chain_pem
    if not c_bytes:
        if DEFAULT_CERT_PATH.is_file():
            c_bytes = DEFAULT_CERT_PATH.read_bytes()
        elif cfg.get("c2pa_cert_pem"):
            c_bytes = cfg["c2pa_cert_pem"].encode("utf-8")
        else:
            log_err(f"C2PA certificate chain not found for SSH key '{target_comment}'.")
            log_info(f"Generate certificates for this SSH key: {C_BOLD}media keys gen --agent{C_RESET}")
            sys.exit(1)

    certs = x509.load_pem_x509_certificates(c_bytes)
    if not certs:
        log_err("No valid X.509 certificates found in certificate chain.")
        sys.exit(1)

    parent_cert = certs[0]
    parent_pub_key = parent_cert.public_key()

    # Generate ephemeral EC SECP256R1 session key in RAM
    session_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    session_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{domain} Media Build Session"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
        ]))
        .issuer_name(parent_cert.subject)
        .public_key(session_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=24))
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
            x509.SubjectKeyIdentifier.from_public_key(session_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_pub_key),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
    )

    tbs_bytes, sig_algo_bytes = _get_tbs_and_template(session_builder, parent_pub_key)

    log_info(f"Awaiting build session signature authorization from Bitwarden Desktop ('{target_comment}')...")
    sig = ssh_agent_sign(sock, target_blob, target_type, tbs_bytes)
    log_ok("Build session authorized via Bitwarden SSH Agent (active for all assets in build).")

    leaf_cert = _assemble_signed_cert(tbs_bytes, sig_algo_bytes, sig)
    full_chain_pem = leaf_cert.public_bytes(serialization.Encoding.PEM) + c_bytes

    session_key_pem = session_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    signer_info = c2pa.C2paSignerInfo(
        alg=c2pa.C2paSigningAlg.ES256,
        sign_cert=full_chain_pem,
        private_key=session_key_pem,
        ta_url=None,
    )
    return c2pa.Signer.from_info(signer_info)


def create_c2pa_signer_from_ssh_agent(
    sock_path: Path | None = None,
    key_comment: str | None = None,
    cert_chain_pem: bytes | None = None,
) -> c2pa.Signer:
    """Creates a c2pa.Signer instance that signs via SSH Agent (Bitwarden Authorize popup)."""
    sock = sock_path or find_ssh_agent_socket()
    if not sock:
        log_err("SSH agent socket not found.")
        log_info("Ensure Bitwarden Desktop is running with SSH agent enabled ($SSH_AUTH_SOCK).")
        sys.exit(1)

    keys = ssh_agent_list_keys(sock)
    if not keys:
        log_err(f"No SSH keys available in agent at {sock}.")
        log_info("Ensure Bitwarden Desktop is unlocked and contains an SSH key.")
        sys.exit(1)

    target_blob = None
    target_type = None
    target_comment = None

    cfg = load_config()
    wanted = key_comment or cfg.get("ssh_key_name") or "c2pa-signer"
    for k_blob, k_type, comm in keys:
        if wanted.lower() in comm.lower():
            target_blob, target_type, target_comment = k_blob, k_type, comm
            break

    if not target_blob:
        for k_blob, k_type, comm in keys:
            if "ecdsa" in k_type or "ed25519" in k_type:
                target_blob, target_type, target_comment = k_blob, k_type, comm
                break

    if not target_blob:
        log_err(f"Could not find an ECDSA or Ed25519 key in SSH agent at {sock}.")
        sys.exit(1)

    c_bytes = cert_chain_pem
    if not c_bytes:
        if DEFAULT_CERT_PATH.is_file():
            c_bytes = DEFAULT_CERT_PATH.read_bytes()
        elif cfg.get("c2pa_cert_pem"):
            c_bytes = cfg["c2pa_cert_pem"].encode("utf-8")
        else:
            log_err(f"C2PA certificate chain not found for SSH key '{target_comment}'.")
            log_info(f"Generate certificates for this SSH key: {C_BOLD}media keys gen --agent{C_RESET}")
            sys.exit(1)

    alg = c2pa.C2paSigningAlg.ES256 if "ecdsa" in target_type else c2pa.C2paSigningAlg.ED25519

    def _callback(data: bytes) -> bytes:
        log_info(f"Awaiting signature authorization from Bitwarden Desktop ('{target_comment}')...")
        sig = ssh_agent_sign(sock, target_blob, target_type, data)
        log_ok("Signature authorized via Bitwarden SSH Agent.")
        return sig

    return c2pa.Signer.from_callback(_callback, alg, c_bytes.decode("utf-8"))


def derive_watermark_secret_from_ssh_agent(
    sock_path: Path | None = None,
    key_name: str | None = None,
    challenge: bytes = DEFAULT_WATERMARK_CHALLENGE,
) -> str | None:
    """Derives a deterministic watermark secret by signing a challenge via SSH agent (Ed25519/ECDSA).

    Zero secret bytes on disk or in persistent configuration.
    """
    sock = sock_path or find_ssh_agent_socket()
    if not sock or not sock.exists():
        return None

    try:
        keys = ssh_agent_list_keys(sock)
        if not keys:
            return None

        cfg = load_config()
        target_name = key_name or cfg.get("ssh_key_name") or "c2pa-signer"

        target_blob = None
        target_type = None
        target_comment = None

        # 1. Match by name / comment
        for k_blob, k_type, comm in keys:
            if target_name.lower() in (comm or "").lower():
                target_blob, target_type, target_comment = k_blob, k_type, comm
                break

        # 2. Match by ed25519 or ecdsa
        if not target_blob:
            for k_blob, k_type, comm in keys:
                if "ed25519" in k_type.lower() or "ecdsa" in k_type.lower():
                    target_blob, target_type, target_comment = k_blob, k_type, comm
                    break

        if not target_blob:
            return None

        if "ecdsa" in target_type.lower():
            log_warn(f"SSH key '{target_comment}' is ECDSA. Ed25519 is strongly recommended for deterministic watermark derivation across all SSH agents.")

        log_info(f"Deriving watermark secret via SSH Agent key '{target_comment}'...")
        sig = ssh_agent_sign(sock, target_blob, target_type, challenge)
        derived = hashlib.sha256(sig).hexdigest()
        log_ok(f"Derived deterministic watermark secret from SSH Agent ({target_comment}).")
        return derived
    except Exception as e:
        log_warn(f"Failed to derive watermark secret via SSH agent: {e}")
        return None


def keys_gen_ssh_agent(
    domain: str = DEFAULT_DOMAIN,
    key_name: str = "c2pa-signer",
    sock_path: Path | None = None,
) -> None:
    """Binds C2PA certificates to an existing SSH Key (e.g. Bitwarden Desktop SSH Agent).

    Zero private keys and zero watermark secrets on disk or in persistent configuration.
    """
    log_head(f"Binding C2PA credentials to SSH Agent key: '{key_name}'...")
    sock = sock_path or find_ssh_agent_socket()
    if not sock:
        log_err("SSH agent socket not found.")
        log_info("Ensure Bitwarden Desktop is running with SSH agent enabled.")
        log_info("Checked: $SSH_AUTH_SOCK and standard paths (~/.ssh/bitwarden-agent.sock, Flatpak, systemd).")
        sys.exit(1)

    log_info(f"Connected to SSH agent socket: {sock}")
    keys = ssh_agent_list_keys(sock)
    if not keys:
        log_err(f"No SSH keys available in agent at {sock}.")
        log_info("Ensure Bitwarden Desktop is unlocked and contains an SSH key.")
        sys.exit(1)

    target_blob = None
    target_type = None
    target_comment = None

    for k_blob, k_type, comm in keys:
        if key_name.lower() in comm.lower():
            target_blob, target_type, target_comment = k_blob, k_type, comm
            break

    if not target_blob:
        for k_blob, k_type, comm in keys:
            if "ed25519" in k_type.lower() or "ecdsa" in k_type.lower():
                target_blob, target_type, target_comment = k_blob, k_type, comm
                break

    if not target_blob:
        available_names = [f"'{c}' ({t})" for _, t, c in keys]
        log_err(f"Could not find an Ed25519 or ECDSA SSH key matching '{key_name}' in SSH agent.")
        log_info(f"Available keys in agent: {', '.join(available_names) if available_names else 'None'}")
        log_info("Please ensure an SSH Key item (Ed25519 or ECDSA) is loaded in Bitwarden Desktop.")
        sys.exit(1)

    log_ok(f"Found active SSH key: '{target_comment}' ({target_type})")

    try:
        pub_key = extract_public_key_from_blob(target_blob, target_type)
    except Exception as e:
        log_err(f"Failed to parse public key for '{target_comment}': {e}")
        sys.exit(1)

    log_info(f"Issuing X.509 C2PA certificates for {domain} (Root CA -> Leaf)...")
    chain_pem, root_key_pem, root_cert_pem = generate_c2pa_certs_for_public_key(pub_key, domain)

    # Save certificate chain to DEFAULT_CERT_PATH (public certificates only!)
    DEFAULT_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CERT_PATH.write_bytes(chain_pem)
    os.chmod(DEFAULT_CERT_PATH, 0o644)

    # Update configuration (Zero-Disk: watermark secret is derived on-the-fly)
    cfg = load_config()
    cfg["signing_mode"] = "ssh-agent"
    cfg["ssh_key_name"] = target_comment
    cfg["ssh_agent_sock"] = str(sock)
    cfg.pop("watermark_secret", None)
    cfg["domain"] = domain
    cfg.pop("bitwarden_item", None)
    save_config(cfg)

    log_ok(f"Public certificate chain saved: {DEFAULT_CERT_PATH}")
    log_ok(f"Signing mode configured: 'ssh-agent' in {DEFAULT_CONFIG_FILE}")

    # Verify deterministic watermark secret derivation
    try:
        derived_wm = derive_watermark_secret_from_ssh_agent(sock_path=sock, key_name=target_comment)
        if derived_wm:
            log_ok(f"Verified deterministic watermark secret derivation ({derived_wm[:12]}...).")
    except Exception as e:
        log_warn(f"Watermark secret derivation test warning: {e}")

    print(f"\n  {C_BOLD}{C_GREEN}Zero-Knowledge SSH Agent Signing Active!{C_RESET}")
    print(f"  • Private key storage:     {C_CYAN}Bitwarden Desktop Vault (Protected){C_RESET}")
    print(f"  • Private key on disk:     {C_GREEN}0 bytes{C_RESET}")
    print(f"  • Private key in RAM:      {C_GREEN}0 bytes (Agent callback protocol){C_RESET}")
    print(f"  • Signature confirmation:  {C_CYAN}Bitwarden Desktop [Authorize] GUI prompt{C_RESET}")
    print(f"  • Watermark secret:        {C_GREEN}0 bytes on disk (Derived on-the-fly via SSH Agent){C_RESET}\n")
    print(f"  {C_BOLD}Bitwarden Vault Recommendation:{C_RESET}")
    print(f"  Open Bitwarden Desktop -> edit SSH Key entry '{target_comment}':")
    print(f"    1. Add custom text field:   {C_BOLD}cert{C_RESET}             (Paste contents of {DEFAULT_CERT_PATH})")
    print(f"    2. Add custom hidden field: {C_BOLD}root_key{C_RESET}         (Root CA disaster recovery backup below)")
    print(f"    • Watermark secret:         {C_GREEN}No field needed (Derived on-the-fly via SSH Agent){C_RESET}")
    print(f"\n{C_YELLOW}--- BEGIN ROOT CA PRIVATE KEY BACKUP ---{C_RESET}")
    print(root_key_pem.decode("utf-8").strip())
    print(f"{C_YELLOW}--- END ROOT CA PRIVATE KEY BACKUP ---{C_RESET}\n")


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


def stamp_media_files(target_files: list[Path], wait: bool = False, force: bool = False) -> list[Path]:
    """Anchors multiple files in the Bitcoin blockchain via OpenTimestamps in a single batch."""
    to_stamp: list[Path] = []
    created_ots: list[Path] = []

    for f in target_files:
        if not f.is_file():
            continue
        ots_path = f.with_name(f"{f.name}.ots")
        if ots_path.is_file() and not force:
            created_ots.append(ots_path)
        else:
            to_stamp.append(f)

    if not to_stamp:
        return created_ots

    log_info(f"Anchoring {len(to_stamp)} file(s) in Bitcoin blockchain (OpenTimestamps batch)...")
    cli_args = ["stamp"]
    if wait:
        cli_args.append("--wait")
    cli_args.extend(str(f) for f in to_stamp)

    try:
        parsed_args = otsclient.args.parse_ots_args(cli_args)
        parsed_args.cmd_func(parsed_args)
        for f in to_stamp:
            ots_path = f.with_name(f"{f.name}.ots")
            if ots_path.is_file():
                created_ots.append(ots_path)
            else:
                log_warn(f"OpenTimestamps did not produce {ots_path.name}")
        log_ok(f"Created {len(to_stamp)} Bitcoin timestamp proof(s).")
    except Exception as e:
        log_err(f"OpenTimestamps batch stamping failed: {e}")
        raise

    return created_ots


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
                try:
                    ots_p.chmod(0o644)
                except OSError:
                    pass
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
            finally:
                try:
                    ots_p.chmod(0o444)
                except OSError:
                    pass

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
        try:
            ots_file.chmod(0o644)
        except OSError:
            pass
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
    finally:
        try:
            ots_file.chmod(0o444)
        except OSError:
            pass


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
    use_agent: bool = False,
    agent_key_name: str | None = None,
    signer: c2pa.Signer | None = None,
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

    # Determine signing mode: preloaded signer, SSH agent callback, or in-memory / local key
    is_agent_mode = use_agent or (cfg.get("signing_mode") == "ssh-agent" and not bw_item and not key_path)
    c2pa_signer: c2pa.Signer | None = signer
    key_bytes: bytes | None = None
    cert_bytes: bytes | None = None

    if not no_c2pa and c2pa_signer is None:
        if is_agent_mode:
            k_target = agent_key_name or cfg.get("ssh_key_name") or "c2pa-signer"
            c_target = cert_path.read_bytes() if cert_path and cert_path.is_file() else None
            c2pa_signer = create_c2pa_signer_from_ssh_agent(
                key_comment=k_target,
                cert_chain_pem=c_target,
            )
        else:
            key_bytes, cert_bytes = load_or_create_credentials(
                key_path=key_path,
                cert_path=cert_path,
                domain=act_domain,
                bw_item=bw_item,
            )
            signer_info = c2pa.C2paSignerInfo(
                alg=c2pa.C2paSigningAlg.ES256,
                sign_cert=cert_bytes,
                private_key=key_bytes,
                ta_url=None,
            )
            c2pa_signer = c2pa.Signer.from_info(signer_info)

    # Derive watermark permutation secret from key bytes or configuration
    wm_secret = secret
    if not wm_secret and is_agent_mode:
        k_target = agent_key_name or cfg.get("ssh_key_name")
        wm_secret = derive_watermark_secret_from_ssh_agent(key_name=k_target)
    if not wm_secret:
        if key_bytes:
            wm_secret = hashlib.sha256(key_bytes).hexdigest()
        else:
            wm_secret = get_default_secret()

    # Stage 1: Embed DWT-DCT Steganographic Watermark
    is_svg = input_path.suffix.lower() == ".svg"
    is_vid = is_video_path(input_path)
    is_anim = is_animated_image_path(input_path)

    if not no_watermark and not is_svg and not is_vid:
        try:
            with Image.open(input_path) as pil_img:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                if is_anim:
                    log_info(f"Stage 1: Embedding invisible DWT-DCT watermark across animation frames ('{wm_text}')...")
                    out_frames = []
                    durations = []
                    disposals = []
                    loop = pil_img.info.get("loop", 0)
                    is_out_gif = output_path.suffix.lower() == ".gif"
                    is_out_webp = output_path.suffix.lower() == ".webp"

                    for frame in ImageSequence.Iterator(pil_img):
                        durations.append(frame.info.get("duration", 100))
                        disposals.append(frame.info.get("disposal", 2))
                        rgba_frame = frame.convert("RGBA")
                        wm_frame = embed_dwt_watermark(
                            rgba_frame,
                            text=wm_text,
                            secret=wm_secret,
                            delta=wm_delta,
                            repeats=wm_repeats,
                        )
                        if is_out_gif:
                            has_alpha = wm_frame.getchannel("A").getextrema() != (255, 255)
                            if has_alpha:
                                pal_frame = wm_frame.quantize(colors=255, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
                            else:
                                pal_frame = wm_frame.convert("RGB").quantize(colors=256, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
                            out_frames.append(pal_frame)
                        else:
                            out_frames.append(wm_frame)

                    if output_path.is_file():
                        output_path.unlink()

                    save_fmt = "GIF" if is_out_gif else ("WEBP" if is_out_webp else (pil_img.format or "GIF"))
                    save_kwargs: dict[str, Any] = {
                        "save_all": True,
                        "append_images": out_frames[1:],
                        "duration": durations,
                        "loop": loop,
                    }
                    if is_out_gif:
                        save_kwargs["disposal"] = disposals
                    elif is_out_webp:
                        save_kwargs["quality"] = 95

                    out_frames[0].save(output_path, format=save_fmt, **save_kwargs)
                    log_ok(f"Stage 1 complete: Watermark embedded across all {len(out_frames)} animation frames.")
                else:
                    log_info(f"Stage 1: Embedding invisible DWT-DCT watermark ('{wm_text}')...")
                    wm_img = embed_dwt_watermark(
                        pil_img,
                        text=wm_text,
                        secret=wm_secret,
                        delta=wm_delta,
                        repeats=wm_repeats,
                    )
                    save_fmt = pil_img.format or "PNG"
                    save_kwargs = {}
                    if output_path.suffix.lower() in (".jpg", ".jpeg"):
                        save_fmt = "JPEG"
                        save_kwargs = {"quality": 95}
                        if wm_img.mode in ("RGBA", "LA", "P"):
                            wm_img = wm_img.convert("RGB")
                    if output_path.is_file():
                        output_path.unlink()
                    wm_img.save(output_path, format=save_fmt, **save_kwargs)
                    log_ok("Stage 1 complete: Watermark embedded into frequency spectrum.")
        except Exception as e:
            log_err(f"Steganographic watermarking failed: {e}")
            sys.exit(1)
    else:
        if is_vid:
            log_info("Stage 1: Steganography skipped (not applicable to compressed video stream; secured via C2PA + OpenTimestamps).")
        elif is_svg and not no_watermark:
            log_info("Stage 1: Steganography skipped (not applicable to vector XML format).")
        else:
            log_info("Stage 1: Invisible watermarking disabled (--no-watermark).")
        if input_path.resolve() != output_path.resolve():
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if output_path.is_file():
                output_path.unlink()
            shutil.copyfile(input_path, output_path)

    # Stage 2: C2PA Content Credentials
    if not no_c2pa and c2pa_signer:
        log_info("Stage 2: Signing with C2PA Content Credentials...")

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
            if temp_dest.is_file():
                temp_dest.unlink()
            builder.sign_file(str(output_path), str(temp_dest), c2pa_signer)
            temp_dest.replace(output_path)
            log_ok("Stage 2 complete: C2PA cryptographic manifest embedded.")
        except Exception as e:
            if is_vid and ("unsupported" in str(e).lower() or "notsupported" in str(e).lower()):
                log_warn(f"Stage 2: C2PA manifest embedding not supported for video container '{output_path.suffix}'; secured via Bitcoin blockchain timestamp.")
                temp_dest = output_path.with_suffix(f".tmp{output_path.suffix}")
                if temp_dest.is_file():
                    temp_dest.unlink()
            else:
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


def echo_summary(
    has_c2pa: bool,
    has_wm: bool,
    ots_status: str | None = None,
    is_vector: bool = False,
    is_video: bool = False,
    is_anim: bool = False,
) -> None:
    print(f"\n  {C_BOLD}Summary Verdict:{C_RESET}")
    ots_valid = (ots_status in ("confirmed", "pending"))

    if is_video and has_c2pa and ots_valid:
        print(f"    {C_GREEN}★ Dual-Layer Video Attestation Verified (C2PA Content Credentials + OpenTimestamps; Steganography N/A for Video).{C_RESET}\n")
    elif is_video and ots_valid:
        print(f"    {C_BLUE}✓ Blockchain Video Timestamp Verified (OpenTimestamps Bitcoin proof).{C_RESET}\n")
    elif is_vector and has_c2pa and ots_valid:
        print(f"    {C_GREEN}★ Dual-Layer Vector Attestation Verified (C2PA + OpenTimestamps; Steganography N/A for SVG).{C_RESET}\n")
    elif is_anim and has_c2pa and has_wm and ots_valid:
        print(f"    {C_GREEN}★ Full Triple-Layer Animation Attestation Verified (C2PA + Per-Frame Steganography + OpenTimestamps).{C_RESET}\n")
    elif has_c2pa and has_wm and ots_valid:
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
    use_agent: bool = False,
    agent_key_name: str | None = None,
) -> None:
    """Verifies C2PA Content Credentials, DWT-DCT invisible watermarks, and OpenTimestamps."""
    if not image_path.is_file():
        log_err(f"File not found: {image_path}")
        sys.exit(1)

    if not as_json:
        log_head(f"Media Verification: {image_path.name}")

    is_svg = (image_path.suffix.lower() == ".svg")
    is_vid = is_video_path(image_path)
    is_anim = is_animated_image_path(image_path)

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
    if not wm_secret and (use_agent or cfg.get("signing_mode") == "ssh-agent"):
        k_target = agent_key_name or cfg.get("ssh_key_name")
        wm_secret = derive_watermark_secret_from_ssh_agent(key_name=k_target)
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
        if DEFAULT_KEY_PATH.is_file():
            try:
                wm_secret = hashlib.sha256(DEFAULT_KEY_PATH.read_bytes()).hexdigest()
            except Exception:
                pass
    if not wm_secret:
        wm_secret = get_default_secret()
    wm_repeats = int(cfg.get("watermark_repeats", 3))
    detected_wm: str | None = None

    if is_svg or is_vid:
        detected_wm = None
    else:
        try:
            with Image.open(image_path) as pil_img:
                if getattr(pil_img, "is_animated", False) and getattr(pil_img, "n_frames", 1) > 1:
                    for f in ImageSequence.Iterator(pil_img):
                        detected_wm = extract_dwt_watermark(f, secret=wm_secret, repeats=wm_repeats)
                        if detected_wm:
                            break
                else:
                    detected_wm = extract_dwt_watermark(pil_img, secret=wm_secret, repeats=wm_repeats)
        except Exception as e:
            log_warn(f"Watermark scan error: {e}")

    # 3. Verify OpenTimestamps Proof (Stage 3)
    ots_data = inspect_ots_proof(image_path, ots_path=ots_path)

    if as_json:
        fmt_str = "video" if is_vid else ("svg" if is_svg else ("animated" if is_anim else "raster"))
        result = {
            "file": str(image_path),
            "format": fmt_str,
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
    if is_vid:
        print(f"    {C_BLUE}ℹ N/A (Video stream; pixel-domain steganography not applicable){C_RESET}")
    elif is_svg:
        print(f"    {C_BLUE}ℹ N/A (Vector XML asset; pixel-domain steganography not applicable){C_RESET}")
    elif detected_wm:
        anim_note = " (Detected across animation frames)" if is_anim else ""
        print(f"    {C_GREEN}✓ Watermark Decoded:{C_RESET} \"{C_BOLD}{detected_wm}{C_RESET}\"{anim_note}")
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
        is_vector=is_svg,
        is_video=is_vid,
        is_anim=is_anim,
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
# Asset Pipeline: Manifest & Aspect Ratio Detection
# ------------------------------------------------------------------------------
def detect_aspect_ratio_and_targets(
    w: int,
    h: int,
    name: str = "",
    version: str = "",
) -> dict[str, Any]:
    """Auto-detects aspect ratio and sensible downscale targets based on master image dimensions."""
    r = (w / h) if h > 0 else 1.0

    if abs(r - 1.0) < 0.03:
        ratio_name = "1:1"
        targets = [
            {"width": 512, "height": 512, "label": "512"},
            {"width": 256, "height": 256, "label": "256"},
            {"width": 128, "height": 128, "label": "128"},
            {"width": 64, "height": 64, "label": "64"},
            {"width": 32, "height": 32, "label": "32"},
        ]
        generate_favicon = True
    elif abs(r - 16 / 9) < 0.03:
        ratio_name = "16:9"
        targets = [
            {"width": 1920, "height": 1080, "label": "1920x1080"},
            {"width": 1280, "height": 720, "label": "1280x720"},
            {"width": 854, "height": 480, "label": "854x480"},
            {"width": 640, "height": 360, "label": "640x360"},
        ]
        generate_favicon = True
    elif abs(r - 16 / 10) < 0.03:
        ratio_name = "16:10"
        targets = [
            {"width": 1920, "height": 1200, "label": "1920x1200"},
            {"width": 1440, "height": 900, "label": "1440x900"},
            {"width": 1280, "height": 800, "label": "1280x800"},
            {"width": 640, "height": 400, "label": "640x400"},
        ]
        generate_favicon = True
    elif abs(r - 4 / 3) < 0.03:
        ratio_name = "4:3"
        targets = [
            {"width": 1600, "height": 1200, "label": "1600x1200"},
            {"width": 1200, "height": 900, "label": "1200x900"},
            {"width": 800, "height": 600, "label": "800x600"},
            {"width": 640, "height": 480, "label": "640x480"},
        ]
        generate_favicon = True
    elif abs(r - 21 / 9) < 0.05 or abs(r - 64 / 27) < 0.05:
        ratio_name = "21:9"
        targets = [
            {"width": 2560, "height": 1080, "label": "2560x1080"},
            {"width": 1920, "height": 810, "label": "1920x810"},
            {"width": 1280, "height": 540, "label": "1280x540"},
        ]
        generate_favicon = True
    elif abs(r - 9 / 16) < 0.03:
        ratio_name = "9:16"
        targets = [
            {"width": 1080, "height": 1920, "label": "1080x1920"},
            {"width": 720, "height": 1280, "label": "720x1280"},
            {"width": 360, "height": 640, "label": "360x640"},
        ]
        generate_favicon = True
    elif abs(r - 3 / 4) < 0.03:
        ratio_name = "3:4"
        targets = [
            {"width": 1200, "height": 1600, "label": "1200x1600"},
            {"width": 900, "height": 1200, "label": "900x1200"},
            {"width": 600, "height": 800, "label": "600x800"},
        ]
        generate_favicon = True
    else:
        gcd_val = math.gcd(w, h)
        ratio_name = f"{w // gcd_val}:{h // gcd_val}" if gcd_val > 1 else f"{w}x{h}"
        targets = []
        for step in (1.0, 0.75, 0.5, 0.25):
            tw = max(16, round(w * step))
            th = max(16, round(h * step))
            targets.append({"width": tw, "height": th, "label": f"{tw}x{th}"})
        generate_favicon = True

    # Filter out targets larger than master image
    filtered_targets = [t for t in targets if t["width"] <= w * 1.05 and t["height"] <= h * 1.05]
    if not filtered_targets:
        filtered_targets = [{"width": w, "height": h, "label": (str(w) if w == h else f"{w}x{h}")}]
        if w >= 64 and h >= 64:
            filtered_targets.append({
                "width": w // 2,
                "height": h // 2,
                "label": (str(w // 2) if w == h else f"{w // 2}x{h // 2}"),
            })

    return {
        "name": name,
        "version": version,
        "aspect_ratio": ratio_name,
        "master_dimensions": f"{w}x{h}",
        "resize_mode": "pad",
        "pad_color": "transparent",
        "generate_favicon": generate_favicon,
        "formats": ["webp", "png"],
        "targets": filtered_targets,
        "signed": {
            "enabled": False,
            "sizes": [],
        },
        "metadata": {
            "author": "",
            "domain": "",
            "license": "",
            "description": "",
        },
        "watermark": {
            "text": "",
        },
    }


def strip_json_comments(text: str) -> str:
    """Removes single-line (//) and multi-line (/* */) comments from JSON text while preserving strings."""
    pattern = re.compile(
        r'("(?:\\.|[^"\\])*")|//.*?$|/\*.*?\*/',
        re.MULTILINE | re.DOTALL,
    )

    def replacer(match: re.Match) -> str:
        if match.group(1):
            return match.group(1)
        return ""

    return pattern.sub(replacer, text)


def render_manifest_json(manifest: dict[str, Any]) -> str:
    """Formats manifest dictionary into human-friendly, self-documenting JSONC with inline guides."""
    name = manifest.get("name", "asset")
    version = manifest.get("version", "v1")
    aspect_ratio = manifest.get("aspect_ratio", "auto")
    master_dim = manifest.get("master_dimensions", "")
    resize_mode = manifest.get("resize_mode", "pad")
    pad_color = manifest.get("pad_color", "transparent")
    gen_favicon = bool(manifest.get("generate_favicon", True))
    formats = manifest.get("formats", ["webp", "png"])
    targets = manifest.get("targets", [])
    signed = manifest.get("signed", {})
    if isinstance(signed, bool):
        signed = {"enabled": signed, "sizes": []}
    elif not isinstance(signed, dict):
        signed = {"enabled": True, "sizes": [signed]}

    signed_enabled = bool(signed.get("enabled", False))
    signed_sizes = signed.get("sizes", [])

    meta = manifest.get("metadata", {})
    meta_author = meta.get("author", "")
    meta_domain = meta.get("domain", "")
    meta_license = meta.get("license", "")
    meta_description = meta.get("description", "")

    wm = manifest.get("watermark", {})
    wm_text = wm.get("text", "")

    target_lines = []
    for t in targets:
        if isinstance(t, dict):
            w = t.get("width")
            h = t.get("height")
            lbl = t.get("label", str(w) if w == h else f"{w}x{h}")
            parts = [f'"width": {w}', f'"height": {h}', f'"label": "{lbl}"']
            if "resize_mode" in t:
                parts.append(f'"resize_mode": "{t["resize_mode"]}"')
            if "pad_color" in t:
                parts.append(f'"pad_color": "{t["pad_color"]}"')
            if "source" in t:
                parts.append(f'"source": "{t["source"]}"')
            target_lines.append(f'    {{ {", ".join(parts)} }}')
        elif isinstance(t, int):
            target_lines.append(f'    {t}')
        else:
            target_lines.append(f'    {json.dumps(t)}')
    targets_str = ",\n".join(target_lines)

    formats_str = ", ".join(f'"{f}"' for f in formats)

    signed_size_parts = []
    for s in signed_sizes:
        if isinstance(s, dict):
            w = s.get("width")
            h = s.get("height")
            lbl = s.get("label", str(w) if w == h else f"{w}x{h}")
            signed_size_parts.append(f'{{ "width": {w}, "height": {h}, "label": "{lbl}" }}')
        else:
            signed_size_parts.append(json.dumps(s))
    signed_sizes_str = ", ".join(signed_size_parts)

    gen_favicon_str = "true" if gen_favicon else "false"
    signed_enabled_str = "true" if signed_enabled else "false"

    lines = [
        "{",
        "  // --------------------------------------------------------------------------",
        f"  // Media Asset Pipeline Manifest: {name} ({version})",
        "  // Documentation: man media(1) | media --help",
        "  // --------------------------------------------------------------------------",
        f'  "name": "{name}",',
        f'  "version": "{version}",',
        "",
        '  // Aspect Ratio & Master Dimensions:',
        '  // Auto-detected on build from raster image or vector SVG viewBox.',
        '  // Options: "auto", "1:1", "16:9", "16:10", "4:3", "21:9", "9:16", "3:4", or "WxH"',
        f'  "aspect_ratio": "{aspect_ratio}",',
    ]

    if master_dim:
        lines.append(f'  "master_dimensions": "{master_dim}",')

    lines.extend([
        "",
        '  // Fitting Policy & Canvas Padding (when source and target aspect ratios differ):',
        '  // Options: "pad" (letterbox with transparent alpha borders, preserves entire graphic),',
        '  //          "crop" (center-crop to fill target dimensions),',
        '  //          "stretch" (resizes without preserving aspect ratio),',
        '  //          "fit" (scales to fit within target bounding box without canvas padding)',
        f'  "resize_mode": "{resize_mode}",',
        '  // Background color for "pad" mode: "transparent" (RGBA alpha=0), or hex color e.g. "#ffffff"',
        f'  "pad_color": "{pad_color}",',
        "",
        '  // Favicon Generation:',
        '  // When true, generates multi-resolution generated/favicon.ico (16, 32, 48, 64, 128, 256 layers).',
        '  // Multi-source selection: if a 1:1 square source exists in to_generate/, it is automatically prioritized.',
        '  // For rectangular sources, "resize_mode" (default "pad") renders clean icons with alpha padding.',
        f'  "generate_favicon": {gen_favicon_str},',
        "",
        '  // Distribution Formats (rendered into generated/):',
        '  // Supported: ["webp", "png", "svg", "gif", "mp4", "webm"] ("svg" for vector, "mp4"/"webm" for video)',
        f'  "formats": [{formats_str}],',
        "",
        '  // Distribution Resolutions (rendered into generated/):',
        '  // For raster masters: resized with Lanczos filter. For vector SVG: rasterized at native sharpness.',
        '  // Supports objects {"width": 512, "height": 512, "label": "512"}, numbers [512, 256], or strings ["1920x1080"]',
        '  // Targets can optionally specify custom "resize_mode", "pad_color", or explicit "source" filename.',
    ])

    if target_lines:
        lines.append('  "targets": [')
        lines.append(",\n".join(target_lines))
        lines.append('  ],')
    else:
        lines.append('  "targets": [],')

    lines.extend([
        "",
        '  // Additional Scaled Releases (C2PA + DWT + OTS signatures in signed/):',
        '  // When enabled, renders master into specified sizes and applies all cryptographic signatures.',
        '  // Note: Master clone (raster or SVG) and extra to_sign/ files are always signed into signed/.',
        '  // Leave sizes empty [] if only master clone and extra to_sign/ files should be signed.',
        '  "signed": {',
        f'    "enabled": {signed_enabled_str},',
        f'    "sizes": [{signed_sizes_str}]',
        '  },',
        "",
        '  // Optional C2PA Content Credentials metadata overrides:',
        '  // Embedded into raster images (PNG/WebP/JPG) and vector SVG XML metadata.',
        '  // Leave empty strings "" to use global defaults from ~/.config/nadamu/c2pa.json',
        '  "metadata": {',
        f'    "author": "{meta_author}",',
        f'    "domain": "{meta_domain}",',
        f'    "license": "{meta_license}",',
        f'    "description": "{meta_description}"',
        '  },',
        "",
        '  // Optional Invisible DWT-DCT Steganography overrides:',
        '  // Applied to raster releases; vector SVGs are secured via C2PA cryptographic assertion + Bitcoin OTS.',
        '  // Leave empty string "" to use global default from ~/.config/nadamu/c2pa.json ("NADAMU")',
        '  "watermark": {',
        f'    "text": "{wm_text}"',
        '  }',
        "}",
        "",
    ])
    return "\n".join(lines)


def load_or_resolve_manifest(
    target_dir: Path,
    name: str,
    version: str,
    master_path: Path | None = None,
    sizes_cli: str | None = None,
) -> dict[str, Any]:
    """Loads manifest.json from target_dir (or parent), or auto-detects from master image."""
    manifest_file = target_dir / "manifest.json"
    if not manifest_file.is_file() and (target_dir.parent / "manifest.json").is_file():
        manifest_file = target_dir.parent / "manifest.json"

    manifest: dict[str, Any] = {}
    if manifest_file.is_file():
        try:
            content = manifest_file.read_text(encoding="utf-8")
            clean_content = strip_json_comments(content)
            manifest = json.loads(clean_content)
        except Exception as e:
            log_warn(f"Failed to read existing manifest {manifest_file}: {e}")
            manifest = {}

    # Inspect master image dimensions if available
    master_w, master_h = 0, 0
    if master_path and master_path.is_file():
        if master_path.suffix.lower() == ".svg":
            master_w, master_h = get_svg_dimensions(master_path)
        elif is_video_path(master_path):
            master_w, master_h = get_video_dimensions(master_path)
        else:
            try:
                with Image.open(master_path) as img:
                    master_w, master_h = img.size
            except Exception:
                pass

    # If manifest is empty or aspect_ratio was "auto", compute from master
    if not manifest:
        if master_w > 0 and master_h > 0:
            manifest = detect_aspect_ratio_and_targets(master_w, master_h, name=name, version=version)
            if master_path:
                msfx = master_path.suffix.lower()
                if msfx == ".svg" and "svg" not in manifest["formats"]:
                    manifest["formats"].append("svg")
                elif msfx == ".gif" and "gif" not in manifest["formats"]:
                    manifest["formats"].insert(0, "gif")
                elif is_video_path(master_path):
                    v_fmt = msfx.lstrip(".")
                    if v_fmt not in manifest["formats"]:
                        manifest["formats"].insert(0, v_fmt)
            save_path = target_dir / "manifest.json"
            try:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_text(render_manifest_json(manifest), encoding="utf-8")
                log_ok(f"Generated asset manifest ({manifest['aspect_ratio']}): {save_path.name}")
            except Exception as e:
                log_warn(f"Could not save manifest: {e}")
        else:
            manifest = {
                "name": name,
                "version": version,
                "aspect_ratio": "1:1",
                "resize_mode": "pad",
                "pad_color": "transparent",
                "generate_favicon": True,
                "formats": ["webp", "png"],
                "targets": [
                    {"width": 512, "height": 512, "label": "512"},
                    {"width": 256, "height": 256, "label": "256"},
                    {"width": 128, "height": 128, "label": "128"},
                    {"width": 64, "height": 64, "label": "64"},
                    {"width": 32, "height": 32, "label": "32"},
                ],
                "signed": {
                    "enabled": False,
                    "sizes": [],
                },
                "metadata": {
                    "author": "",
                    "domain": "",
                    "license": "",
                    "description": "",
                },
                "watermark": {
                    "text": "",
                },
            }
    elif manifest.get("aspect_ratio") == "auto":
        # Manifest exists from init with "auto" aspect ratio: update ratio and dimensions, but keep user custom fields
        if master_w > 0 and master_h > 0:
            auto_m = detect_aspect_ratio_and_targets(master_w, master_h, name=name, version=version)
            manifest["aspect_ratio"] = auto_m["aspect_ratio"]
            manifest["master_dimensions"] = auto_m["master_dimensions"]
            if "resize_mode" not in manifest:
                manifest["resize_mode"] = auto_m.get("resize_mode", "pad")
            if "pad_color" not in manifest:
                manifest["pad_color"] = auto_m.get("pad_color", "transparent")
            if master_path:
                msfx = master_path.suffix.lower()
                if msfx == ".svg" and "svg" not in manifest.get("formats", []):
                    manifest.setdefault("formats", []).append("svg")
                elif msfx == ".gif" and "gif" not in manifest.get("formats", []):
                    manifest.setdefault("formats", []).insert(0, "gif")
                elif is_video_path(master_path):
                    v_fmt = msfx.lstrip(".")
                    if v_fmt not in manifest.get("formats", []):
                        manifest.setdefault("formats", []).insert(0, v_fmt)
            if auto_m["aspect_ratio"] != "1:1" and (not manifest.get("targets") or manifest.get("targets") == [
                {"width": 512, "height": 512, "label": "512"},
                {"width": 256, "height": 256, "label": "256"},
                {"width": 128, "height": 128, "label": "128"},
                {"width": 64, "height": 64, "label": "64"},
                {"width": 32, "height": 32, "label": "32"},
            ]):
                manifest["targets"] = auto_m["targets"]
                manifest["generate_favicon"] = auto_m["generate_favicon"]
            if "signed" not in manifest:
                manifest["signed"] = auto_m["signed"]
            if "metadata" not in manifest:
                manifest["metadata"] = auto_m["metadata"]
            if "watermark" not in manifest:
                manifest["watermark"] = auto_m["watermark"]
            save_path = target_dir / "manifest.json"
            try:
                save_path.write_text(render_manifest_json(manifest), encoding="utf-8")
                log_ok(f"Updated asset manifest ({manifest['aspect_ratio']}): {save_path.name}")
            except Exception as e:
                log_warn(f"Could not save manifest: {e}")

    # Handle CLI --sizes override if provided
    r = (master_w / master_h) if (master_w > 0 and master_h > 0) else 1.0
    is_sq = abs(r - 1.0) < 0.03
    if sizes_cli:
        cli_targets = []
        for part in sizes_cli.split(","):
            part = part.strip()
            if not part:
                continue
            if "x" in part.lower():
                pw, ph = part.lower().split("x", 1)
                tw, th = int(pw), int(ph)
                cli_targets.append({"width": tw, "height": th, "label": f"{tw}x{th}"})
            else:
                dim = int(part)
                if is_sq:
                    cli_targets.append({"width": dim, "height": dim, "label": str(dim)})
                else:
                    th = max(1, round(dim / r))
                    cli_targets.append({"width": dim, "height": th, "label": f"{dim}x{th}"})
        if cli_targets:
            manifest["targets"] = cli_targets

    # Normalize targets in manifest
    normalized_targets: list[dict[str, Any]] = []
    raw_targets = manifest.get("targets") or manifest.get("sizes") or []
    for item in raw_targets:
        if isinstance(item, int):
            if is_sq:
                normalized_targets.append({"width": item, "height": item, "label": str(item)})
            else:
                th = max(1, round(item / r))
                normalized_targets.append({"width": item, "height": th, "label": f"{item}x{th}"})
        elif isinstance(item, str):
            if "x" in item.lower():
                pw, ph = item.lower().split("x", 1)
                tw, th = int(pw), int(ph)
                normalized_targets.append({"width": tw, "height": th, "label": f"{tw}x{th}"})
            else:
                dim = int(item)
                if is_sq:
                    normalized_targets.append({"width": dim, "height": dim, "label": str(dim)})
                else:
                    th = max(1, round(dim / r))
                    normalized_targets.append({"width": dim, "height": th, "label": f"{dim}x{th}"})
        elif isinstance(item, dict):
            tw = int(item["width"])
            th = int(item["height"])
            lbl = item.get("label") or (str(tw) if tw == th else f"{tw}x{th}")
            normalized_targets.append({"width": tw, "height": th, "label": lbl})

    manifest["targets"] = normalized_targets

    # Normalize signed configuration in manifest
    raw_signed = manifest.get("signed")
    if raw_signed is None:
        raw_signed = manifest.get("showcase")

    signed_config: dict[str, Any] = {"enabled": True, "sizes": [], "targets": []}
    if raw_signed is False:
        signed_config["enabled"] = False
        signed_config["sizes"] = []
    elif isinstance(raw_signed, (int, str)):
        signed_config["enabled"] = True
        signed_config["sizes"] = [raw_signed]
    elif isinstance(raw_signed, list):
        signed_config["enabled"] = True
        signed_config["sizes"] = raw_signed
    elif isinstance(raw_signed, dict):
        signed_config["enabled"] = bool(raw_signed.get("enabled", True))
        raw_sizes = raw_signed.get("sizes") or ([raw_signed.get("size")] if raw_signed.get("size") else [])
        signed_config["sizes"] = raw_sizes if isinstance(raw_sizes, list) else [raw_sizes]

    signed_targets: list[dict[str, Any]] = []
    if signed_config["enabled"]:
        for item in signed_config["sizes"]:
            if isinstance(item, int):
                dim = item
                if is_sq:
                    signed_targets.append({"width": dim, "height": dim, "label": str(dim)})
                else:
                    if master_w >= master_h:
                        tw = dim
                        th = max(1, round(dim / r))
                    else:
                        th = dim
                        tw = max(1, round(dim * r))
                    signed_targets.append({"width": tw, "height": th, "label": str(dim)})
            elif isinstance(item, str):
                if "x" in item.lower():
                    pw, ph = item.lower().split("x", 1)
                    signed_targets.append({"width": int(pw), "height": int(ph), "label": f"{int(pw)}x{int(ph)}"})
                else:
                    dim = int(item)
                    if is_sq:
                        signed_targets.append({"width": dim, "height": dim, "label": str(dim)})
                    else:
                        if master_w >= master_h:
                            tw = dim
                            th = max(1, round(dim / r))
                        else:
                            th = dim
                            tw = max(1, round(dim * r))
                        signed_targets.append({"width": tw, "height": th, "label": str(dim)})
            elif isinstance(item, dict):
                tw = int(item["width"])
                th = int(item["height"])
                lbl = item.get("label") or (str(tw) if tw == th else f"{tw}x{th}")
                signed_targets.append({"width": tw, "height": th, "label": lbl})

    signed_config["targets"] = signed_targets
    manifest["signed"] = signed_config

    return manifest


# ------------------------------------------------------------------------------
# Asset Pipeline: Init, Build, Audit, List, Upgrade
# ------------------------------------------------------------------------------
def execute_init(
    name: str,
    version: str,
    base_dir: Path | None = None,
    proofs_dir: Path | None = None,
) -> tuple[Path, Path | None]:
    """Initializes standard asset folder hierarchy with clean directory names and manifest."""
    icons_dir = base_dir or get_default_icons_dir()
    resolved_proofs_dir = proofs_dir or get_default_proofs_dir(icons_dir)

    target_dir = icons_dir / name / version
    raw_dir = target_dir / "raw"
    to_sign_dir = target_dir / "to_sign"
    to_gen_dir = to_sign_dir / "to_generate"
    gen_dir = target_dir / "generated"
    signed_dir = target_dir / "signed"

    raw_dir.mkdir(parents=True, exist_ok=True)
    to_sign_dir.mkdir(parents=True, exist_ok=True)
    to_gen_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)
    signed_dir.mkdir(parents=True, exist_ok=True)

    # Initialize default manifest.json if absent
    manifest_path = target_dir / "manifest.json"
    if not manifest_path.exists():
        manifest_data = {
            "name": name,
            "version": version,
            "aspect_ratio": "auto",
            "resize_mode": "pad",
            "pad_color": "transparent",
            "generate_favicon": True,
            "formats": ["webp", "png"],
            "targets": [
                {"width": 512, "height": 512, "label": "512"},
                {"width": 256, "height": 256, "label": "256"},
                {"width": 128, "height": 128, "label": "128"},
                {"width": 64, "height": 64, "label": "64"},
                {"width": 32, "height": 32, "label": "32"},
            ],
            "signed": {
                "enabled": False,
                "sizes": [],
            },
            "metadata": {
                "author": "",
                "domain": "",
                "license": "",
                "description": "",
            },
            "watermark": {
                "text": "",
            },
        }
        try:
            manifest_path.write_text(render_manifest_json(manifest_data), encoding="utf-8")
            log_ok(f"Build Manifest: {manifest_path}")
        except Exception as e:
            log_warn(f"Failed to create manifest {manifest_path}: {e}")

    target_proofs_dir = None
    if resolved_proofs_dir:
        target_proofs_dir = resolved_proofs_dir / name / version
        (target_proofs_dir / "raw").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "to_sign" / "to_generate").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "generated").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "signed").mkdir(parents=True, exist_ok=True)

    log_head(f"Initialized Asset Structure: {name} ({version})")
    log_ok(f"Raw Project:    {raw_dir}")
    log_ok(f"To Sign / Gen:  {to_gen_dir}")
    log_ok(f"To Sign (Extra):{to_sign_dir}")
    log_ok(f"Generated:      {gen_dir}")
    log_ok(f"Signed Release: {signed_dir}")
    if target_proofs_dir:
        log_ok(f"Proofs Archive: {target_proofs_dir}")

    print(f"\n  {C_BOLD}Next steps:{C_RESET}")
    print(f"    1. Place raw canvas (e.g. {name}.xcf) into:        {C_CYAN}{raw_dir}/{C_RESET}")
    print(f"    2. Place master image (PNG/WebP) into:             {C_CYAN}{to_gen_dir}/{C_RESET}")
    print(f"    3. (Optional) Place extra images to sign into:     {C_CYAN}{to_sign_dir}/{C_RESET}")
    print(f"    4. (Optional) Customize sizes in:                 {C_CYAN}{manifest_path}/{C_RESET}")
    print(f"    5. Run build: {C_GREEN}media build {name} {version}{C_RESET}\n")

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

            # Seamless backward-compatibility check for legacy 'source' / '01_source' / 'raw' / 'dist' / 'generated' paths
            if not expected_target.is_file():
                rel_str = str(rel.parent)
                candidate_paths: list[Path] = []
                if rel_str in ("source/raw", "01_source/raw"):
                    candidate_paths.append(target_dir / "raw" / base_name)
                elif rel_str == "raw":
                    candidate_paths.append(target_dir / "source" / "raw" / base_name)
                    candidate_paths.append(target_dir / "01_source" / "raw" / base_name)

                if rel_str in ("dist", "03_dist"):
                    candidate_paths.append(target_dir / "generated" / base_name)
                elif rel_str == "generated":
                    candidate_paths.append(target_dir / "dist" / base_name)
                    candidate_paths.append(target_dir / "03_dist" / base_name)

                if rel_str in ("signed", "02_signed"):
                    candidate_paths.append(target_dir / "signed" / base_name)
                    candidate_paths.append(target_dir / "02_signed" / base_name)

                if rel_str in ("source/master", "01_source/master"):
                    candidate_paths.append(target_dir / "to_sign" / "to_generate" / base_name)
                    candidate_paths.append(target_dir / "signed" / base_name)
                elif rel_str in ("to_sign/to_generate", "to_sign"):
                    candidate_paths.append(target_dir / "source" / "master" / base_name)
                    candidate_paths.append(target_dir / "01_source" / "master" / base_name)

                for cand in candidate_paths:
                    if cand.is_file():
                        expected_target = cand
                        break

                # Universal search across target_dir for base_name if still not matched
                if not expected_target.is_file():
                    matches = [
                        f for f in target_dir.rglob(base_name)
                        if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
                    ]
                    if matches:
                        expected_target = matches[0]

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

    # Verify that all files in raw, to_sign, generated, signed (and legacy source/dist) have .ots proofs
    target_files_checked = set(all_ots_map.values())
    stamped_dirs = []
    for d_name in ["raw", "to_sign", "generated", "signed", "source", "01_source", "02_signed", "dist", "03_dist"]:
        cand = target_dir / d_name
        if cand.is_dir():
            stamped_dirs.append(cand)

    for s_dir in stamped_dirs:
        for f in s_dir.rglob("*"):
            if (
                f.is_file()
                and not f.name.endswith(".ots")
                and not f.name.startswith(".")
                and f.name != "manifest.json"
            ):
                if f not in target_files_checked:
                    violations.append({
                        "path": str(f.relative_to(target_dir)),
                        "type": "MISSING_PROOF",
                        "severity": "WARN",
                        "desc": f"Asset in {f.parent.name}/ has not been anchored in Bitcoin blockchain (.ots missing).",
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


def migrate_proofs_directory(proofs_dir: Path | None) -> int:
    """Migrates legacy proofs directories (source/raw, source/master, dist, 02_signed)
    to clean 1:1 mirror structure (raw, to_sign/to_generate, generated, signed)."""
    if not proofs_dir or not proofs_dir.is_dir():
        return 0

    migrated_count = 0

    # 1. raw: migrate source/raw and 01_source/raw -> raw/
    p_raw = proofs_dir / "raw"
    for old_raw in (proofs_dir / "source" / "raw", proofs_dir / "01_source" / "raw"):
        if old_raw.is_dir():
            p_raw.mkdir(parents=True, exist_ok=True)
            for old_ots in old_raw.glob("*.ots"):
                new_ots = p_raw / old_ots.name
                if new_ots.is_file():
                    new_ots.unlink()
                shutil.move(old_ots, new_ots)
                migrated_count += 1
            try:
                old_raw.rmdir()
                old_raw.parent.rmdir()
            except OSError:
                pass

    # 2. to_sign/to_generate: migrate source/master and 01_source/master -> to_sign/to_generate/
    p_to_gen = proofs_dir / "to_sign" / "to_generate"
    for old_master in (proofs_dir / "source" / "master", proofs_dir / "01_source" / "master"):
        if old_master.is_dir():
            p_to_gen.mkdir(parents=True, exist_ok=True)
            for old_ots in old_master.glob("*.ots"):
                new_ots = p_to_gen / old_ots.name
                if new_ots.is_file():
                    new_ots.unlink()
                shutil.move(old_ots, new_ots)
                migrated_count += 1
            try:
                old_master.rmdir()
                old_master.parent.rmdir()
            except OSError:
                pass

    # 3. to_sign: any remaining .ots in source/ or 01_source/ -> to_sign/
    for old_source in (proofs_dir / "source", proofs_dir / "01_source"):
        if old_source.is_dir():
            p_to_sign = proofs_dir / "to_sign"
            for old_ots in old_source.glob("*.ots"):
                p_to_sign.mkdir(parents=True, exist_ok=True)
                new_ots = p_to_sign / old_ots.name
                if new_ots.is_file():
                    new_ots.unlink()
                shutil.move(old_ots, new_ots)
                migrated_count += 1
            try:
                old_source.rmdir()
            except OSError:
                pass

    # 4. generated: migrate dist and 03_dist -> generated/
    p_gen = proofs_dir / "generated"
    for old_dist in (proofs_dir / "dist", proofs_dir / "03_dist"):
        if old_dist.is_dir():
            p_gen.mkdir(parents=True, exist_ok=True)
            for old_ots in old_dist.glob("*.ots"):
                new_ots = p_gen / old_ots.name
                if new_ots.is_file():
                    new_ots.unlink()
                shutil.move(old_ots, new_ots)
                migrated_count += 1
            try:
                old_dist.rmdir()
            except OSError:
                pass

    # 5. signed: migrate 02_signed -> signed/
    p_signed = proofs_dir / "signed"
    for old_signed in (proofs_dir / "02_signed",):
        if old_signed.is_dir():
            p_signed.mkdir(parents=True, exist_ok=True)
            for old_ots in old_signed.glob("*.ots"):
                new_ots = p_signed / old_ots.name
                if new_ots.is_file():
                    new_ots.unlink()
                shutil.move(old_ots, new_ots)
                migrated_count += 1
            try:
                old_signed.rmdir()
            except OSError:
                pass

    return migrated_count


def execute_build(
    name: str,
    version: str,
    master_path: Path | None = None,
    raw_path: Path | None = None,
    base_dir: Path | None = None,
    proofs_dir: Path | None = None,
    sizes: list[int] | None = None,
    sizes_cli: str | None = None,
    resize_mode: str | None = None,
    pad_color: str | None = None,
    bw_item: str | None = None,
    use_agent: bool = False,
    agent_key_name: str | None = None,
    no_sign: bool = False,
    no_stamp: bool = False,
    force: bool = False,
) -> None:
    """Executes atomic multi-scale build pipeline for an asset version."""
    icons_dir = base_dir or get_default_icons_dir()
    resolved_proofs_dir = proofs_dir or get_default_proofs_dir(icons_dir)
    target_dir = icons_dir / name / version

    # Resolve primary and legacy directories
    raw_dest_dir = target_dir / "raw"
    if not raw_dest_dir.is_dir():
        if (target_dir / "source" / "raw").is_dir():
            raw_dest_dir = target_dir / "source" / "raw"
        elif (target_dir / "01_source" / "raw").is_dir():
            raw_dest_dir = target_dir / "01_source" / "raw"

    to_sign_dir = target_dir / "to_sign"
    to_gen_dir = to_sign_dir / "to_generate"
    legacy_master_dir = None
    if not to_gen_dir.is_dir():
        if (target_dir / "source" / "master").is_dir():
            legacy_master_dir = target_dir / "source" / "master"
        elif (target_dir / "01_source" / "master").is_dir():
            legacy_master_dir = target_dir / "01_source" / "master"

    gen_dir = target_dir / "generated"
    if not gen_dir.is_dir():
        if (target_dir / "dist").is_dir():
            gen_dir = target_dir / "dist"
        elif (target_dir / "03_dist").is_dir():
            gen_dir = target_dir / "03_dist"

    signed_dir = target_dir / "signed"
    if not signed_dir.is_dir():
        if (target_dir / "02_signed").is_dir():
            signed_dir = target_dir / "02_signed"

    # Discover all candidate source images in to_generate/ (and legacy locations)
    search_gen_dir = to_gen_dir
    if not search_gen_dir.is_dir() and legacy_master_dir and legacy_master_dir.is_dir():
        search_gen_dir = legacy_master_dir
    elif not search_gen_dir.is_dir() and to_sign_dir.is_dir():
        search_gen_dir = to_sign_dir

    sources = discover_sources(search_gen_dir, explicit_master=master_path)

    # Auto-detect primary master image if not provided
    if master_path is None:
        if sources:
            # Prefer vector source, then first source
            master_source = next((s for s in sources if s["is_vector"]), sources[0])
            master_path = master_source["path"]
            log_info(f"Auto-detected primary master: {master_path.name}")
        elif to_gen_dir.is_dir():
            candidates = [
                f for f in sorted(to_gen_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            if candidates:
                master_path = candidates[0]
                log_info(f"Auto-detected master: {master_path.name}")
        elif legacy_master_dir and legacy_master_dir.is_dir():
            candidates = [
                f for f in sorted(legacy_master_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            if candidates:
                master_path = candidates[0]
                log_info(f"Auto-detected master (legacy): {master_path.name}")
        elif to_sign_dir.is_dir():
            candidates = [
                f for f in sorted(to_sign_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            if candidates:
                master_path = candidates[0]
                log_info(f"Auto-detected master in to_sign/: {master_path.name}")

    # Auto-organize project canvas files (.xcf, .psd, .kra, .blend, .ai) into raw/
    raw_dest_dir.mkdir(parents=True, exist_ok=True)
    for search_dir in (to_gen_dir, to_sign_dir):
        if search_dir.is_dir():
            for f in sorted(search_dir.iterdir()):
                if (
                    f.is_file()
                    and not f.name.startswith(".")
                    and f.suffix.lower() in (".xcf", ".psd", ".kra", ".blend", ".ai")
                ):
                    target_canvas = raw_dest_dir / f.name
                    if target_canvas.resolve() != f.resolve():
                        log_info(f"Organizing project canvas '{f.name}' -> {raw_dest_dir.name}/")
                        if target_canvas.is_file():
                            target_canvas.unlink()
                        shutil.move(f, target_canvas)
                        ots_f = f.with_name(f"{f.name}.ots")
                        if ots_f.is_file():
                            target_canvas_ots = raw_dest_dir / ots_f.name
                            if target_canvas_ots.is_file():
                                target_canvas_ots.unlink()
                            shutil.move(ots_f, target_canvas_ots)

    # Auto-detect existing raw project canvas if not provided
    if raw_path is None:
        if raw_dest_dir.is_dir():
            raw_candidates = [
                f for f in sorted(raw_dest_dir.iterdir())
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
            ]
            canvas_cands = [f for f in raw_candidates if f.suffix.lower() in (".xcf", ".psd", ".kra", ".svg", ".ai", ".blend")]
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

    # Resolve separated proofs paths
    target_proofs_dir = None
    if resolved_proofs_dir:
        target_proofs_dir = resolved_proofs_dir / name / version
        migrate_proofs_directory(target_proofs_dir)

        (target_proofs_dir / "raw").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "to_sign" / "to_generate").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "to_sign").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "generated").mkdir(parents=True, exist_ok=True)
        (target_proofs_dir / "signed").mkdir(parents=True, exist_ok=True)

    # Load or resolve scale manifest (targets, aspect ratio, favicon)
    manifest_cli_str = sizes_cli or (",".join(str(s) for s in sizes) if sizes else None)
    manifest = load_or_resolve_manifest(
        target_dir=target_dir,
        name=name,
        version=version,
        master_path=master_path,
        sizes_cli=manifest_cli_str,
    )
    if resize_mode:
        manifest["resize_mode"] = resize_mode
    if pad_color:
        manifest["pad_color"] = pad_color

    eff_resize_mode = manifest.get("resize_mode", "pad")
    eff_pad_color_str = manifest.get("pad_color", "transparent")
    eff_pad_color = parse_pad_color(eff_pad_color_str)

    targets = manifest.get("targets", [])
    formats = manifest.get("formats", ["webp", "png"])
    aspect_ratio = manifest.get("aspect_ratio", "auto")

    log_head(f"Building Media Asset: {name} ({version})")
    log_info(f"Target Directory: {target_dir}")
    if target_proofs_dir:
        log_info(f"Proofs Archive:   {target_proofs_dir}")
    log_info(f"Master Image:     {master_path}")
    if len(sources) > 1:
        extra_src_str = ", ".join(f"{s['name']} ({s['width']}x{s['height']})" for s in sources if s["path"] != master_path)
        if extra_src_str:
            log_info(f"Extra Sources:    {extra_src_str}")
    if raw_path:
        log_info(f"Raw Project:      {raw_path}")
    log_info(f"Fitting Policy:   {eff_resize_mode} (pad color: {eff_pad_color_str})")
    log_info(f"Aspect Ratio:     {aspect_ratio} ({len(targets)} targets: {', '.join(t.get('label', '') for t in targets)})")

    # 1. Pre-flight Audit if target directory exists
    if target_dir.is_dir():
        err_count, violations = run_audit(target_dir, target_proofs_dir)
        blocking_violations = [
            v for v in violations
            if v["severity"] == "CRITICAL"
            or (v["severity"] == "ERROR" and not any(part in v["path"] for part in ("generated", "dist", "03_dist")))
        ]
        if blocking_violations and not force:
            print_audit_report(name, version, violations)
            log_err(
                f"Build aborted due to {len(blocking_violations)} integrity violation(s). "
                f"Fix them or pass --force to overwrite."
            )
            sys.exit(1)

    raw_dest_dir.mkdir(parents=True, exist_ok=True)
    to_sign_dir.mkdir(parents=True, exist_ok=True)
    to_gen_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)
    signed_dir.mkdir(parents=True, exist_ok=True)

    # 2. Stage 1: Preserve and Anchor Raw Project Canvases (raw/)
    if raw_path and raw_path.parent.resolve() != raw_dest_dir.resolve():
        dest_raw = raw_dest_dir / raw_path.name
        if dest_raw.resolve() != raw_path.resolve():
            if dest_raw.is_file():
                dest_raw.unlink()
            shutil.copyfile(raw_path, dest_raw)
        raw_path = dest_raw

    if raw_dest_dir.is_dir():
        raw_files = [
            f for f in sorted(raw_dest_dir.iterdir())
            if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
        ]
        for rf in raw_files:
            rf.chmod(0o444)

        if not no_stamp and raw_files:
            raw_to_stamp: list[Path] = []
            for rf in raw_files:
                final_ots = (
                    (target_proofs_dir / "raw" / f"{rf.name}.ots")
                    if target_proofs_dir
                    else rf.with_name(f"{rf.name}.ots")
                )
                if not final_ots.is_file() or force:
                    raw_to_stamp.append(rf)

            if raw_to_stamp:
                log_info(f"Anchoring raw canvas ({len(raw_to_stamp)} file(s)) in Bitcoin blockchain...")
                stamp_media_files(raw_to_stamp, force=True)
                for rf in raw_to_stamp:
                    local_ots = rf.with_name(f"{rf.name}.ots")
                    if target_proofs_dir and local_ots.is_file():
                        final_ots = target_proofs_dir / "raw" / f"{rf.name}.ots"
                        if final_ots.is_file():
                            final_ots.unlink()
                        shutil.move(local_ots, final_ots)
                        final_ots.chmod(0o444)
                    elif local_ots.is_file():
                        local_ots.chmod(0o444)

        for rf in raw_files:
            log_ok(f"Raw canvas secured: {rf.name} (0444)")

    # 3. Stage 2: Stage Master in to_sign/to_generate/ & Anchor to_sign input files with OTS
    dest_master = master_path
    if master_path.parent.resolve() != to_gen_dir.resolve() and (
        legacy_master_dir is None or master_path.parent.resolve() != legacy_master_dir.resolve()
    ):
        dest_master = to_gen_dir / master_path.name
        if dest_master.resolve() != master_path.resolve():
            if dest_master.is_file():
                dest_master.unlink()
            shutil.copyfile(master_path, dest_master)
    dest_master.chmod(0o444)
    log_ok(f"Master image staged: {dest_master.name} (0444)")

    # Ensure all extra discovered sources are staged into to_gen_dir
    for s in sources:
        if s["path"].parent.resolve() != to_gen_dir.resolve() and (
            legacy_master_dir is None or s["path"].parent.resolve() != legacy_master_dir.resolve()
        ):
            dst_s = to_gen_dir / s["path"].name
            if dst_s.resolve() != s["path"].resolve():
                if dst_s.is_file():
                    dst_s.unlink()
                shutil.copyfile(s["path"], dst_s)
            dst_s.chmod(0o444)
            s["path"] = dst_s
        elif s["path"].resolve() == master_path.resolve():
            s["path"] = dest_master

    # Anchor raw master and extra input files in to_sign/ with OTS before C2PA modifications
    if not no_stamp:
        to_sign_to_stamp: list[tuple[Path, Path]] = []
        if to_gen_dir.is_dir():
            for f in sorted(to_gen_dir.iterdir()):
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith("."):
                    f.chmod(0o444)
                    final_ots = (
                        (target_proofs_dir / "to_sign" / "to_generate" / f"{f.name}.ots")
                        if target_proofs_dir
                        else f.with_name(f"{f.name}.ots")
                    )
                    if not final_ots.is_file() or force:
                        to_sign_to_stamp.append((f, final_ots))

        if to_sign_dir.is_dir():
            for f in sorted(to_sign_dir.iterdir()):
                if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith("."):
                    f.chmod(0o444)
                    final_ots = (
                        (target_proofs_dir / "to_sign" / f"{f.name}.ots")
                        if target_proofs_dir
                        else f.with_name(f"{f.name}.ots")
                    )
                    if not final_ots.is_file() or force:
                        to_sign_to_stamp.append((f, final_ots))

        if to_sign_to_stamp:
            files_list = [f for f, _ in to_sign_to_stamp]
            log_info(f"Anchoring raw master/input ({len(files_list)} file(s)) in Bitcoin blockchain...")
            stamp_media_files(files_list, force=True)
            for f, final_ots in to_sign_to_stamp:
                local_ots = f.with_name(f"{f.name}.ots")
                if target_proofs_dir and local_ots.is_file():
                    final_ots.parent.mkdir(parents=True, exist_ok=True)
                    if final_ots.is_file():
                        final_ots.unlink()
                    shutil.move(local_ots, final_ots)
                    final_ots.chmod(0o444)
                elif local_ots.is_file():
                    local_ots.chmod(0o444)
            log_ok(f"Anchored all {len(files_list)} to_sign input file(s) in Bitcoin blockchain (OpenTimestamps)")

    # 4. Stage 3: Render Multi-Scale Distribution (generated/) and Batch-Stamp with OTS
    log_info(f"Rendering distribution assets ({len(targets)} targets) into {gen_dir.name}/...")
    generated_count = 0
    try:
        # Multi-layer favicon.ico container
        gen_favicon = bool(manifest.get("generate_favicon", True))
        if gen_favicon:
            fav_src_name = manifest.get("favicon_source")
            fav_source = select_best_source(sources, 256, 256, explicit_name=fav_src_name)
            fav_mode = manifest.get("favicon_resize_mode", eff_resize_mode)
            fav_pad_color = parse_pad_color(manifest.get("favicon_pad_color", eff_pad_color_str))

            ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
            ico_path = gen_dir / "favicon.ico"
            if ico_path.is_file():
                ico_path.unlink()

            ico_layers = [
                render_source_to_canvas(fav_source, iw, ih, resize_mode=fav_mode, pad_color=fav_pad_color)
                for iw, ih in ico_sizes
            ]
            ico_layers[-1].save(ico_path, format="ICO", sizes=ico_sizes, append_images=ico_layers[:-1])
            ico_path.chmod(0o444)
            generated_count += 1
            log_ok(
                f"Rendered multi-resolution favicon.ico (16..256) from {fav_source['name']} (mode: {fav_mode})"
            )

        # Render targets directly using best matching source
        for t in targets:
            tw, th = t["width"], t["height"]
            lbl = t.get("label") or (str(tw) if tw == th else f"{tw}x{th}")
            t_mode = t.get("resize_mode", eff_resize_mode)
            t_pad = parse_pad_color(t.get("pad_color", eff_pad_color_str))
            t_src_name = t.get("source")

            best_src = select_best_source(sources, tw, th, explicit_name=t_src_name)

            if best_src.get("is_video"):
                # Video source: render scaled video formats via ffmpeg
                if "mp4" in formats:
                    out_mp4 = gen_dir / f"{name}_{lbl}.mp4"
                    render_video_to_target(best_src["path"], out_mp4, tw, th, resize_mode=t_mode, pad_color=t_pad)
                    out_mp4.chmod(0o444)
                    generated_count += 1
                if "webm" in formats:
                    out_webm = gen_dir / f"{name}_{lbl}.webm"
                    render_video_to_target(best_src["path"], out_webm, tw, th, resize_mode=t_mode, pad_color=t_pad)
                    out_webm.chmod(0o444)
                    generated_count += 1
                # Also generate raster poster/previews if requested
                if "webp" in formats:
                    res_img = render_source_to_canvas(best_src, tw, th, resize_mode=t_mode, pad_color=t_pad)
                    out_webp = gen_dir / f"{name}_{lbl}.webp"
                    if out_webp.is_file():
                        out_webp.unlink()
                    res_img.save(out_webp, format="WEBP", quality=90, method=6)
                    out_webp.chmod(0o444)
                    generated_count += 1
                if "png" in formats:
                    res_img = render_source_to_canvas(best_src, tw, th, resize_mode=t_mode, pad_color=t_pad)
                    out_png = gen_dir / f"{name}_{lbl}.png"
                    if out_png.is_file():
                        out_png.unlink()
                    res_img.save(out_png, format="PNG", optimize=True)
                    out_png.chmod(0o444)
                    generated_count += 1

            elif best_src.get("is_animated"):
                # Animated source (GIF or animated WebP): render all frames
                with Image.open(best_src["path"]) as anim_im:
                    durations = []
                    disposals = []
                    loop = anim_im.info.get("loop", 0)
                    canvas_frames = []
                    for f in ImageSequence.Iterator(anim_im):
                        durations.append(f.info.get("duration", 100))
                        disposals.append(f.info.get("disposal", 2))
                        canvas_frames.append(render_pil_to_canvas(f.convert("RGBA"), tw, th, resize_mode=t_mode, pad_color=t_pad))

                if "gif" in formats or best_src["suffix"] == ".gif":
                    out_gif = gen_dir / f"{name}_{lbl}.gif"
                    if out_gif.is_file():
                        out_gif.unlink()
                    pal_frames = []
                    for cf in canvas_frames:
                        has_alpha = cf.getchannel("A").getextrema() != (255, 255)
                        if has_alpha:
                            pal = cf.quantize(colors=255, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
                        else:
                            pal = cf.convert("RGB").quantize(colors=256, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
                        pal_frames.append(pal)
                    pal_frames[0].save(out_gif, format="GIF", save_all=True, append_images=pal_frames[1:], duration=durations, loop=loop, disposal=disposals)
                    out_gif.chmod(0o444)
                    generated_count += 1

                if "webp" in formats:
                    out_webp = gen_dir / f"{name}_{lbl}.webp"
                    if out_webp.is_file():
                        out_webp.unlink()
                    canvas_frames[0].save(out_webp, format="WEBP", save_all=True, append_images=canvas_frames[1:], duration=durations, loop=loop, quality=90)
                    out_webp.chmod(0o444)
                    generated_count += 1

                if "png" in formats:
                    out_png = gen_dir / f"{name}_{lbl}.png"
                    if out_png.is_file():
                        out_png.unlink()
                    canvas_frames[0].save(out_png, format="PNG", optimize=True)
                    out_png.chmod(0o444)
                    generated_count += 1

            else:
                # Still raster or vector source
                res_img = render_source_to_canvas(best_src, tw, th, resize_mode=t_mode, pad_color=t_pad)
                if "webp" in formats:
                    out_webp = gen_dir / f"{name}_{lbl}.webp"
                    if out_webp.is_file():
                        out_webp.unlink()
                    res_img.save(out_webp, format="WEBP", quality=90, method=6)
                    out_webp.chmod(0o444)
                    generated_count += 1
                if "png" in formats:
                    out_png = gen_dir / f"{name}_{lbl}.png"
                    if out_png.is_file():
                        out_png.unlink()
                    res_img.save(out_png, format="PNG", optimize=True)
                    out_png.chmod(0o444)
                    generated_count += 1
                if "gif" in formats:
                    out_gif = gen_dir / f"{name}_{lbl}.gif"
                    if out_gif.is_file():
                        out_gif.unlink()
                    res_img.save(out_gif, format="GIF")
                    out_gif.chmod(0o444)
                    generated_count += 1

        # Export distribution video assets if master is video
        video_sources = [s for s in sources if s.get("is_video")]
        for v_src in video_sources:
            if v_src["suffix"].lstrip(".") in formats:
                out_v = gen_dir / f"{name}{v_src['suffix']}"
                if out_v.resolve() != v_src["path"].resolve():
                    if out_v.is_file():
                        out_v.unlink()
                    shutil.copyfile(v_src["path"], out_v)
                out_v.chmod(0o444)
                generated_count += 1
                log_ok(f"Exported distribution video asset: {out_v.name}")

        # Export distribution vector assets
        vector_sources = [s for s in sources if s["is_vector"]]
        if "svg" in formats or vector_sources:
            for v_src in vector_sources:
                if v_src["path"].name == dest_master.name or len(vector_sources) == 1:
                    out_svg = gen_dir / f"{name}.svg"
                else:
                    out_svg = gen_dir / f"{name}_{v_src['stem']}.svg"
                if out_svg.resolve() != v_src["path"].resolve():
                    if out_svg.is_file():
                        out_svg.unlink()
                    shutil.copyfile(v_src["path"], out_svg)
                out_svg.chmod(0o444)
                generated_count += 1
                log_ok(f"Exported distribution vector asset: {out_svg.name}")

    except Exception as e:
        log_err(f"Failed during generated rendering: {e}")
        sys.exit(1)

    log_ok(f"Generated {generated_count} distribution files in {gen_dir.name}/")

    if not no_stamp:
        gen_files = [
            f for f in sorted(gen_dir.iterdir())
            if f.is_file() and not f.name.endswith(".ots") and not f.name.startswith(".")
        ]
        gen_to_stamp = []
        for gf in gen_files:
            gf.chmod(0o444)
            final_ots = (
                (target_proofs_dir / "generated" / f"{gf.name}.ots")
                if target_proofs_dir
                else gf.with_name(f"{gf.name}.ots")
            )
            if not final_ots.is_file() or force:
                gen_to_stamp.append(gf)

        if gen_to_stamp:
            stamp_media_files(gen_to_stamp, force=True)
            for gf in gen_to_stamp:
                local_ots = gf.with_name(f"{gf.name}.ots")
                if target_proofs_dir and local_ots.is_file():
                    final_ots = target_proofs_dir / "generated" / f"{gf.name}.ots"
                    if final_ots.is_file():
                        final_ots.unlink()
                    shutil.move(local_ots, final_ots)
                    final_ots.chmod(0o444)
                elif local_ots.is_file():
                    local_ots.chmod(0o444)
            log_ok(f"Anchored all {len(gen_to_stamp)} generated files in Bitcoin blockchain (OpenTimestamps)")

    # 5. Stage 4: Sign Master Clone and Extra Images into signed/ (C2PA + DWT + OTS)
    items_to_sign: list[tuple[Path, Path, str]] = []

    # 1. Master clone (full resolution clone from to_generate)
    items_to_sign.append((dest_master, signed_dir / dest_master.name, f"Master clone ({dest_master.name})"))

    # 2. Additional generator files in to_generate/ (if any)
    if to_gen_dir.is_dir():
        for f in sorted(to_gen_dir.iterdir()):
            if (
                f.is_file()
                and not f.name.startswith(".")
                and not f.name.endswith(".ots")
                and f.suffix.lower() in MEDIA_MASTER_EXTENSIONS
                and f.resolve() != dest_master.resolve()
            ):
                items_to_sign.append((f, signed_dir / f.name, f"Generator master ({f.name})"))

    # 3. Additional files in to_sign/ (excluding subdirectories)
    if to_sign_dir.is_dir():
        for f in sorted(to_sign_dir.iterdir()):
            if (
                f.is_file()
                and not f.name.startswith(".")
                and not f.name.endswith(".ots")
                and f.suffix.lower() in MEDIA_MASTER_EXTENSIONS
            ):
                target_dst = signed_dir / f.name
                if any(dst == target_dst for _, dst, _ in items_to_sign):
                    log_warn(f"Filename collision for {f.name} in to_sign/, skipping duplicate.")
                    continue
                items_to_sign.append((f, target_dst, f"Additional asset ({f.name})"))

    # 4. Optional showcase scale renders from manifest if configured (legacy compatibility)
    signed_config = manifest.get("signed")
    if isinstance(signed_config, dict) and signed_config.get("enabled") and signed_config.get("targets"):
        for st in signed_config["targets"]:
            lbl = st.get("label", "1024")
            tw = st["width"]
            th = st["height"]
            target_dst = signed_dir / f"{name}_{lbl}_signed.png"
            if not any(dst == target_dst for _, dst, _ in items_to_sign):
                showcase_tmp = target_dir / f".tmp_showcase_{name}_{lbl}.png"
                try:
                    best_src = select_best_source(sources, tw, th, explicit_name=st.get("source"))
                    st_mode = st.get("resize_mode", eff_resize_mode)
                    st_pad = parse_pad_color(st.get("pad_color", eff_pad_color_str))
                    showcase_img = render_source_to_canvas(best_src, tw, th, resize_mode=st_mode, pad_color=st_pad)
                    if showcase_tmp.is_file():
                        showcase_tmp.unlink()
                    showcase_img.save(showcase_tmp, format="PNG")
                    items_to_sign.append((showcase_tmp, target_dst, f"Showcase release {tw}x{th} ({target_dst.name})"))
                except Exception as e:
                    log_warn(f"Could not render legacy showcase target {lbl}: {e}")

    items_to_sign_pending: list[tuple[Path, Path, str, bool]] = []
    for src_file, dst_file, desc in items_to_sign:
        is_tmp = src_file.name.startswith(".tmp_")

        # Skip already-signed and anchored releases if up to date and not forced
        if dst_file.is_file() and not force:
            local_ots = dst_file.with_name(f"{dst_file.name}.ots")
            remote_ots = (
                (target_proofs_dir / "signed" / f"{dst_file.name}.ots")
                if target_proofs_dir
                else local_ots
            )
            if (remote_ots.is_file() or no_stamp) and (
                is_tmp or src_file.stat().st_mtime <= dst_file.stat().st_mtime
            ):
                log_ok(f"Signed release already up to date: {dst_file.name} (use --force to re-sign)")
                if is_tmp:
                    src_file.unlink(missing_ok=True)
                continue
        items_to_sign_pending.append((src_file, dst_file, desc, is_tmp))

    # Pre-authorize single C2PA session signer and derive watermark secret once for entire build
    batch_signer: c2pa.Signer | None = None
    batch_wm_secret: str | None = None

    if not no_sign and items_to_sign_pending:
        cfg = load_config()
        manifest_meta = manifest.get("metadata") or {}
        manifest_wm = manifest.get("watermark") or {}
        manifest_author = manifest_meta.get("author") or None
        manifest_domain = manifest_meta.get("domain") or None
        manifest_license = manifest_meta.get("license") or None
        manifest_description = manifest_meta.get("description") or None
        manifest_wm_text = manifest_wm.get("text") or None

        is_agent_mode = use_agent or (cfg.get("signing_mode") == "ssh-agent" and not bw_item)

        # 1. Derive watermark permutation secret once for entire build
        if is_agent_mode:
            k_target = agent_key_name or cfg.get("ssh_key_name")
            batch_wm_secret = derive_watermark_secret_from_ssh_agent(key_name=k_target)
        elif bw_item or cfg.get("bitwarden_item"):
            target_bw = bw_item or cfg.get("bitwarden_item")
            try:
                k_bytes, _ = fetch_bitwarden_credentials(target_bw)
                batch_wm_secret = hashlib.sha256(k_bytes).hexdigest()
            except Exception:
                pass
        elif DEFAULT_KEY_PATH.is_file():
            batch_wm_secret = hashlib.sha256(DEFAULT_KEY_PATH.read_bytes()).hexdigest()

        # 2. Authorize single C2PA session signer for entire build
        if is_agent_mode:
            k_target = agent_key_name or cfg.get("ssh_key_name") or "c2pa-signer"
            log_info(f"Initializing single C2PA session signer via SSH Agent for {len(items_to_sign_pending)} asset(s)...")
            try:
                batch_signer = create_c2pa_session_signer_from_ssh_agent(
                    key_comment=k_target,
                    domain=manifest_domain or cfg.get("domain", DEFAULT_DOMAIN),
                )
                log_ok(f"Session signer active: single SSH authorization covers all {len(items_to_sign_pending)} release(s).")
            except Exception as e:
                log_warn(f"Failed to create session signer via SSH Agent: {e}. Falling back to per-file signing.")
        elif bw_item or cfg.get("bitwarden_item"):
            target_bw = bw_item or cfg.get("bitwarden_item")
            try:
                k_bytes, c_bytes = fetch_bitwarden_credentials(target_bw)
                signer_info = c2pa.C2paSignerInfo(
                    alg=c2pa.C2paSigningAlg.ES256,
                    sign_cert=c_bytes,
                    private_key=k_bytes,
                    ta_url=None,
                )
                batch_signer = c2pa.Signer.from_info(signer_info)
            except Exception as e:
                log_warn(f"Failed to load Bitwarden credentials: {e}")
        elif DEFAULT_KEY_PATH.is_file() and DEFAULT_CERT_PATH.is_file():
            try:
                k_bytes = DEFAULT_KEY_PATH.read_bytes()
                c_bytes = DEFAULT_CERT_PATH.read_bytes()
                signer_info = c2pa.C2paSignerInfo(
                    alg=c2pa.C2paSigningAlg.ES256,
                    sign_cert=c_bytes,
                    private_key=k_bytes,
                    ta_url=None,
                )
                batch_signer = c2pa.Signer.from_info(signer_info)
            except Exception as e:
                log_warn(f"Failed to load local signing credentials: {e}")

    for src_file, dst_file, desc, is_tmp in items_to_sign_pending:
        if not no_sign:
            log_info(f"Cryptographically signing {desc} -> {dst_file.name}...")
            process_signing(
                input_path=src_file,
                output_path=dst_file,
                author=manifest_author,
                domain=manifest_domain,
                license_text=manifest_license,
                description=manifest_description,
                watermark_payload=manifest_wm_text,
                stamp=(not no_stamp),
                bw_item=bw_item,
                use_agent=use_agent,
                agent_key_name=agent_key_name,
                signer=batch_signer,
                secret=batch_wm_secret,
            )
            if is_tmp:
                src_file.unlink(missing_ok=True)
            local_ots = dst_file.with_name(f"{dst_file.name}.ots")
            if target_proofs_dir and local_ots.is_file():
                final_ots = target_proofs_dir / "signed" / f"{dst_file.name}.ots"
                if final_ots.is_file():
                    final_ots.unlink()
                shutil.move(local_ots, final_ots)
                final_ots.chmod(0o444)
            elif local_ots.is_file():
                local_ots.chmod(0o444)
            dst_file.chmod(0o444)
            log_ok(f"Signed release ready: {dst_file.name} (0444)")
        else:
            if src_file.resolve() != dst_file.resolve():
                if dst_file.is_file():
                    dst_file.unlink()
                shutil.copyfile(src_file, dst_file)
            if is_tmp:
                src_file.unlink(missing_ok=True)
            dst_file.chmod(0o444)
            if not no_stamp:
                local_ots = dst_file.with_name(f"{dst_file.name}.ots")
                final_ots = (
                    (target_proofs_dir / "signed" / f"{dst_file.name}.ots")
                    if target_proofs_dir
                    else local_ots
                )
                if not final_ots.is_file() or force:
                    stamp_media_file(dst_file, force=True)
                    if target_proofs_dir and local_ots.is_file():
                        if final_ots.is_file():
                            final_ots.unlink()
                        shutil.move(local_ots, final_ots)
                        final_ots.chmod(0o444)
                    elif local_ots.is_file():
                        local_ots.chmod(0o444)
            log_ok(f"Release saved without signing: {dst_file.name} (0444)")

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
    print(f"  {C_BOLD}Raw:{C_RESET}        {raw_dest_dir}")
    print(f"  {C_BOLD}To Sign:{C_RESET}    {to_sign_dir}")
    print(f"  {C_BOLD}Generated:{C_RESET}  {gen_dir}")
    print(f"  {C_BOLD}Signed:{C_RESET}     {signed_dir}")
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


def execute_migrate(
    base_dir: Path,
    proofs_base: Path | None = None,
    name: str | None = None,
    version: str | None = None,
) -> None:
    """Migrates asset directories and proofs archives to clean 1:1 mirror structure."""
    log_head("Migrating Asset & Proofs Library to 1:1 Mirror Layout")

    def _migrate_version(v_dir: Path, p_dir: Path | None):
        a_slug = v_dir.parent.name
        v_tag = v_dir.name
        print(f"  {C_BOLD}Checking:{C_RESET} {a_slug}/{v_tag}")

        # 1. Project canvases (.xcf, .psd, etc.) -> raw/
        raw_dest = v_dir / "raw"
        raw_dest.mkdir(parents=True, exist_ok=True)
        for s_dir in (
            v_dir / "source" / "raw",
            v_dir / "01_source" / "raw",
            v_dir / "to_sign" / "to_generate",
            v_dir / "to_sign",
            v_dir / "source",
            v_dir / "01_source",
            v_dir,
        ):
            if s_dir.is_dir():
                for f in sorted(s_dir.iterdir()):
                    if f.is_file() and not f.name.startswith(".") and f.suffix.lower() in (".xcf", ".psd", ".kra", ".blend", ".ai"):
                        target_canvas = raw_dest / f.name
                        if target_canvas.resolve() != f.resolve():
                            if target_canvas.is_file():
                                target_canvas.unlink()
                            shutil.move(f, target_canvas)
                            log_ok(f"    Organized canvas: {f.name} -> raw/")
                            ots_f = f.with_name(f"{f.name}.ots")
                            if ots_f.is_file():
                                target_ots = raw_dest / ots_f.name
                                if target_ots.is_file():
                                    target_ots.unlink()
                                shutil.move(ots_f, target_ots)

        # 2. Master image -> to_sign/to_generate/
        to_gen = v_dir / "to_sign" / "to_generate"
        for old_m in (v_dir / "source" / "master", v_dir / "01_source" / "master"):
            if old_m.is_dir():
                to_gen.mkdir(parents=True, exist_ok=True)
                for f in sorted(old_m.iterdir()):
                    if f.is_file():
                        tgt = to_gen / f.name
                        if tgt.is_file():
                            tgt.unlink()
                        shutil.move(f, tgt)
                        log_ok(f"    Moved master: {f.name} -> to_sign/to_generate/")
                        ots_f = f.with_name(f"{f.name}.ots")
                        if ots_f.is_file():
                            target_ots = to_gen / ots_f.name
                            if target_ots.is_file():
                                target_ots.unlink()
                            shutil.move(ots_f, target_ots)

        # 3. Generated assets -> generated/
        gen_dir = v_dir / "generated"
        for old_dist in (v_dir / "dist", v_dir / "03_dist"):
            if old_dist.is_dir():
                gen_dir.mkdir(parents=True, exist_ok=True)
                for f in sorted(old_dist.iterdir()):
                    if f.is_file():
                        tgt = gen_dir / f.name
                        if tgt.is_file():
                            tgt.unlink()
                        shutil.move(f, tgt)
                        log_ok(f"    Moved generated: {f.name} -> generated/")
                        ots_f = f.with_name(f"{f.name}.ots")
                        if ots_f.is_file():
                            target_ots = gen_dir / ots_f.name
                            if target_ots.is_file():
                                target_ots.unlink()
                            shutil.move(ots_f, target_ots)

        # 4. Signed releases -> signed/
        signed_dir = v_dir / "signed"
        for old_signed in (v_dir / "02_signed",):
            if old_signed.is_dir():
                signed_dir.mkdir(parents=True, exist_ok=True)
                for f in sorted(old_signed.iterdir()):
                    if f.is_file():
                        tgt = signed_dir / f.name
                        if tgt.is_file():
                            tgt.unlink()
                        shutil.move(f, tgt)
                        log_ok(f"    Moved signed: {f.name} -> signed/")
                        ots_f = f.with_name(f"{f.name}.ots")
                        if ots_f.is_file():
                            target_ots = signed_dir / ots_f.name
                            if target_ots.is_file():
                                target_ots.unlink()
                            shutil.move(ots_f, target_ots)

        # Clean up empty legacy directories in asset tree
        for old_dir in (
            v_dir / "source" / "raw",
            v_dir / "01_source" / "raw",
            v_dir / "source" / "master",
            v_dir / "01_source" / "master",
            v_dir / "source",
            v_dir / "01_source",
            v_dir / "dist",
            v_dir / "03_dist",
            v_dir / "02_signed",
        ):
            if old_dir.is_dir():
                try:
                    old_dir.rmdir()
                except OSError:
                    pass

        # 5. Proofs archive migration
        if p_dir and p_dir.is_dir():
            count = migrate_proofs_directory(p_dir)
            if count > 0:
                log_ok(f"    Migrated {count} proof(s) in Icons-Proofs -> 1:1 mirror layout.")

    if name and version:
        v_dir = base_dir / name / version
        p_dir = (proofs_base / name / version) if proofs_base else None
        if not v_dir.is_dir() and not (p_dir and p_dir.is_dir()):
            log_err(f"Asset version not found: {name} ({version})")
            return
        _migrate_version(v_dir, p_dir)
    elif name:
        a_dir = base_dir / name
        if not a_dir.is_dir():
            log_err(f"Asset directory not found: {a_dir}")
            return
        for v_dir in sorted(a_dir.iterdir()):
            if v_dir.is_dir() and not v_dir.is_symlink():
                p_dir = (proofs_base / name / v_dir.name) if proofs_base else None
                _migrate_version(v_dir, p_dir)
    else:
        if not base_dir.is_dir():
            log_warn(f"Icons directory does not exist: {base_dir}")
            return
        for a_dir in sorted(base_dir.iterdir()):
            if a_dir.is_dir() and not a_dir.name.startswith("."):
                for v_dir in sorted(a_dir.iterdir()):
                    if v_dir.is_dir() and not v_dir.is_symlink():
                        p_dir = (proofs_base / a_dir.name / v_dir.name) if proofs_base else None
                        _migrate_version(v_dir, p_dir)

    log_ok("Migration complete! Run 'media audit' to verify integrity.\n")


# ------------------------------------------------------------------------------
# Keys & Vault Subcommands
# ------------------------------------------------------------------------------
def keys_show(bw_item: str | None = None) -> None:
    """Displays active signing credentials information."""
    log_head("C2PA Signing Credentials Status")
    cfg = load_config()
    mode = cfg.get("signing_mode")
    target_bw = bw_item or cfg.get("bitwarden_item") or os.environ.get("C2PA_BW_ITEM")

    if bw_item:
        mode = "bitwarden"
    elif not mode:
        mode = "bitwarden" if target_bw else "local"

    if mode == "ssh-agent":
        key_name = cfg.get("ssh_key_name", "c2pa-signer")
        sock = find_ssh_agent_socket()
        print(f"  {C_BOLD}Signing Mode:{C_RESET}     SSH Agent (Zero-Knowledge / RAM-Safe)")
        print(f"  {C_BOLD}Security Enclave:{C_RESET} Bitwarden Desktop (GUI Prompt [Authorize])")
        print(f"  {C_BOLD}Config File:{C_RESET}      {DEFAULT_CONFIG_FILE}")
        print(f"  {C_BOLD}Agent Socket:{C_RESET}     {sock if sock else C_RED + 'Not found' + C_RESET}")
        print(f"  {C_BOLD}SSH Key Name:{C_RESET}     {key_name}")

        if sock and sock.exists():
            try:
                keys = ssh_agent_list_keys(sock)
                matched = [comm for _, _, comm in keys if key_name.lower() in (comm or "").lower()]
                if matched:
                    print(f"  {C_BOLD}Agent Status:{C_RESET}     {C_GREEN}Active (Key '{matched[0]}' loaded){C_RESET}")
                else:
                    print(f"  {C_BOLD}Agent Status:{C_RESET}     {C_YELLOW}Connected, but key '{key_name}' not listed{C_RESET}")
            except Exception as e:
                print(f"  {C_BOLD}Agent Status:{C_RESET}     {C_RED}Communication error: {e}{C_RESET}")
        else:
            print(f"  {C_BOLD}Agent Status:{C_RESET}     {C_RED}Agent socket unreachable{C_RESET}")

        print(f"  {C_BOLD}Cert File:{C_RESET}        {DEFAULT_CERT_PATH} ({'Found' if DEFAULT_CERT_PATH.is_file() else 'Missing'})")
        wm_sec = cfg.get("watermark_secret")
        if wm_sec:
            print(f"  {C_BOLD}Watermark Key:{C_RESET}    {C_YELLOW}Explicitly configured in c2pa.json{C_RESET}")
        else:
            print(f"  {C_BOLD}Watermark Key:{C_RESET}    {C_GREEN}Derived on-the-fly via SSH Agent (Zero-Disk / Ed25519){C_RESET}")
        print(f"  {C_BOLD}Private Key RAM:{C_RESET}  {C_GREEN}0 bytes (Never leaves Bitwarden process){C_RESET}")
        print(f"  {C_BOLD}Private Key Disk:{C_RESET} {C_GREEN}0 bytes (Never written to filesystem){C_RESET}\n")
        return

    if mode == "bitwarden" and target_bw:
        print(f"  {C_BOLD}Source:{C_RESET}           Bitwarden Vault (In-Memory CLI)")
        print(f"  {C_BOLD}Config File:{C_RESET}       {DEFAULT_CONFIG_FILE}")
        print(f"  {C_BOLD}Item:{C_RESET}              {target_bw}")
        try:
            k_bytes, c_bytes = fetch_bitwarden_credentials(target_bw)
            print(f"  {C_BOLD}Key Status:{C_RESET}       {C_GREEN}Available in RAM ({len(k_bytes)} bytes){C_RESET}")
            print(f"  {C_BOLD}Cert Status:{C_RESET}      {C_GREEN}Available in RAM ({len(c_bytes)} bytes){C_RESET}")
        except Exception as e:
            print(f"  {C_BOLD}Status:{C_RESET}           {C_RED}Failed to load: {e}{C_RESET}")
        print()
        return

    env_creds = load_env_credentials()
    if env_creds:
        print(f"  {C_BOLD}Source:{C_RESET}           Environment Variables (C2PA_PRIVATE_KEY, C2PA_CERT)")
        print(f"  {C_BOLD}Status:{C_RESET}           {C_GREEN}Active in environment{C_RESET}\n")
        return

    print(f"  {C_BOLD}Source:{C_RESET}           Local Disk Storage")
    print(f"  {C_BOLD}Config File:{C_RESET}       {DEFAULT_CONFIG_FILE}")
    print(f"  {C_BOLD}Key File:{C_RESET}         {DEFAULT_KEY_PATH} ({'Found' if DEFAULT_KEY_PATH.is_file() else 'Missing'})")
    print(f"  {C_BOLD}Cert File:{C_RESET}        {DEFAULT_CERT_PATH} ({'Found' if DEFAULT_CERT_PATH.is_file() else 'Missing'})")
    print(f"\n  {C_CYAN}To use Bitwarden SSH Agent (Zero keys in RAM / disk):{C_RESET}")
    print(f"    1. Create SSH Key item 'c2pa-signer' (Ed25519 or ECDSA) in Bitwarden")
    print(f"    2. media keys gen --agent")
    print(f"    3. rm -rf {DEFAULT_KEY_DIR}\n")


def keys_export(bw_item: str | None = None) -> None:
    """Exports raw PEM key and certificate to stdout for backup or Bitwarden."""
    cfg = load_config()
    mode = cfg.get("signing_mode")
    if mode == "ssh-agent" and not bw_item:
        print(f"  {C_YELLOW}Note: Private key is stored securely in Bitwarden Desktop and cannot be exported.{C_RESET}\n")
        if DEFAULT_CERT_PATH.is_file():
            print(DEFAULT_CERT_PATH.read_bytes().decode("utf-8").strip())
        return

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


def keys_gen(
    domain: str = DEFAULT_DOMAIN,
    bw_item: str | None = None,
    out_dir: Path | None = None,
    use_agent: bool = False,
    key_name: str = "c2pa-signer",
) -> None:
    """Generates new Root CA + Leaf C2PA credentials."""
    if use_agent:
        keys_gen_ssh_agent(domain=domain, key_name=key_name)
        return

    if bw_item:
        log_head(f"Generating C2PA credentials directly in Bitwarden vault: '{bw_item}'...")
        k_bytes, c_bytes, r_bytes = generate_c2pa_credentials(domain)
        save_credentials_to_bitwarden(bw_item, k_bytes, c_bytes, domain, root_key_pem=r_bytes)
        cfg = load_config()
        cfg["signing_mode"] = "bitwarden"
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
        cfg = load_config()
        cfg["signing_mode"] = "local"
        save_config(cfg)
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
    cfg["signing_mode"] = "bitwarden"
    cfg["bitwarden_item"] = item_name
    save_config(cfg)
    log_ok(f"Configured Bitwarden item '{item_name}' as default signing source in {DEFAULT_CONFIG_FILE}.")
    print(f"\n  {C_GREEN}Credentials successfully mirrored into Bitwarden vault!{C_RESET}")
    print(f"  To enforce zero-disk-storage, you may now delete local keys:")
    print(f"    {C_BOLD}rm -rf {DEFAULT_KEY_DIR}{C_RESET}\n")


def keys_use(item_name: str | None = None) -> None:
    """Configures default signing source: 'agent' / 'ssh-agent', Bitwarden item name, or 'local'."""
    cfg = load_config()
    if not item_name or item_name.lower() in ("local", "disk", "none"):
        cfg["signing_mode"] = "local"
        cfg["bitwarden_item"] = None
        save_config(cfg)
        log_ok(f"Reverted signing credentials source to local disk in {DEFAULT_CONFIG_FILE}.")
        return

    if item_name.lower() in ("agent", "ssh-agent"):
        sock = find_ssh_agent_socket()
        if not sock:
            log_err("SSH agent socket not found.")
            log_info("Ensure Bitwarden Desktop is running with SSH agent enabled ($SSH_AUTH_SOCK).")
            sys.exit(1)
        keys = ssh_agent_list_keys(sock)
        if not keys:
            log_err(f"No SSH keys available in agent at {sock}.")
            sys.exit(1)
        cfg["signing_mode"] = "ssh-agent"
        cfg["bitwarden_item"] = None
        cfg.pop("watermark_secret", None)
        save_config(cfg)
        key_name = cfg.get("ssh_key_name", "c2pa-signer")
        log_ok(f"Configured SSH Agent ('{key_name}') as default signing source in {DEFAULT_CONFIG_FILE}.")
        return

    # Verify we can fetch the item
    fetch_bitwarden_credentials(item_name)
    cfg["signing_mode"] = "bitwarden"
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
  media build duck v2 --agent                    # Build & sign via Bitwarden SSH Agent ([Authorize] prompt)
  media build duck v2 --bw                       # Build using Bitwarden in-memory CLI keys
  media audit duck v1                            # Verify asset integrity against Bitcoin
  media audit                                    # Full integrity audit of entire library
  media migrate                                  # Migrate legacy folders to 1:1 mirror layout
  media list                                     # List managed assets and active versions
  media upgrade duck v1                          # Upgrade OTS proofs for an asset

File Attestation Examples:
  media sign photo.png                           # Sign with C2PA and invisible watermark
  media sign --agent photo.png                   # Sign via Bitwarden SSH Agent
  media sign --bw --stamp hero.png               # Sign from Bitwarden & anchor in Bitcoin
  media verify photo_signed.png                  # Inspect all 3 security layers
  media stamp document.pdf                       # Anchor arbitrary file in Bitcoin

Automation & Keys Examples:
  media timer setup /path/to/Icons-Proofs        # Start background OTS upgrade timer
  media timer status                             # Inspect timer state
  media keys show                                # Inspect active C2PA certificate & agent status
  media keys gen --agent                         # Bind C2PA certs to Bitwarden SSH Agent (0 keys in RAM/disk)
  media keys use agent                           # Set SSH Agent as default signing source
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
    p_build.add_argument("-m", "--master", type=Path, default=None, help="Cropped master PNG/WebP (auto-detected in to_sign/to_generate/)")
    p_build.add_argument("-r", "--raw", type=Path, default=None, help="Project canvas XCF/PSD/SVG (auto-detected in raw/)")
    p_build.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_build.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")
    p_build.add_argument("--sizes", type=str, default=None, help="Comma-separated generated resolutions or WxH sizes (overrides manifest.json)")
    p_build.add_argument(
        "--resize-mode",
        choices=["pad", "crop", "stretch", "fit"],
        default=None,
        help="Fitting policy when source and target aspect ratios differ (overrides manifest.json)",
    )
    p_build.add_argument(
        "--pad-color",
        type=str,
        default=None,
        help="Padding background color for 'pad' mode (e.g. 'transparent', '#ffffff')",
    )
    p_build.add_argument("--agent", "--ssh-agent", dest="agent", action="store_true", help="Sign via SSH Agent (Bitwarden Authorize prompt, zero keys in RAM)")
    p_build.add_argument("--key-name", type=str, default=None, help="SSH key comment / identifier in agent (default: 'c2pa-signer')")
    p_build.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Bitwarden item name for C2PA keys")
    p_build.add_argument("--no-sign", action="store_true", help="Skip C2PA & watermark signing (produce unsigned releases)")
    p_build.add_argument("--no-stamp", action="store_true", help="Skip OpenTimestamps Bitcoin anchoring")
    p_build.add_argument("--force", action="store_true", help="Bypass audit mismatch and re-stamp files")

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

    # Command: migrate
    p_mig = subparsers.add_parser("migrate", help="Migrate legacy library folder layout to clean 1:1 mirror structure")
    p_mig.add_argument("name", type=str, nargs="?", help="Specific asset name to migrate (optional)")
    p_mig.add_argument("version", type=str, nargs="?", help="Specific version to migrate (optional)")
    p_mig.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_mig.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: upgrade
    p_up = subparsers.add_parser("upgrade", help="Recursively upgrade OpenTimestamps proofs in Bitcoin")
    p_up.add_argument("target", type=str, nargs="?", help="Asset name, directory, or .ots proof file (optional)")
    p_up.add_argument("version", type=str, nargs="?", help="Asset version (if target is asset name)")
    p_up.add_argument("-d", "--dir", type=Path, help="Base icons library directory")
    p_up.add_argument("-p", "--proofs-dir", type=Path, help="Separated proofs library directory")

    # Command: sign
    p_sign = subparsers.add_parser("sign", help="Sign an individual media file (image, animation, or video)")
    p_sign.add_argument("input", type=Path, help="Input media file (PNG, JPG, WebP, GIF, MP4, MOV, SVG, etc.)")
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
    p_sign.add_argument("--agent", "--ssh-agent", dest="agent", action="store_true", help="Sign via SSH Agent (Bitwarden Authorize prompt, zero keys in RAM)")
    p_sign.add_argument("--key-name", type=str, default=None, help="SSH key comment / identifier in agent (default: 'c2pa-signer')")
    p_sign.add_argument("--key", type=Path, help="Custom EC private key in PEM format")
    p_sign.add_argument("--cert", type=Path, help="Custom X.509 certificate chain in PEM format")
    p_sign.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Fetch C2PA credentials strictly from Bitwarden into RAM")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Inspect and verify C2PA, watermarks & OpenTimestamps")
    p_verify.add_argument("file", type=Path, help="Target media file to inspect (image, animation, or video)")
    p_verify.add_argument("--ots", type=Path, help="Path to custom or detached .ots proof file")
    p_verify.add_argument("-s", "--secret", type=str, help="Secret passphrase for watermark extraction")
    p_verify.add_argument("--agent", "--ssh-agent", dest="agent", action="store_true", help="Derive watermark secret via SSH Agent (Bitwarden)")
    p_verify.add_argument("--key-name", type=str, default=None, help="SSH key comment / identifier in agent (default: 'c2pa-signer')")
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
    p_k_gen.add_argument("--agent", "--ssh-agent", dest="agent", action="store_true", help="Bind C2PA certificates to SSH Agent key (Bitwarden, zero keys on disk/RAM)")
    p_k_gen.add_argument("--key-name", type=str, default="c2pa-signer", help="SSH key comment / identifier in agent (default: 'c2pa-signer')")
    p_k_gen.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Store credentials directly in Bitwarden vault (0 disk files)")
    p_k_exp = sub_keys.add_parser("export", help="Export private key and cert in PEM format")
    p_k_exp.add_argument("--bw", "--bw-item", dest="bw_item", nargs="?", const=DEFAULT_BW_ITEM, type=str, help="Export from Bitwarden vault")
    p_k_push = sub_keys.add_parser("push", help="Push local keys to Bitwarden vault as Secure Note")
    p_k_push.add_argument("item", type=str, default=DEFAULT_BW_ITEM, nargs="?", help="Bitwarden item name")
    p_k_use = sub_keys.add_parser("use", help="Configure default signing source ('agent', Bitwarden item, or 'local')")
    p_k_use.add_argument("item", type=str, nargs="?", default="agent", help="Signing source ('agent', Bitwarden item name, or 'local')")

    # Shortcut handling: if first arg is an existing file, default to 'verify'
    args_list = sys.argv[1:]
    all_cmds = ("init", "build", "audit", "list", "migrate", "upgrade", "sign", "verify", "stamp", "timer", "keys", "-h", "--help")
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
        execute_build(
            name=args.name,
            version=args.version,
            master_path=args.master,
            raw_path=args.raw,
            base_dir=base_dir,
            proofs_dir=proofs_base,
            sizes_cli=args.sizes,
            resize_mode=getattr(args, "resize_mode", None),
            pad_color=getattr(args, "pad_color", None),
            bw_item=args.bw_item,
            use_agent=getattr(args, "agent", False),
            agent_key_name=getattr(args, "key_name", None),
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

    # Dispatch: migrate
    elif args.command == "migrate":
        execute_migrate(base_dir, proofs_base, name=args.name, version=args.version)

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
            use_agent=getattr(args, "agent", False),
            agent_key_name=getattr(args, "key_name", None),
        )

    # Dispatch: verify
    elif args.command == "verify":
        inspect_image(
            image_path=args.file,
            as_json=args.json,
            secret=args.secret,
            ots_path=args.ots,
            bw_item=args.bw_item,
            use_agent=getattr(args, "agent", False),
            agent_key_name=getattr(args, "key_name", None),
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
            keys_gen(
                domain=args.domain,
                bw_item=args.bw_item,
                out_dir=args.out_dir,
                use_agent=getattr(args, "agent", False),
                key_name=getattr(args, "key_name", "c2pa-signer"),
            )
        elif action == "export":
            keys_export(bw_item=args.bw_item)
        elif action == "push":
            keys_push(item_name=args.item)
        elif action == "use":
            keys_use(item_name=args.item)


if __name__ == "__main__":
    main()
