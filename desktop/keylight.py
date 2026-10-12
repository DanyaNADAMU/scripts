#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "openrgb-python",
# ]
# ///
"""
Script:      keylight.py
Category:    desktop
Description: High-performance keyboard RGB backlight profile switcher using OpenRGB SDK.
Target:      Linux workstations with OpenRGB (specifically MSI MS-1565 / Mystic Light)
Requires:    python >= 3.10, uv, openrgb
Usage:       keylight [profile | --next | --current | --list | --help]
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ==============================================================================
# PROFILES REGISTRY
# ==============================================================================
# Add, modify, or remove profiles here.
# Order in this dictionary defines cyclic switching sequence.
# ==============================================================================
PROFILES = {
    "off": {
        "desc": "Turn off all keyboard backlight",
        "modes": [
            {"name": "Off"},
        ],
        "cli_cmd": ["-d", "0", "-m", "Off"],
    },
    "night": {
        "desc": "Forest 4-zone gradient (emerald -> olive)",
        "modes": [
            {"name": "Static zone 1", "color": "#006644", "brightness": 40},
            {"name": "Static zone 2", "color": "#006626", "brightness": 40},
            {"name": "Static zone 3", "color": "#1E6610", "brightness": 40},
            {"name": "Static zone 4", "color": "#386608", "brightness": 40},
        ],
        "cli_chain": [
            ["-d", "0", "-m", "Static zone 1", "-c", "006644", "-b", "40"],
            ["-d", "0", "-m", "Static zone 2", "-c", "006626", "-b", "40"],
            ["-d", "0", "-m", "Static zone 3", "-c", "1E6610", "-b", "40"],
            ["-d", "0", "-m", "Static zone 4", "-c", "386608", "-b", "40"],
        ],
    },
    "cyan": {
        "desc": "Static vivid cyan backlight (#00FFFF)",
        "modes": [
            {"name": "Static", "color": "#00FFFF", "brightness": 40},
        ],
        "cli_cmd": ["-d", "0", "-m", "Static", "-c", "00FFFF", "-b", "40"],
    },
    "white": {
        "desc": "Static clean soft white backlight (#FFFFFF)",
        "modes": [
            {"name": "Static", "color": "#FFFFFF", "brightness": 35},
        ],
        "cli_cmd": ["-d", "0", "-m", "Static", "-c", "FFFFFF", "-b", "35"],
    },
}

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
STATE_FILE = CACHE_DIR / "keylight-current-profile"
LEGACY_STATE_FILE = CACHE_DIR / "kbd-current-profile"


def get_current_profile() -> str:
    if STATE_FILE.is_file():
        try:
            return STATE_FILE.read_text().strip()
        except OSError:
            pass
    if LEGACY_STATE_FILE.is_file():
        try:
            return LEGACY_STATE_FILE.read_text().strip()
        except OSError:
            pass
    return "off"


def save_state(name: str):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(f"{name}\n")


def get_next_profile() -> str:
    current = get_current_profile()
    profile_names = list(PROFILES.keys())
    try:
        idx = profile_names.index(current)
        next_idx = (idx + 1) % len(profile_names)
    except ValueError:
        next_idx = 0
    return profile_names[next_idx]


def show_help():
    prog = Path(sys.argv[0]).name
    print(f"Usage: {prog} [OPTIONS] [PROFILE]\n")
    print("Cyclic keyboard RGB backlight profile switcher using OpenRGB SDK.")
    print("Specially tuned for MSI Mystic Light controllers (MS-1565) using direct")
    print("socket communication for ultra-low latency (< 50ms) profile switching.\n")
    print("Arguments:")
    print("  PROFILE           Directly apply a specific profile:")
    for name, data in PROFILES.items():
        print(f"                    {name:<6} - {data['desc']}")
    print("\nOptions:")
    print("  -n, --next        Switch to the next profile in sequence (default when no argument)")
    print("  -c, --current     Print the currently active profile name")
    print("  -l, --list        List all available profiles (highlights active)")
    print("  -h, --help        Show this help message and exit\n")
    print("Hardware Context & Architecture:")
    print("  MSI MS-1565 controllers expose 4 physical zones as mutually exclusive driver modes.")
    print("  keylight communicates directly with the OpenRGB SDK server on 127.0.0.1:6742 via")
    print("  TCP socket, pushing zone updates in ~50ms. If the server is offline, it transparently")
    print("  falls back to the OpenRGB CLI.\n")
    print("Environment Variables:")
    print("  OPENRGB           Path to openrgb binary (fallback mode)")
    print(f"  XDG_CACHE_HOME    Base cache directory (state file: {STATE_FILE})")


def list_profiles():
    current = get_current_profile()
    print("Available profiles:")
    for name, data in PROFILES.items():
        desc = data["desc"]
        if name == current:
            print(f"  * {name} (active) - {desc}")
        else:
            print(f"    {name} - {desc}")


def complete_names():
    print(" ".join(PROFILES.keys()))


def complete_zsh():
    for name, data in PROFILES.items():
        print(f"{name}:{data['desc']}")


def apply_fallback_cli(name: str) -> bool:
    """Fallback to executing openrgb CLI if OpenRGB server is not running."""
    openrgb_bin = os.environ.get("OPENRGB")
    if not openrgb_bin or not os.path.isfile(openrgb_bin) or not os.access(openrgb_bin, os.X_OK):
        openrgb_bin = shutil.which("openrgb")
    if not openrgb_bin:
        local_openrgb = Path.home() / ".local/bin/openrgb"
        if local_openrgb.is_file() and os.access(local_openrgb, os.X_OK):
            openrgb_bin = str(local_openrgb)

    if not openrgb_bin:
        return False

    spec = PROFILES[name]
    try:
        if "cli_chain" in spec:
            for subcmd in spec["cli_chain"]:
                cmd = [openrgb_bin, "--loglevel", "error"] + subcmd
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        elif "cli_cmd" in spec:
            cmd = [openrgb_bin, "--loglevel", "error"] + spec["cli_cmd"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def apply_profile(name: str):
    if name not in PROFILES:
        sys.stderr.write(f"Error: Unknown profile: {name}\n")
        sys.stderr.write(f"Available profiles: {' '.join(PROFILES.keys())}\n")
        sys.exit(1)

    spec = PROFILES[name]

    # Try applying via direct OpenRGB SDK socket (super fast: 20-50ms)
    applied_via_socket = False
    try:
        from openrgb import OpenRGBClient
        from openrgb.utils import PacketType, RGBColor

        client = OpenRGBClient(protocol_version=3)
        if client.devices:
            dev = client.devices[0]
            steps = spec["modes"]
            for i, step in enumerate(steps):
                mode_name = step["name"]
                m = next((m for m in dev.modes if m.name.lower() == mode_name.lower()), None)
                if m:
                    if "color" in step and step["color"]:
                        m.colors = [RGBColor.fromHEX(step["color"])]
                    if "brightness" in step and step["brightness"] is not None:
                        m.brightness = step["brightness"]

                    data = m.pack(client.comms._protocol_version)
                    client.comms.send_header(dev.id, PacketType.RGBCONTROLLER_UPDATEMODE, len(data))
                    client.comms.send_data(data)

                    # Inter-packet pause for MSI MS-1565 micro-controller USB buffer
                    if i < len(steps) - 1:
                        time.sleep(0.05)
            applied_via_socket = True
    except Exception:
        applied_via_socket = False

    # If socket communication wasn't possible, transparently fall back to CLI
    if not applied_via_socket:
        if not apply_fallback_cli(name):
            sys.stderr.write(
                "Error: Failed to connect to OpenRGB server (127.0.0.1:6742) and OpenRGB CLI failed.\n"
                "Please ensure the server is running: systemctl --user start openrgb\n"
            )
            sys.exit(1)

    save_state(name)
    print(f"Active profile: {name}")


def main():
    if len(sys.argv) == 1:
        apply_profile(get_next_profile())
        return

    arg = sys.argv[1]
    if arg in ("-h", "--help"):
        show_help()
    elif arg in ("-l", "--list"):
        list_profiles()
    elif arg in ("-c", "--current"):
        print(get_current_profile())
    elif arg in ("-n", "--next"):
        apply_profile(get_next_profile())
    elif arg == "--complete-names":
        complete_names()
    elif arg == "--complete-zsh":
        complete_zsh()
    elif arg.startswith("-"):
        sys.stderr.write(f"Error: Unknown option '{arg}'\n")
        sys.stderr.write(f"Run '{Path(sys.argv[0]).name} --help' for usage.\n")
        sys.exit(1)
    else:
        apply_profile(arg)


if __name__ == "__main__":
    main()
