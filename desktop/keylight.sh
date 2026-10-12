#!/usr/bin/env bash
# ==============================================================================
# Script:      keylight.sh
# Category:    desktop
# Description: Cyclic keyboard RGB backlight profile switcher using OpenRGB.
# Target:      Linux workstations with OpenRGB (specifically MSI MS-1565 / Mystic Light)
# Requires:    bash, openrgb
# Usage:       keylight [profile | --next | --current | --list | --help]
# ==============================================================================

set -euo pipefail

# Resolve OpenRGB executable: respect OPENRGB env var, prefer existing local bin, fallback to PATH
OPENRGB="${OPENRGB:-$HOME/.local/bin/openrgb}"
if [[ ! -x "$OPENRGB" ]] && command -v openrgb >/dev/null 2>&1; then
    OPENRGB="$(command -v openrgb)"
fi

STATE_FILE="${XDG_CACHE_HOME:-$HOME/.cache}/keylight-current-profile"
LEGACY_STATE_FILE="${XDG_CACHE_HOME:-$HOME/.cache}/kbd-current-profile"

# Ordered list for cyclic switching
PROFILES=("off" "night" "cyan" "white")

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [PROFILE]

Cyclic keyboard RGB backlight profile switcher using OpenRGB.
Specially tuned for MSI Mystic Light controllers (MS-1565) where standard
OpenRGB profile JSON files fail due to write-only hardware and mutually
exclusive zone modes.

Arguments:
  PROFILE           Directly apply a specific profile:
                    off    - Turn off all keyboard backlight
                    night  - Forest-to-olive 4-zone gradient (emerald -> olive)
                    cyan   - Static cyan backlight (#00FFFF)
                    white  - Static white backlight (#FFFFFF)

Options:
  -n, --next        Switch to the next profile in sequence (default when no argument)
  -c, --current     Print the currently active profile name
  -l, --list        List all available profiles (highlights active)
  -h, --help        Show this help message and exit

Hardware Context & Quirks:
  MSI MS-1565 (Mystic Light) controllers have two major architectural quirks:
  1. Write-only hardware: The controller does not support hardware readback.
     OpenRGB cannot query current colors from the chip.
  2. Zones as Modes: The 4 physical keyboard zones are exposed as mutually
     exclusive modes ('Static zone 1' through 'Static zone 4') instead of OpenRGB
     zones. Standard OpenRGB .json profiles only store one active mode, making
     multi-zone profiles impossible via .json files.

  This utility resolves this by sending direct commands to the controller and
  tracking the active profile in:
  $STATE_FILE

Environment Variables:
  OPENRGB           Path to openrgb binary (default: \$HOME/.local/bin/openrgb)
  XDG_CACHE_HOME    Base cache directory (default: \$HOME/.cache)
EOF
}

check_openrgb() {
    if [[ ! -x "$OPENRGB" ]] && ! command -v "$OPENRGB" >/dev/null 2>&1; then
        >&2 echo "Error: OpenRGB binary not found at '$OPENRGB' and not in PATH."
        >&2 echo "Please install OpenRGB or set the OPENRGB environment variable."
        exit 1
    fi
}

get_current_profile() {
    local current="off"
    if [[ -f "$STATE_FILE" ]]; then
        current="$(<"$STATE_FILE")"
    elif [[ -f "$LEGACY_STATE_FILE" ]]; then
        current="$(<"$LEGACY_STATE_FILE")"
    fi
    echo "$current"
}

get_next_profile() {
    local current
    current="$(get_current_profile)"

    local next_idx=0
    for i in "${!PROFILES[@]}"; do
        if [[ "${PROFILES[$i]}" == "$current" ]]; then
            next_idx=$(( (i + 1) % ${#PROFILES[@]} ))
            break
        fi
    done
    echo "${PROFILES[$next_idx]}"
}

list_profiles() {
    local current
    current="$(get_current_profile)"
    echo "Available profiles:"
    for p in "${PROFILES[@]}"; do
        if [[ "$p" == "$current" ]]; then
            echo "  * $p (active)"
        else
            echo "    $p"
        fi
    done
}

apply_profile() {
    local name="$1"
    check_openrgb

    case "$name" in
        off)
            "$OPENRGB" --loglevel error -d 0 -m Off >/dev/null 2>&1
            ;;
        night)
            "$OPENRGB" --loglevel error -d 0 -m "Static zone 1" -c 006644 -b 40 >/dev/null 2>&1 && \
            "$OPENRGB" --loglevel error -d 0 -m "Static zone 2" -c 006626 -b 40 >/dev/null 2>&1 && \
            "$OPENRGB" --loglevel error -d 0 -m "Static zone 3" -c 1E6610 -b 40 >/dev/null 2>&1 && \
            "$OPENRGB" --loglevel error -d 0 -m "Static zone 4" -c 386608 -b 40 >/dev/null 2>&1
            ;;
        cyan)
            "$OPENRGB" --loglevel error -d 0 -m Static -c 00FFFF -b 40 >/dev/null 2>&1
            ;;
        white)
            "$OPENRGB" --loglevel error -d 0 -m Static -c FFFFFF -b 35 >/dev/null 2>&1
            ;;
        *)
            >&2 echo "Error: Unknown profile: $name"
            >&2 echo "Available profiles: ${PROFILES[*]}"
            exit 1
            ;;
    esac

    mkdir -p "$(dirname "$STATE_FILE")"
    echo "$name" > "$STATE_FILE"
    echo "Active profile: $name"
}

main() {
    if [[ $# -eq 0 ]]; then
        apply_profile "$(get_next_profile)"
        exit 0
    fi

    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            list_profiles
            exit 0
            ;;
        -c|--current)
            get_current_profile
            exit 0
            ;;
        -n|--next)
            apply_profile "$(get_next_profile)"
            exit 0
            ;;
        -*)
            >&2 echo "Error: Unknown option '$1'"
            >&2 echo "Run '$(basename "$0") --help' for usage."
            exit 1
            ;;
        *)
            apply_profile "$1"
            exit 0
            ;;
    esac
}

main "$@"
