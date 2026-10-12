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

# ==============================================================================
# PROFILES REGISTRY
# ==============================================================================
# To add, remove, or modify a profile:
#   1. Add/edit its name in PROFILES_ORDER (defines the cyclic switching order).
#   2. Add/edit its description in PROFILE_DESCS["<name>"].
#   3. Define its action in 'profile_<name>()'.
# ==============================================================================

PROFILES_ORDER=("off" "night" "cyan" "white")
declare -A PROFILE_DESCS=()

PROFILE_DESCS["off"]="Turn off all keyboard backlight"
profile_off() {
    "$OPENRGB" --loglevel error -d 0 -m Off >/dev/null 2>&1
}

PROFILE_DESCS["night"]="Forest 4-zone gradient (emerald -> olive)"
profile_night() {
    "$OPENRGB" --loglevel error -d 0 -m "Static zone 1" -c 006644 -b 40 >/dev/null 2>&1 &
    "$OPENRGB" --loglevel error -d 0 -m "Static zone 2" -c 006626 -b 40 >/dev/null 2>&1 &
    "$OPENRGB" --loglevel error -d 0 -m "Static zone 3" -c 1E6610 -b 40 >/dev/null 2>&1 &
    "$OPENRGB" --loglevel error -d 0 -m "Static zone 4" -c 386608 -b 40 >/dev/null 2>&1 &
    wait
}

PROFILE_DESCS["cyan"]="Static vivid cyan backlight (#00FFFF)"
profile_cyan() {
    "$OPENRGB" --loglevel error -d 0 -m Static -c 00FFFF -b 40 >/dev/null 2>&1
}

PROFILE_DESCS["white"]="Static clean soft white backlight (#FFFFFF)"
profile_white() {
    "$OPENRGB" --loglevel error -d 0 -m Static -c FFFFFF -b 35 >/dev/null 2>&1
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [PROFILE]

Cyclic keyboard RGB backlight profile switcher using OpenRGB.
Specially tuned for MSI Mystic Light controllers (MS-1565) where standard
OpenRGB profile JSON files fail due to write-only hardware and mutually
exclusive zone modes.

Arguments:
  PROFILE           Directly apply a specific profile:
EOF
    for p in "${PROFILES_ORDER[@]}"; do
        printf "                    %-6s - %s\n" "$p" "${PROFILE_DESCS[$p]:-$p}"
    done
    cat << EOF

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
     multi-zone profiles impossible via .json files. Also, OpenRGB CLI does not
     support multi-mode commands in a single invocation, requiring chained calls.

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
    for i in "${!PROFILES_ORDER[@]}"; do
        if [[ "${PROFILES_ORDER[$i]}" == "$current" ]]; then
            next_idx=$(( (i + 1) % ${#PROFILES_ORDER[@]} ))
            break
        fi
    done
    echo "${PROFILES_ORDER[$next_idx]}"
}

list_profiles() {
    local current
    current="$(get_current_profile)"
    echo "Available profiles:"
    for p in "${PROFILES_ORDER[@]}"; do
        local desc="${PROFILE_DESCS[$p]:-}"
        local desc_str=""
        [[ -n "$desc" ]] && desc_str=" - $desc"
        if [[ "$p" == "$current" ]]; then
            echo "  * $p (active)$desc_str"
        else
            echo "    $p$desc_str"
        fi
    done
}

complete_names() {
    echo "${PROFILES_ORDER[*]}"
}

complete_zsh() {
    for p in "${PROFILES_ORDER[@]}"; do
        echo "$p:${PROFILE_DESCS[$p]:-$p}"
    done
}

apply_profile() {
    local name="$1"
    check_openrgb

    local handler="profile_$name"
    if ! declare -f "$handler" >/dev/null; then
        >&2 echo "Error: Unknown profile: $name"
        >&2 echo "Available profiles: ${PROFILES_ORDER[*]}"
        exit 1
    fi

    "$handler"

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
        --complete-names)
            complete_names
            exit 0
            ;;
        --complete-zsh)
            complete_zsh
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
