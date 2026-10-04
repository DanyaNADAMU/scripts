#!/usr/bin/env bash
# ==============================================================================
# Script:      install.sh
# Description: Bootstrap launcher for the unified 'scripts' manager.
# Usage:       ./install.sh [options]  OR  curl -fsSL <url>/install.sh | bash
# ==============================================================================
set -euo pipefail

GITHUB_RAW="https://raw.githubusercontent.com/DanyaNADAMU/scripts/main"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || echo "")"

ARGS=()
if [ $# -eq 0 ]; then
    ARGS=("install")
else
    case "$1" in
        install|update|list|uninstall|help|-h|--help)
            ARGS=("$@")
            ;;
        *)
            ARGS=("install" "$@")
            ;;
    esac
fi

if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/scripts" ]; then
    exec "$SELF_DIR/scripts" "${ARGS[@]}"
else
    TMP_SCRIPTS="$(mktemp)"
    trap 'rm -f "$TMP_SCRIPTS"' EXIT
    curl -fsSL "$GITHUB_RAW/scripts" -o "$TMP_SCRIPTS"
    chmod +x "$TMP_SCRIPTS"
    exec "$TMP_SCRIPTS" "${ARGS[@]}"
fi
