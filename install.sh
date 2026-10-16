#!/usr/bin/env bash
# ==============================================================================
# Script:      install.sh
# Description: Bootstrap launcher for the unified 'scripts' manager.
# Usage:       ./install.sh [options]  OR  curl -fsSL <url>/install.sh | bash
# ==============================================================================
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || echo "")"

ARGS=()
if [ $# -eq 0 ]; then
    ARGS=("update")
else
    case "$1" in
        update|sync|install|list|uninstall|help|-h|--help)
            ARGS=("$@")
            ;;
        *)
            ARGS=("update" "$@")
            ;;
    esac
fi

if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/scripts" ]; then
    exec "$SELF_DIR/scripts" "${ARGS[@]}"
fi

# Remote bootstrap mode (e.g. curl -fsSL .../install.sh | bash)
GITHUB_RAW="https://raw.githubusercontent.com/DanyaNADAMU/scripts/main"
COMMIT_SHA="$(curl -fsSL --connect-timeout 2 --max-time 4 "https://api.github.com/repos/DanyaNADAMU/scripts/commits/main" 2>/dev/null | grep '"sha"' | head -n 1 | cut -d'"' -f4 || echo "")"
if [ -n "$COMMIT_SHA" ]; then
    GITHUB_RAW="https://raw.githubusercontent.com/DanyaNADAMU/scripts/$COMMIT_SHA"
fi

TMP_SCRIPTS="$(mktemp -t scripts-bootstrap.XXXXXX)"
cleanup() {
    rm -f "$TMP_SCRIPTS"
}
trap cleanup EXIT INT TERM

if ! curl -fsSL --connect-timeout 5 --max-time 30 "$GITHUB_RAW/scripts" -o "$TMP_SCRIPTS"; then
    echo "Error: Failed to download bootstrap scripts manager." >&2
    exit 1
fi

chmod +x "$TMP_SCRIPTS"
"$TMP_SCRIPTS" "${ARGS[@]}"
cleanup

