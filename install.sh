#!/usr/bin/env bash
# ==============================================================================
# Script:      install.sh
# Description: Installs symlinks for scripts into ~/.local/bin
# Usage:       ./install.sh [--uninstall] [--prefix /custom/bin]
# ==============================================================================
set -e

DEST_DIR="${HOME}/.local/bin"
ACTION="install"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            DEST_DIR="$2"
            shift 2
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --prefix PATH    Target directory for symlinks (default: ~/.local/bin)"
            echo "  --uninstall      Remove symlinks installed by this script"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define mapping: <symlink_name>:<relative_path>
MAPPINGS=(
    "setup-user:server/setup_user.sh"
    "sign-image:media/sign_image.py"
)

if [ "$ACTION" = "install" ]; then
    mkdir -p "$DEST_DIR"
    echo "==> Installing symlinks to $DEST_DIR..."

    for entry in "${MAPPINGS[@]}"; do
        NAME="${entry%%:*}"
        REL_PATH="${entry##*:}"
        SRC="$SCRIPT_DIR/$REL_PATH"
        TARGET="$DEST_DIR/$NAME"

        if [ -f "$SRC" ]; then
            chmod +x "$SRC"
            ln -sf "$SRC" "$TARGET"
            echo "  [✓] $TARGET -> $SRC"
        else
            echo "  [ ] Skipping $NAME (source not yet present: $REL_PATH)"
        fi
    done

    echo ""
    if [[ ":$PATH:" != *":$DEST_DIR:"* ]]; then
        echo "Note: $DEST_DIR is not in your PATH."
        echo "Add it by adding this line to your ~/.zshrc or ~/.bashrc:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    else
        echo "All set! $DEST_DIR is already in your PATH."
    fi

elif [ "$ACTION" = "uninstall" ]; then
    echo "==> Removing symlinks from $DEST_DIR..."
    for entry in "${MAPPINGS[@]}"; do
        NAME="${entry%%:*}"
        TARGET="$DEST_DIR/$NAME"
        if [ -L "$TARGET" ]; then
            rm -f "$TARGET"
            echo "  [-] Removed $TARGET"
        fi
    done
    echo "Uninstall completed."
fi
