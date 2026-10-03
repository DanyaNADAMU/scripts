#!/bin/bash
# ==============================================================================
# Script:      setup_user.sh
# Category:    server
# Description: Provisions a new Linux user with Zsh, SSH keys, and rootless Podman.
# Target:      Linux servers (Debian/Ubuntu/Arch/Alpine) with systemd
# Usage:       sudo ./setup_user.sh [--help]
# ==============================================================================

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: sudo $0"
    echo ""
    echo "Interactive script to provision a server user account:"
    echo "  - Creates user with /bin/zsh"
    echo "  - Configures SSH public key in ~/.ssh/authorized_keys"
    echo "  - Sets up rootless Podman with lingering and user socket"
    exit 0
fi

# Ensure running with sufficient privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (or via sudo)."
    exit 1
fi

# Prompt for inputs
read -p "Enter username: " TARGET_USER
if [ -z "$TARGET_USER" ]; then
    echo "Error: Username cannot be empty."
    exit 1
fi

read -p "Enter SSH public key (or leave empty to skip): " SSH_KEY
read -p "Enable rootless Podman? (y/n): " ENABLE_PODMAN
read -p "Set password for user? (y/n): " SET_PASSWORD

# Create user if missing
if ! id "$TARGET_USER" &>/dev/null; then
    echo "Creating new user: $TARGET_USER"
    # The -m flag automatically copies contents of /etc/skel
    useradd -m -s /bin/zsh "$TARGET_USER"
else
    echo "User $TARGET_USER already exists. Updating configuration."
    # Ensure existing users are also switched to zsh
    usermod -s /bin/zsh "$TARGET_USER" 2>/dev/null
fi

USER_HOME=$(eval echo ~$TARGET_USER)
USER_UID=$(id -u "$TARGET_USER")

# Set password
if [[ "$SET_PASSWORD" =~ ^[Yy]$ ]]; then
    passwd "$TARGET_USER"
fi

# Configure SSH key
if [ -n "$SSH_KEY" ]; then
    mkdir -p "$USER_HOME/.ssh"

    # Add key if not already present
    if ! grep -q -F "$SSH_KEY" "$USER_HOME/.ssh/authorized_keys" 2>/dev/null; then
        echo "$SSH_KEY" >> "$USER_HOME/.ssh/authorized_keys"
        echo "SSH key added."
    else
        echo "SSH key already exists. Skipping."
    fi

    # Enforce strict permissions
    chmod 700 "$USER_HOME/.ssh"
    chmod 600 "$USER_HOME/.ssh/authorized_keys"
    chown -R "$TARGET_USER:$TARGET_USER" "$USER_HOME/.ssh"
fi

# Configure Podman
if [[ "$ENABLE_PODMAN" =~ ^[Yy]$ ]]; then
    echo "Configuring rootless Podman for $TARGET_USER..."

    # Create data directory for service state
    mkdir -p "$USER_HOME/data"
    chown "$TARGET_USER:$TARGET_USER" "$USER_HOME/data"
    echo "Created data directory at $USER_HOME/data"

    # Enable lingering and start systemd instance
    loginctl enable-linger "$TARGET_USER"
    systemctl start "user@$USER_UID.service"

    # Update shell configs idempotently
    ENV_BLOCK="export XDG_RUNTIME_DIR=\"/run/user/$USER_UID\"
export DOCKER_HOST=\"unix://\$XDG_RUNTIME_DIR/podman/podman.sock\"
export DBUS_SESSION_BUS_ADDRESS=\"unix:path=\$XDG_RUNTIME_DIR/bus\""

    for RC_FILE in "$USER_HOME/.bashrc" "$USER_HOME/.zshrc"; do
        # Ensure file exists before appending
        touch "$RC_FILE"
        chown "$TARGET_USER:$TARGET_USER" "$RC_FILE"

        if ! grep -q "DOCKER_HOST" "$RC_FILE"; then
            echo -e "\n$ENV_BLOCK" >> "$RC_FILE"
            echo "Added environment variables to $RC_FILE"
        fi
    done

    # Configure systemd services as the target user
    su - "$TARGET_USER" <<EOF
    export XDG_RUNTIME_DIR=/run/user/$USER_UID
    export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus

    systemctl --user daemon-reload
    systemctl --user enable --now podman.socket
    systemctl --user enable podman-restart.service
EOF
    echo "Podman services enabled."
fi

echo "Done!"
