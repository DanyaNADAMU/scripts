#!/usr/bin/env bash
# ==============================================================================
# Script:      backup_seadrive.sh
# Category:    desktop
# Description: Encrypted incremental backup from SeaDrive to Google Drive via Rclone.
# Target:      Linux workstations with SeaDrive and Rclone
# Usage:       backup-seadrive [--help] [--setup-timer] [--remove-timer] [--status] [--dry-run]
# ==============================================================================

set -euo pipefail

SOURCE_DIR="${SEADRIVE_SOURCE:-$HOME/SeaDrive/My Libraries}"
REMOTE_DEST="${RCLONE_DEST:-gdrive-crypt:SeafileBackup}"
LOG_DIR="${LOG_DIR:-$HOME/.cache/rclone}"
LOG_FILE="$LOG_DIR/backup.log"
LOCK_FILE="/tmp/seadrive-backup.lock"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DEFAULT_TIMER_TIME="${BACKUP_TIME:-15:00:00}"

show_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Automated, encrypted incremental backup from SeaDrive to Google Drive.

Options:
  -h, --help        Show this help message and exit
  --setup-timer     Install and enable daily systemd user timer (default: 15:00)
  --remove-timer    Disable and remove the systemd user timer
  --status          Display systemd timer status and recent backup logs
  --dry-run         Perform a trial run with no changes made

Environment Variables:
  SEADRIVE_SOURCE   Path to SeaDrive library mount (default: \$HOME/SeaDrive/My Libraries)
  RCLONE_DEST       Rclone destination remote and path (default: gdrive-crypt:SeafileBackup)
  LOG_DIR           Directory for backup logs (default: \$HOME/.cache/rclone)
  BACKUP_TIME       Time for systemd timer (default: 15:00:00)
EOF
}

send_notification() {
    local urgency="$1"
    local title="$2"
    local message="$3"
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -u "$urgency" -a "SeaDrive Backup" "$title" "$message" || true
    fi
}

setup_timer() {
    echo "Настройка systemd user timer..."
    mkdir -p "$SYSTEMD_USER_DIR"

    # Определяем исполняемый путь к backup-seadrive
    local bin_path
    bin_path="$(command -v backup-seadrive 2>/dev/null || echo "$HOME/.local/bin/backup-seadrive")"

    cat << EOF > "$SYSTEMD_USER_DIR/seafile-backup.service"
[Unit]
Description=Incremental Backup SeaDrive to Google Drive
Documentation=https://rclone.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$bin_path
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

    cat << EOF > "$SYSTEMD_USER_DIR/seafile-backup.timer"
[Unit]
Description=Daily Backup SeaDrive to Google Drive Timer
Documentation=https://rclone.org/

[Timer]
OnCalendar=*-*-* $DEFAULT_TIMER_TIME
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable --now seafile-backup.timer
    echo "✓ Таймер успешно установлен и запущен на ежедневное расписание ($DEFAULT_TIMER_TIME)."
    echo "  Проверить статус: systemctl --user list-timers seafile-backup.timer"
}

remove_timer() {
    echo "Отключение таймера..."
    systemctl --user disable --now seafile-backup.timer 2>/dev/null || true
    systemctl --user stop seafile-backup.service 2>/dev/null || true
    rm -f "$SYSTEMD_USER_DIR/seafile-backup.service" "$SYSTEMD_USER_DIR/seafile-backup.timer"
    systemctl --user daemon-reload
    echo "✓ Таймер и служба удалены."
}

show_status() {
    echo "=== Статус systemd таймера ==="
    if systemctl --user is-enabled seafile-backup.timer &>/dev/null; then
        systemctl --user status seafile-backup.timer --no-pager || true
    else
        echo "Таймер не установлен или отключен (установите через --setup-timer)."
    fi
    echo ""
    echo "=== Последние строки лога ($LOG_FILE) ==="
    if [ -f "$LOG_FILE" ]; then
        tail -n 20 "$LOG_FILE"
    else
        echo "Лог еще не создан."
    fi
}

DRY_RUN=false

case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --setup-timer)
        setup_timer
        exit 0
        ;;
    --remove-timer)
        remove_timer
        exit 0
        ;;
    --status)
        show_status
        exit 0
        ;;
    --dry-run)
        DRY_RUN=true
        ;;
    "")
        ;;
    *)
        echo "Неизвестный параметр: $1"
        show_help
        exit 1
        ;;
esac

# Основной процесс синхронизации
mkdir -p "$LOG_DIR"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Предыдущий процесс бэкапа еще выполняется. Пропуск." | tee -a "$LOG_FILE"
    exit 0
fi

# Проверка rclone
if ! command -v rclone >/dev/null 2>&1; then
    msg="Ошибка: Rclone не установлен в системе."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE"
    send_notification "critical" "Ошибка бэкапа" "$msg"
    exit 1
fi

# Проверка монтирования SeaDrive
if ! mount | grep -qE "seadrive|fuse\.seadrive"; then
    msg="SeaDrive не смонтирован. Пропуск резервного копирования."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE"
    exit 0
fi

# Проверка каталога исходных библиотек
if [ ! -d "$SOURCE_DIR" ]; then
    msg="Каталог '$SOURCE_DIR' не найден. Пропуск."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE"
    exit 0
fi

echo "========================================================" >> "$LOG_FILE"
if [ "$DRY_RUN" = true ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRY-RUN] Тестовый запуск синхронизации..." | tee -a "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Запуск синхронизации: '$SOURCE_DIR' -> '$REMOTE_DEST'..." >> "$LOG_FILE"
fi

RCLONE_OPTS=(
    sync "$SOURCE_DIR" "$REMOTE_DEST"
    --transfers 4
    --checkers 8
    --tpslimit 10
    --fast-list
    --log-file "$LOG_FILE"
    --log-level NOTICE
)

if [ "$DRY_RUN" = true ]; then
    RCLONE_OPTS+=(--dry-run)
fi

if rclone "${RCLONE_OPTS[@]}"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Синхронизация успешно завершена." >> "$LOG_FILE"
    if [ "$DRY_RUN" = false ]; then
        send_notification "normal" "Бэкап завершен" "SeaDrive успешно синхронизирован с зашифрованным Google Drive."
    fi
else
    EXIT_CODE=$?
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Ошибка синхронизации (код $EXIT_CODE)." >> "$LOG_FILE"
    send_notification "critical" "Ошибка бэкапа" "Синхронизация завершилась с ошибкой $EXIT_CODE. Подробности в $LOG_FILE."
    exit "$EXIT_CODE"
fi
