#!/usr/bin/env bash
# ==============================================================================
# Script:      backup_seadrive.sh
# Category:    desktop
# Description: Resilient encrypted incremental backup from SeaDrive to Google Drive via Rclone.
# Target:      Linux workstations with SeaDrive and Rclone
# Requires:    bash, rclone, systemd
# Usage:       backup-seadrive [--help] [--setup-timer] [--remove-timer] [--status] [--force] [--dry-run] [--auto]
# ==============================================================================

set -euo pipefail

SOURCE_DIR="${SEADRIVE_SOURCE:-$HOME/SeaDrive/My Libraries}"
REMOTE_DEST="${RCLONE_DEST:-gdrive-crypt:SeafileBackup}"
LOG_DIR="${LOG_DIR:-$HOME/.cache/rclone}"
LOG_FILE="$LOG_DIR/backup.log"
LOCK_FILE="/tmp/seadrive-backup.lock"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/scripts"
STATE_FILE="$STATE_DIR/backup-seadrive.last"

BACKUP_INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-20}"
CHECK_INTERVAL="${CHECK_INTERVAL:-15m}"
WAIT_ONLINE_TIMEOUT="${WAIT_ONLINE_TIMEOUT:-25}"

show_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Automated, encrypted incremental backup from SeaDrive to Google Drive.
Resilient against offline boots and network interruptions.

Options:
  -h, --help        Show this help message and exit
  --setup-timer     Install and enable resilient systemd user timer (checks every ${CHECK_INTERVAL})
  --remove-timer    Disable and remove the systemd user timer
  --status          Display timer status, prerequisites, and recent logs
  --force           Force backup now, bypassing cooldown and lock checks
  --dry-run         Perform a trial run with no changes made to remote
  --auto            Automated run mode used by systemd timer (throttled to ~daily)

Environment Variables:
  SEADRIVE_SOURCE        Path to SeaDrive library mount (default: \$HOME/SeaDrive/My Libraries)
  RCLONE_DEST            Rclone destination remote and path (default: gdrive-crypt:SeafileBackup)
  LOG_DIR                Directory for backup logs (default: \$HOME/.cache/rclone)
  BACKUP_INTERVAL_HOURS  Minimum hours between automatic backups (default: 20)
  CHECK_INTERVAL         Systemd timer poll interval (default: 15m)
  WAIT_ONLINE_TIMEOUT    Seconds to wait for network/mount at boot (default: 25)
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

check_network() {
    # 1. Быстрая проверка наличия маршрута по умолчанию
    if ! ip route show default 2>/dev/null | grep -q default; then
        return 1
    fi

    # 2. Проверка реальной сетевой доступности
    if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || \
       ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || \
       getent hosts www.google.com >/dev/null 2>&1 || \
       curl -s --head --connect-timeout 2 https://www.google.com >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

check_seadrive() {
    # 1. Проверка наличия точки монтирования SeaDrive в системе
    if ! grep -qE "seadrive|fuse\.seadrive" /proc/mounts 2>/dev/null && ! mount | grep -qE "seadrive|fuse\.seadrive"; then
        return 1
    fi

    # 2. Проверка доступности исходного каталога
    if [ ! -d "$SOURCE_DIR" ] || [ ! -r "$SOURCE_DIR" ]; then
        return 1
    fi

    # 3. Защита от случайной очистки: каталог не должен быть пустым
    if [ -z "$(ls -A "$SOURCE_DIR" 2>/dev/null)" ]; then
        return 1
    fi

    return 0
}

wait_for_prerequisites() {
    local timeout="$1"
    local waited=0
    local step=3

    while [ "$waited" -lt "$timeout" ]; do
        if check_network && check_seadrive; then
            return 0
        fi
        sleep "$step"
        waited=$(( waited + step ))
    done

    # Итоговая проверка после ожидания
    if check_network && check_seadrive; then
        return 0
    fi
    return 1
}

is_backup_due() {
    if [ ! -f "$STATE_FILE" ]; then
        return 0
    fi

    local last_ts
    last_ts="$(awk '{print $1}' "$STATE_FILE" 2>/dev/null || echo 0)"
    if ! [[ "$last_ts" =~ ^[0-9]+$ ]]; then
        return 0
    fi

    local now
    now="$(date +%s)"
    local elapsed=$(( now - last_ts ))
    local threshold=$(( BACKUP_INTERVAL_HOURS * 3600 ))

    if [ "$elapsed" -ge "$threshold" ]; then
        return 0
    else
        return 1
    fi
}

save_state() {
    mkdir -p "$STATE_DIR"
    local now
    now="$(date +%s)"
    local iso_date
    iso_date="$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"
    echo "$now $iso_date" > "$STATE_FILE"
}

setup_timer() {
    echo "Настройка resilient systemd user timer..."
    mkdir -p "$SYSTEMD_USER_DIR"

    local bin_path
    bin_path="$(command -v backup-seadrive 2>/dev/null || echo "$HOME/.local/bin/backup-seadrive")"

    cat << EOF > "$SYSTEMD_USER_DIR/seafile-backup.service"
[Unit]
Description=Incremental Backup SeaDrive to Google Drive
Documentation=https://rclone.org/
After=network.target network-online.target

[Service]
Type=oneshot
ExecStart=$bin_path --auto
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

    cat << EOF > "$SYSTEMD_USER_DIR/seafile-backup.timer"
[Unit]
Description=Resilient Periodic SeaDrive to Google Drive Backup Timer
Documentation=https://rclone.org/

[Timer]
OnBootSec=2m
OnUnitActiveSec=$CHECK_INTERVAL
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        systemctl --user enable --now seafile-backup.timer
        echo "✓ Таймер успешно установлен и запущен."
    else
        echo "✓ Файлы systemd созданы в $SYSTEMD_USER_DIR (systemctl не найден в окружении)."
    fi

    echo "  Интервал проверки: каждые $CHECK_INTERVAL (при пропуске или отсутствии сети повторит автоматически)."
    echo "  Периодичность бэкапа: каждые ~${BACKUP_INTERVAL_HOURS}ч."
    echo "  Проверить статус: backup-seadrive --status"
}

remove_timer() {
    echo "Отключение таймера..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now seafile-backup.timer 2>/dev/null || true
        systemctl --user stop seafile-backup.service 2>/dev/null || true
        rm -f "$SYSTEMD_USER_DIR/seafile-backup.service" "$SYSTEMD_USER_DIR/seafile-backup.timer"
        systemctl --user daemon-reload
    else
        rm -f "$SYSTEMD_USER_DIR/seafile-backup.service" "$SYSTEMD_USER_DIR/seafile-backup.timer"
    fi
    echo "✓ Таймер и служба удалены."
}

show_status() {
    echo "=== SeaDrive Backup Status ==="
    echo ""
    echo "--- Systemd User Timer ---"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl --user is-enabled seafile-backup.timer &>/dev/null; then
            systemctl --user status seafile-backup.timer --no-pager || true
            echo ""
            echo "--- Next Scheduled Run ---"
            systemctl --user list-timers seafile-backup.timer --no-pager || true
        else
            echo "Таймер не установлен или отключен (установите через: backup-seadrive --setup-timer)."
        fi
    else
        echo "systemctl недоступен."
    fi
    echo ""
    echo "--- Backup Cooldown State ---"
    if [ -f "$STATE_FILE" ]; then
        local last_ts="" iso_date=""
        read -r last_ts iso_date < "$STATE_FILE" || true
        if [[ "$last_ts" =~ ^[0-9]+$ ]]; then
            local now elapsed hours_elapsed mins_elapsed
            now="$(date +%s)"
            elapsed=$(( now - last_ts ))
            hours_elapsed=$(( elapsed / 3600 ))
            mins_elapsed=$(( (elapsed % 3600) / 60 ))
            echo "  Последний успешный бэкап : $iso_date (${hours_elapsed}ч ${mins_elapsed}м назад)"
            if [ "$elapsed" -ge $(( BACKUP_INTERVAL_HOURS * 3600 )) ]; then
                echo "  Статус расписания        : ТРЕБУЕТСЯ (прошло >= ${BACKUP_INTERVAL_HOURS}ч)"
            else
                local left_hours=$(( BACKUP_INTERVAL_HOURS - hours_elapsed ))
                echo "  Статус расписания        : АКТУАЛЕН (следующий автозапуск через ~${left_hours}ч)"
            fi
        else
            echo "  Файл состояния поврежден: $STATE_FILE"
        fi
    else
        echo "  Бэкап еще ни разу не выполнялся (состояние отсутствует)."
    fi
    echo ""
    echo "--- Prerequisites Check ---"
    if check_network; then
        echo "  [✓] Сеть: подключена (интернет доступен)"
    else
        echo "  [✗] Сеть: ОТСУТСТВУЕТ (офлайн)"
    fi

    if check_seadrive; then
        echo "  [✓] SeaDrive: смонтирован ('$SOURCE_DIR')"
    else
        echo "  [✗] SeaDrive: НЕ смонтирован или каталог пуст/недоступен"
    fi

    if command -v rclone >/dev/null 2>&1; then
        echo "  [✓] Rclone: установлен ($(rclone --version 2>/dev/null | head -n 1))"
    else
        echo "  [✗] Rclone: НЕ установлен"
    fi
    echo ""
    echo "--- Последние строки лога ($LOG_FILE) ---"
    if [ -f "$LOG_FILE" ]; then
        tail -n 20 "$LOG_FILE"
    else
        echo "Лог еще не создан."
    fi
}

DRY_RUN=false
FORCE=false
AUTO_MODE=false

while [ $# -gt 0 ]; do
    case "$1" in
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
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --auto)
            AUTO_MODE=true
            shift
            ;;
        *)
            echo "Неизвестный параметр: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

mkdir -p "$LOG_DIR"

# Блокировка от параллельных запусков
if [ "$FORCE" = false ]; then
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Предыдущий процесс бэкапа еще выполняется. Пропуск." | tee -a "$LOG_FILE"
        exit 0
    fi
fi

# Проверка rclone
if ! command -v rclone >/dev/null 2>&1; then
    msg="Ошибка: Rclone не установлен в системе."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE" >&2
    send_notification "critical" "Ошибка бэкапа" "$msg"
    exit 1
fi

# Автоматический режим: проверка кулдауна (не чаще раза в BACKUP_INTERVAL_HOURS)
if [ "$FORCE" = false ] && [ "$AUTO_MODE" = true ]; then
    if ! is_backup_due; then
        # Бэкап уже успешно выполнялся сегодня, выходим тихо и мгновенно
        exit 0
    fi
fi

# Проверка готовности сети и точки монтирования SeaDrive
if [ "$AUTO_MODE" = true ]; then
    if ! wait_for_prerequisites "$WAIT_ONLINE_TIMEOUT"; then
        reason=""
        if ! check_network; then
            reason="сеть недоступна"
        fi
        if ! check_seadrive; then
            [ -n "$reason" ] && reason="$reason, "
            reason="${reason}SeaDrive не смонтирован"
        fi
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Предусловия не выполнены ($reason). Бэкап отложен до следующей проверки ($CHECK_INTERVAL)." >> "$LOG_FILE"
        exit 0
    fi
else
    # Ручной запуск: сразу выводим ошибку, если что-то не готово
    if ! check_network; then
        echo "Ошибка: Отсутствует подключение к сети (интернет недоступен)." >&2
        exit 1
    fi
    if ! check_seadrive; then
        echo "Ошибка: SeaDrive не смонтирован или каталог '$SOURCE_DIR' недоступен/пуст." >&2
        exit 1
    fi
fi

# Выполнение синхронизации
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
        save_state
        send_notification "normal" "Бэкап завершен" "SeaDrive успешно синхронизирован с зашифрованным Google Drive."
    fi
else
    EXIT_CODE=$?
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Ошибка синхронизации (код $EXIT_CODE)." >> "$LOG_FILE"
    send_notification "critical" "Ошибка бэкапа" "Синхронизация завершилась с ошибкой $EXIT_CODE. Подробности в $LOG_FILE."
    exit "$EXIT_CODE"
fi
