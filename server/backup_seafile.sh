#!/usr/bin/env bash
# ==============================================================================
# Script:      backup_seafile.sh
# Category:    server
# Description: Resilient encrypted incremental backup from Seafile (WebDAV/local) to Google Drive via Rclone.
# Target:      Linux servers with Rclone and systemd
# Requires:    bash, rclone, systemd
# Usage:       backup-seafile [--help] [--setup-timer] [--remove-timer] [--status] [--force] [--dry-run] [--auto] [--config FILE]
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration Defaults
# ------------------------------------------------------------------------------
CONFIG_FILE=""
DEFAULT_SYSTEM_CONFIG="/etc/seafile-backup.conf"
DEFAULT_USER_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/seafile-backup.conf"

# Search for default configuration file
if [ -f "$DEFAULT_SYSTEM_CONFIG" ]; then
    CONFIG_FILE="$DEFAULT_SYSTEM_CONFIG"
elif [ -f "$DEFAULT_USER_CONFIG" ]; then
    CONFIG_FILE="$DEFAULT_USER_CONFIG"
fi

# Pre-parse --config or -c flag before loading settings
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[i]}" == "-c" || "${args[i]}" == "--config" ]]; then
        if [ $((i+1)) -lt ${#args[@]} ]; then
            CONFIG_FILE="${args[i+1]}"
        fi
    fi
done

if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Determine privilege scope
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
    SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
    LOG_DIR="${LOG_DIR:-/var/log/seafile-backup}"
    STATE_DIR="${STATE_DIR:-/var/lib/seafile-backup}"
    LOCK_FILE="${LOCK_FILE:-/run/lock/seafile-backup.lock}"
else
    IS_ROOT=false
    SYSTEMD_DIR="${SYSTEMD_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"
    LOG_DIR="${LOG_DIR:-$HOME/.cache/rclone}"
    STATE_DIR="${STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/scripts}"
    LOCK_FILE="${LOCK_FILE:-/tmp/seafile-backup.lock}"
fi

SEAFILE_SOURCE="${SEAFILE_SOURCE:-seafile-dav:}"
REMOTE_DEST="${RCLONE_DEST:-gdrive-crypt:SeafileBackup}"
RCLONE_CONFIG_PATH="${RCLONE_CONFIG_PATH:-}"
LOG_FILE="$LOG_DIR/backup.log"
STATE_FILE="$STATE_DIR/backup-seafile.last"

BACKUP_INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-20}"
CHECK_INTERVAL="${CHECK_INTERVAL:-15m}"
WAIT_ONLINE_TIMEOUT="${WAIT_ONLINE_TIMEOUT:-25}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"

# ------------------------------------------------------------------------------
# CLI Help
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Automated, encrypted incremental backup from Seafile (via WebDAV or local mount)
directly to Google Drive via Rclone. Designed for Linux servers.

Options:
  -h, --help            Show this help message and exit
  -c, --config FILE     Load settings from specific configuration file
  --setup-timer         Install and enable resilient systemd timer (checks every ${CHECK_INTERVAL})
  --remove-timer        Disable and remove the systemd timer and service
  --status              Display timer status, prerequisite health, and recent logs
  --force               Force backup now, bypassing cooldown and lock checks
  --dry-run             Perform a trial run with no changes made to remote
  --auto                Automated run mode used by systemd timer (throttled to ~daily)

Configuration Priority:
  1. CLI environment variables (highest)
  2. Configuration file specified via --config / -c
  3. Default config file ($DEFAULT_SYSTEM_CONFIG or $DEFAULT_USER_CONFIG)
  4. Built-in defaults

Key Environment / Config Variables:
  SEAFILE_SOURCE         Rclone remote (e.g. seafile-dav:) or local mount path (default: seafile-dav:)
  RCLONE_DEST            Rclone destination remote and path (default: gdrive-crypt:SeafileBackup)
  RCLONE_CONFIG_PATH     Optional explicit path to rclone.conf
  BACKUP_INTERVAL_HOURS  Minimum hours between automatic backups (default: 20)
  CHECK_INTERVAL         Systemd timer poll interval (default: 15m)
  WAIT_ONLINE_TIMEOUT    Seconds to wait for network/Seafile at boot before deferring (default: 25)
  LOG_DIR                Directory for backup logs (default: /var/log/seafile-backup or ~/.cache/rclone)
  STATE_DIR              Directory for last backup timestamp state
  ALERT_WEBHOOK_URL      Optional Webhook URL (Slack/Discord/Telegram/Generic) for alerts
EOF
}

# ------------------------------------------------------------------------------
# Logging & Notifications
# ------------------------------------------------------------------------------
send_alert() {
    local level="$1" # info, warning, error
    local title="$2"
    local message="$3"

    # Syslog logging
    if command -v logger >/dev/null 2>&1; then
        local priority="user.notice"
        [ "$level" = "warning" ] && priority="user.warning"
        [ "$level" = "error" ] && priority="user.err"
        logger -t "backup-seafile" -p "$priority" "[$title] $message" || true
    fi

    # Webhook alert if configured
    if [ -n "$ALERT_WEBHOOK_URL" ] && command -v curl >/dev/null 2>&1; then
        local payload
        payload=$(printf '{"event":"seafile_backup","level":"%s","title":"%s","message":"%s","host":"%s"}' \
            "$level" "$title" "$message" "$(hostname 2>/dev/null || echo 'server')")
        curl -fsS -X POST -H "Content-Type: application/json" -d "$payload" "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
}

# ------------------------------------------------------------------------------
# Prerequisite & Health Checks
# ------------------------------------------------------------------------------
check_network() {
    # 1. Quick check for default route
    if ! ip route show default 2>/dev/null | grep -q default; then
        return 1
    fi

    # 2. Connectivity check to public DNS or Google endpoints
    if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || \
       ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || \
       getent hosts www.google.com >/dev/null 2>&1 || \
       curl -s --head --connect-timeout 2 https://www.google.com >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

get_rclone_cmd() {
    local cmd=(rclone)
    if [ -n "$RCLONE_CONFIG_PATH" ]; then
        cmd+=(--config "$RCLONE_CONFIG_PATH")
    fi
    echo "${cmd[@]}"
}

check_seafile() {
    local rclone_bin
    rclone_bin="$(command -v rclone 2>/dev/null || true)"
    if [ -z "$rclone_bin" ]; then
        return 1
    fi

    local extra_cfg=()
    if [ -n "$RCLONE_CONFIG_PATH" ]; then
        extra_cfg+=(--config "$RCLONE_CONFIG_PATH")
    fi

    # Case 1: Remote endpoint (contains colon, e.g. seafile-dav: or seafile:)
    if [[ "$SEAFILE_SOURCE" == *:* ]]; then
        # Check connection and verify libraries exist
        local list_output
        if list_output="$("$rclone_bin" lsd "$SEAFILE_SOURCE" --max-depth 1 "${extra_cfg[@]}" 2>/dev/null)"; then
            # Must not be completely empty
            if [ -n "$list_output" ]; then
                return 0
            fi
        fi
        return 1
    fi

    # Case 2: Local directory / FUSE mount
    if [ ! -d "$SEAFILE_SOURCE" ] || [ ! -r "$SEAFILE_SOURCE" ]; then
        return 1
    fi

    # Prevent empty directory sync wipes
    if [ -z "$(ls -A "$SEAFILE_SOURCE" 2>/dev/null)" ]; then
        return 1
    fi

    return 0
}

wait_for_prerequisites() {
    local timeout="$1"
    local waited=0
    local step=3

    while [ "$waited" -lt "$timeout" ]; do
        if check_network && check_seafile; then
            return 0
        fi
        sleep "$step"
        waited=$(( waited + step ))
    done

    if check_network && check_seafile; then
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

# ------------------------------------------------------------------------------
# Systemd Service & Timer Management
# ------------------------------------------------------------------------------
setup_timer() {
    echo "Настройка resilient systemd timer для сервера..."
    mkdir -p "$SYSTEMD_DIR"

    local bin_path
    bin_path="$(command -v backup-seafile 2>/dev/null || echo "/usr/local/bin/backup-seafile")"
    if [ ! -x "$bin_path" ]; then
        bin_path="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
    fi

    local exec_cmd="$bin_path --auto"
    if [ -n "$CONFIG_FILE" ]; then
        exec_cmd="$bin_path --config $CONFIG_FILE --auto"
    fi

    local service_file="$SYSTEMD_DIR/seafile-backup.service"
    local timer_file="$SYSTEMD_DIR/seafile-backup.timer"

    cat << EOF > "$service_file"
[Unit]
Description=Incremental Backup Seafile to Google Drive via Rclone
Documentation=https://rclone.org/
After=network.target network-online.target

[Service]
Type=oneshot
ExecStart=$exec_cmd
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > "$timer_file"
[Unit]
Description=Resilient Periodic Seafile to Google Drive Backup Timer
Documentation=https://rclone.org/

[Timer]
OnBootSec=5m
OnUnitActiveSec=$CHECK_INTERVAL
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

    if command -v systemctl >/dev/null 2>&1; then
        if [ "$IS_ROOT" = true ]; then
            systemctl daemon-reload
            systemctl enable --now seafile-backup.timer
        else
            systemctl --user daemon-reload
            systemctl --user enable --now seafile-backup.timer
        fi
        echo "✓ Таймер успешно установлен и запущен."
    else
        echo "✓ Файлы systemd созданы в $SYSTEMD_DIR (systemctl не найден в окружении)."
    fi

    echo "  Интервал проверки : каждые $CHECK_INTERVAL (при отсутствии сети или недоступности повторит автоматически)."
    echo "  Периодичность бэкапа: каждые ~${BACKUP_INTERVAL_HOURS}ч."
    echo "  Проверить статус    : backup-seafile --status"
}

remove_timer() {
    echo "Отключение таймера..."
    local service_file="$SYSTEMD_DIR/seafile-backup.service"
    local timer_file="$SYSTEMD_DIR/seafile-backup.timer"

    if command -v systemctl >/dev/null 2>&1; then
        if [ "$IS_ROOT" = true ]; then
            systemctl disable --now seafile-backup.timer 2>/dev/null || true
            systemctl stop seafile-backup.service 2>/dev/null || true
            rm -f "$service_file" "$timer_file"
            systemctl daemon-reload
        else
            systemctl --user disable --now seafile-backup.timer 2>/dev/null || true
            systemctl --user stop seafile-backup.service 2>/dev/null || true
            rm -f "$service_file" "$timer_file"
            systemctl --user daemon-reload
        fi
    else
        rm -f "$service_file" "$timer_file"
    fi
    echo "✓ Таймер и служба удалены."
}

show_status() {
    echo "=== Seafile Server Backup Status ==="
    echo ""
    echo "--- Configuration ---"
    echo "  Источник Seafile  : $SEAFILE_SOURCE"
    echo "  Назначение Rclone : $REMOTE_DEST"
    [ -n "$CONFIG_FILE" ] && echo "  Файл конфигурации : $CONFIG_FILE"
    [ -n "$RCLONE_CONFIG_PATH" ] && echo "  Конфиг Rclone     : $RCLONE_CONFIG_PATH"
    echo "  Лог-файл          : $LOG_FILE"
    echo "  Файл состояния    : $STATE_FILE"
    echo ""
    echo "--- Systemd Timer ---"
    if command -v systemctl >/dev/null 2>&1; then
        local sys_cmd=(systemctl)
        [ "$IS_ROOT" = false ] && sys_cmd+=(--user)

        if "${sys_cmd[@]}" is-enabled seafile-backup.timer &>/dev/null; then
            "${sys_cmd[@]}" status seafile-backup.timer --no-pager || true
            echo ""
            echo "--- Next Scheduled Run ---"
            "${sys_cmd[@]}" list-timers seafile-backup.timer --no-pager || true
        else
            echo "Таймер не установлен или отключен (установите через: backup-seafile --setup-timer)."
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

    if check_seafile; then
        echo "  [✓] Seafile Источник: доступен ('$SEAFILE_SOURCE')"
    else
        echo "  [✗] Seafile Источник: НЕ доступен или библиотеки пусты ('$SEAFILE_SOURCE')"
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

# ------------------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------------------
DRY_RUN=false
FORCE=false
AUTO_MODE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--config)
            shift
            [ $# -gt 0 ] && shift || true
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

# ------------------------------------------------------------------------------
# Concurrency Lock
# ------------------------------------------------------------------------------
if [ "$FORCE" = false ]; then
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Предыдущий процесс бэкапа еще выполняется. Пропуск." | tee -a "$LOG_FILE"
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# Dependency Verification
# ------------------------------------------------------------------------------
if ! command -v rclone >/dev/null 2>&1; then
    msg="Ошибка: Rclone не установлен в системе."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE" >&2
    send_alert "error" "Ошибка бэкапа Seafile" "$msg"
    exit 1
fi

# ------------------------------------------------------------------------------
# Cooldown Verification (Auto Mode)
# ------------------------------------------------------------------------------
if [ "$FORCE" = false ] && [ "$AUTO_MODE" = true ]; then
    if ! is_backup_due; then
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# Readiness Checks
# ------------------------------------------------------------------------------
if [ "$AUTO_MODE" = true ]; then
    if ! wait_for_prerequisites "$WAIT_ONLINE_TIMEOUT"; then
        reason=""
        if ! check_network; then
            reason="сеть недоступна"
        fi
        if ! check_seafile; then
            [ -n "$reason" ] && reason="$reason, "
            reason="${reason}источник Seafile ($SEAFILE_SOURCE) недоступен"
        fi
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Предусловия не выполнены ($reason). Бэкап отложен до следующей проверки ($CHECK_INTERVAL)." >> "$LOG_FILE"
        exit 0
    fi
else
    if ! check_network; then
        echo "Ошибка: Отсутствует подключение к сети (интернет недоступен)." >&2
        exit 1
    fi
    if ! check_seafile; then
        echo "Ошибка: Источник Seafile ('$SEAFILE_SOURCE') недоступен или не содержит данных." >&2
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------
echo "========================================================" >> "$LOG_FILE"
if [ "$DRY_RUN" = true ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRY-RUN] Тестовый запуск синхронизации: '$SEAFILE_SOURCE' -> '$REMOTE_DEST'..." | tee -a "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Запуск синхронизации: '$SEAFILE_SOURCE' -> '$REMOTE_DEST'..." >> "$LOG_FILE"
fi

RCLONE_CMD=(rclone)
if [ -n "$RCLONE_CONFIG_PATH" ]; then
    RCLONE_CMD+=(--config "$RCLONE_CONFIG_PATH")
fi

RCLONE_OPTS=(
    sync "$SEAFILE_SOURCE" "$REMOTE_DEST"
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

if "${RCLONE_CMD[@]}" "${RCLONE_OPTS[@]}"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Синхронизация успешно завершена." >> "$LOG_FILE"
    if [ "$DRY_RUN" = false ]; then
        save_state
        send_alert "info" "Бэкап Seafile завершен" "Seafile успешно синхронизирован с зашифрованным Google Drive."
    fi
else
    EXIT_CODE=$?
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Ошибка синхронизации (код $EXIT_CODE)." >> "$LOG_FILE"
    send_alert "error" "Ошибка бэкапа Seafile" "Синхронизация завершилась с ошибкой $EXIT_CODE. Подробности в $LOG_FILE."
    exit "$EXIT_CODE"
fi
