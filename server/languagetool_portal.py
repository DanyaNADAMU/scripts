#!/usr/bin/env python3
"""
Script:      languagetool_portal.py
Category:    server
Description: Self-service token portal for LanguageTool with Authentik forward auth.
Target:      Linux server (standalone or reverse-proxied behind HAProxy/Authentik)
Requires:    python >= 3.10 (standard library only)
Usage:       languagetool-portal [options]
"""
from __future__ import annotations

import argparse
import fcntl
import html
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

# ==============================================================================
# Configuration Defaults
# ==============================================================================
DEFAULT_HOST = os.environ.get("LT_PORTAL_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("LT_PORTAL_PORT", "8012"))
DEFAULT_SERVER_URL = os.environ.get("LT_SERVER_URL", "https://lt.nada.mu/v2")
DEFAULT_USERS_FILE = os.environ.get(
    "LT_USERS_FILE",
    os.path.expanduser("~/stacks/languagetool/data/users.txt"),
)
DEFAULT_IN_PLACE = os.environ.get("LT_IN_PLACE", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

SERVICE_NAME = "languagetool-portal"
VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("languagetool-portal")

# Global lock for thread-safety within the process
_process_lock = threading.Lock()


# ==============================================================================
# File Operations & Concurrency
# ==============================================================================
@contextmanager
def file_lock_context(users_file: str) -> Iterator[None]:
    """Acquires a process-level mutex and filesystem-level advisory flock.

    A dedicated '.lock' file ensures processes synchronize without racing on
    inode replacements caused by atomic os.replace operations.
    """
    abs_path = os.path.abspath(users_file)
    dir_name = os.path.dirname(abs_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    lock_path = abs_path + ".lock"

    with _process_lock:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def validate_username(raw_username: str | None) -> tuple[bool, str]:
    """Validates and sanitizes Authentik username input.

    Rejects empty values, newlines, colons, null bytes, and non-printable
    characters to prevent file format injection into users.txt.
    """
    if not raw_username:
        return False, "Username is empty"
    username = raw_username.strip()
    if not username:
        return False, "Username cannot be whitespace only"
    if len(username) > 256:
        return False, "Username exceeds maximum length (256 characters)"
    if any(c in username for c in (":", "\n", "\r", "\0")):
        return False, "Username contains forbidden characters (':', newlines, or null bytes)"
    if any(ord(c) < 32 or ord(c) == 127 for c in username):
        return False, "Username contains control characters"
    return True, username


def _read_token_unlocked(users_file: str, username: str) -> str | None:
    """Reads existing token for a user from users.txt without locking."""
    if not os.path.exists(users_file):
        return None
    try:
        with open(users_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    parts = stripped.split(":", 1)
                    if len(parts) == 2 and parts[0] == username:
                        return parts[1].strip()
    except OSError as e:
        logger.error("Failed to read %s: %s", users_file, e)
    return None


def _save_token_unlocked(
    users_file: str,
    username: str,
    token: str,
    in_place: bool = False,
) -> None:
    """Saves user token into users.txt.

    Preserves comments and records of other users. Supports atomic replacement
    (recommended when directory is mounted) or in-place overwrite (for single-file
    bind-mounts where inode preservation is mandatory).
    """
    abs_path = os.path.abspath(users_file)
    dir_name = os.path.dirname(abs_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    lines: list[str] = []
    found = False
    orig_mode = 0o644

    if os.path.exists(abs_path):
        try:
            stat_info = os.stat(abs_path)
            orig_mode = stat_info.st_mode & 0o777
            with open(abs_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        parts = stripped.split(":", 1)
                        if len(parts) == 2 and parts[0] == username:
                            lines.append(f"{username}:{token}\n")
                            found = True
                            continue
                    lines.append(line)
        except OSError as e:
            logger.error("Error reading %s before save: %s", abs_path, e)

    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"{username}:{token}\n")

    content = "".join(lines)

    if in_place and os.path.exists(abs_path):
        # In-place write: preserves the inode of users.txt
        with open(abs_path, "r+", encoding="utf-8") as f:
            f.seek(0)
            f.write(content)
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
    else:
        # Atomic write: creates temporary file in the same directory and replaces
        fd, tmp_path = tempfile.mkstemp(prefix="users-", suffix=".tmp", dir=dir_name)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, orig_mode)
            os.replace(tmp_path, abs_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise


def get_or_create_token(users_file: str, username: str, in_place: bool = False) -> str:
    """Retrieves existing token or generates and persists a new one."""
    with file_lock_context(users_file):
        token = _read_token_unlocked(users_file, username)
        if token:
            return token
        new_token = secrets.token_hex(16)
        _save_token_unlocked(users_file, username, new_token, in_place=in_place)
        logger.info("Created new API token for user '%s'", username)
        return new_token


def regenerate_token(users_file: str, username: str, in_place: bool = False) -> str:
    """Generates a new token for the user, overwriting previous value."""
    with file_lock_context(users_file):
        new_token = secrets.token_hex(16)
        _save_token_unlocked(users_file, username, new_token, in_place=in_place)
        logger.info("Regenerated API token for user '%s'", username)
        return new_token


# ==============================================================================
# UI Template & Rendering
# ==============================================================================
def render_portal_html(username: str, token: str, server_url: str) -> str:
    """Renders the self-contained dark-themed single page application."""
    safe_user = html.escape(username)
    safe_token = html.escape(token)
    safe_url = html.escape(server_url)

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>LanguageTool — Портал токенов</title>
    <style>
        :root {{
            --bg-body: #0d1117;
            --bg-card: #161b22;
            --bg-input: #090d13;
            --bg-button: #21262d;
            --bg-button-hover: #30363d;
            --border-default: #30363d;
            --border-muted: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-link: #58a6ff;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --btn-green-bg: #238636;
            --accent-red: #f85149;
            --btn-red-border: #da3633;
            --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-stack);
            background-color: var(--bg-body);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}

        .portal-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-default);
            border-radius: 12px;
            width: 100%;
            max-width: 520px;
            padding: 32px;
            box-shadow: 0 16px 36px rgba(1, 4, 9, 0.65);
        }}

        .card-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }}

        .logo-icon {{
            width: 32px;
            height: 32px;
            color: var(--accent-blue);
            flex-shrink: 0;
        }}

        h1 {{
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
            letter-spacing: -0.2px;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 13px;
            margin-bottom: 20px;
        }}

        .user-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(56, 139, 253, 0.1);
            border: 1px solid rgba(56, 139, 253, 0.25);
            color: var(--accent-blue);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 24px;
        }}

        .pulse-dot {{
            width: 7px;
            height: 7px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 0 2px rgba(63, 185, 80, 0.2);
        }}

        .field-group {{
            margin-bottom: 18px;
        }}

        label {{
            display: block;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .input-row {{
            display: flex;
            gap: 8px;
        }}

        input[type="text"] {{
            flex: 1;
            background: var(--bg-input);
            border: 1px solid var(--border-default);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 13px;
            outline: none;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }}

        input[type="text"]:focus {{
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2);
        }}

        .btn {{
            font-family: var(--font-stack);
            font-size: 13px;
            font-weight: 500;
            padding: 8px 14px;
            border-radius: 6px;
            border: 1px solid var(--border-default);
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
            user-select: none;
        }}

        .btn-copy {{
            background: var(--bg-button);
            color: var(--text-primary);
            min-width: 70px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}

        .btn-copy:hover {{
            background: var(--bg-button-hover);
            border-color: #8b949e;
        }}

        .btn-copy.copied {{
            background: var(--btn-green-bg) !important;
            border-color: var(--accent-green) !important;
            color: #ffffff !important;
        }}

        .btn-regen {{
            width: 100%;
            margin-top: 8px;
            margin-bottom: 24px;
            background: transparent;
            border-color: var(--btn-red-border);
            color: var(--accent-red);
            padding: 10px 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }}

        .btn-regen:hover {{
            background: var(--accent-red);
            color: #ffffff;
            border-color: var(--accent-red);
        }}

        .guide-accordion {{
            border: 1px solid var(--border-default);
            border-radius: 8px;
            background: rgba(22, 27, 34, 0.6);
            overflow: hidden;
        }}

        .guide-accordion summary {{
            padding: 12px 16px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            color: var(--accent-blue);
            user-select: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background-color 0.15s ease;
        }}

        .guide-accordion summary:hover {{
            background: rgba(56, 139, 253, 0.08);
        }}

        .guide-content {{
            padding: 14px 18px 18px 18px;
            border-top: 1px solid var(--border-default);
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .guide-content ol {{
            margin-left: 20px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .guide-content li {{
            color: var(--text-primary);
        }}

        .guide-content strong {{
            color: #ffffff;
        }}

        .guide-content code {{
            font-family: var(--font-mono);
            font-size: 12px;
            background: var(--bg-input);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid var(--border-default);
            color: var(--accent-blue);
        }}

        .card-footer {{
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid var(--border-muted);
            text-align: center;
            font-size: 11px;
            color: #6e7681;
        }}
    </style>
</head>
<body>
    <div class="portal-card">
        <div class="card-header">
            <svg class="logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 20h9"></path>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
            </svg>
            <h1>LanguageTool Access</h1>
        </div>
        <p class="subtitle">Персональные реквизиты для плагина LanguageTool в Obsidian</p>

        <div class="user-badge">
            <span class="pulse-dot"></span>
            <span>Авторизован: <strong>{safe_user}</strong></span>
        </div>

        <div class="field-group">
            <label for="server-url">Server URL (Endpoint)</label>
            <div class="input-row">
                <input type="text" id="server-url" value="{safe_url}" readonly spellcheck="false">
                <button type="button" class="btn btn-copy" onclick="copyField('server-url', this)">Copy</button>
            </div>
        </div>

        <div class="field-group">
            <label for="api-user">API Username</label>
            <div class="input-row">
                <input type="text" id="api-user" value="{safe_user}" readonly spellcheck="false">
                <button type="button" class="btn btn-copy" onclick="copyField('api-user', this)">Copy</button>
            </div>
        </div>

        <div class="field-group">
            <label for="api-key">API Key (Token)</label>
            <div class="input-row">
                <input type="text" id="api-key" value="{safe_token}" readonly spellcheck="false">
                <button type="button" class="btn btn-copy" onclick="copyField('api-key', this)">Copy</button>
            </div>
        </div>

        <form method="POST" action="/">
            <button type="submit" class="btn btn-regen" onclick="return confirmRegenerate()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="23 4 23 10 17 10"></polyline>
                    <polyline points="1 20 1 14 7 14"></polyline>
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                </svg>
                Сгенерировать новый ключ
            </button>
        </form>

        <details class="guide-accordion">
            <summary>
                <span>Инструкция по настройке в Obsidian</span>
                <span style="font-size: 11px; opacity: 0.8;">▼</span>
            </summary>
            <div class="guide-content">
                <ol>
                    <li>Установите плагин <strong>LanguageTool Integration</strong> в Obsidian (<em>Настройки → Сторонние плагины</em>).</li>
                    <li>Откройте настройки: <strong>Настройки</strong> → <strong>LanguageTool Integration</strong>.</li>
                    <li>В блоке <strong>Type of connection</strong> выберите вариант <strong>Custom</strong> (Свой сервер).</li>
                    <li>Заполните реквизиты:
                        <ul style="margin-top: 6px; margin-left: 18px; list-style-type: disc;">
                            <li><strong>Server URL</strong>: <code>{safe_url}</code></li>
                            <li><strong>Username</strong>: <code>{safe_user}</code></li>
                            <li><strong>API Key</strong>: скопируйте ключ из поля выше</li>
                        </ul>
                    </li>
                    <li>Нажмите кнопку <strong>Test Connection</strong> для проверки связи. Готово!</li>
                </ol>
            </div>
        </details>

        <div class="card-footer">
            LanguageTool Self-Service Token Portal · Authentik Forward Auth
        </div>
    </div>

    <script>
        function copyField(inputId, btn) {{
            const input = document.getElementById(inputId);
            if (!input) return;
            const text = input.value;
            const originalText = btn.innerText;

            function markCopied() {{
                btn.classList.add('copied');
                btn.innerText = 'Copied!';
                setTimeout(() => {{
                    btn.classList.remove('copied');
                    btn.innerText = originalText;
                }}, 2000);
            }}

            if (navigator.clipboard && window.isSecureContext) {{
                navigator.clipboard.writeText(text).then(markCopied).catch(() => {{
                    fallbackCopy(input, markCopied);
                }});
            }} else {{
                fallbackCopy(input, markCopied);
            }}
        }}

        function fallbackCopy(input, onSuccess) {{
            input.focus();
            input.select();
            input.setSelectionRange(0, 99999);
            try {{
                const successful = document.execCommand('copy');
                if (successful) {{
                    onSuccess();
                }} else {{
                    alert('Не удалось скопировать. Пожалуйста, скопируйте вручную.');
                }}
            }} catch (err) {{
                alert('Не удалось скопировать: ' + err);
            }}
        }}

        function confirmRegenerate() {{
            return confirm(
                'Аннулировать текущий ключ и сгенерировать новый?\\n\\n' +
                'Внимание: старый API-ключ немедленно перестанет действовать в Obsidian!'
            );
        }}
    </script>
</body>
</html>"""


# ==============================================================================
# HTTP Server Handler
# ==============================================================================
class PortalHandler(BaseHTTPRequestHandler):
    """HTTP request handler for LanguageTool token portal."""

    server_version = f"LanguageToolPortal/{VERSION}"

    def log_message(self, format: str, *args: object) -> None:
        """Routes HTTP access logs through Python logging framework."""
        logger.info(
            "%s - %s",
            self.client_address[0],
            format % args,
        )

    def do_GET(self) -> None:
        """Handles healthcheck and token portal interface."""
        if self.path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"OK\n")
            return

        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        raw_user = self.headers.get("X-authentik-username")
        if not raw_user:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = b"401 Unauthorized: Direct access forbidden. Please access this service via Authentik Forward Auth (HAProxy).\n"
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        valid, user_or_err = validate_username(raw_user)
        if not valid:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = f"400 Bad Request: Invalid username format ({user_or_err}).\n".encode("utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        username = user_or_err
        users_file: str = getattr(self.server, "users_file", DEFAULT_USERS_FILE)
        server_url: str = getattr(self.server, "server_url", DEFAULT_SERVER_URL)
        in_place: bool = getattr(self.server, "in_place", DEFAULT_IN_PLACE)

        token = get_or_create_token(users_file, username, in_place=in_place)
        page_bytes = render_portal_html(username, token, server_url).encode("utf-8")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
        self.wfile.write(page_bytes)

    def do_POST(self) -> None:
        """Handles API token regeneration and executes Post/Redirect/Get."""
        if self.path not in ("/", "/regenerate"):
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        raw_user = self.headers.get("X-authentik-username")
        if not raw_user:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = b"401 Unauthorized: Direct access forbidden. Please access this service via Authentik Forward Auth (HAProxy).\n"
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        valid, user_or_err = validate_username(raw_user)
        if not valid:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = f"400 Bad Request: Invalid username format ({user_or_err}).\n".encode("utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        # Drain request body if sent
        content_len = self.headers.get("Content-Length")
        if content_len and content_len.isdigit():
            length = int(content_len)
            if 0 < length <= 65536:
                self.rfile.read(length)

        username = user_or_err
        users_file: str = getattr(self.server, "users_file", DEFAULT_USERS_FILE)
        in_place: bool = getattr(self.server, "in_place", DEFAULT_IN_PLACE)

        regenerate_token(users_file, username, in_place=in_place)

        # 303 See Other redirect pattern
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        """Handles HEAD requests for healthchecks."""
        if self.path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "3")
            self.end_headers()
        else:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed")


# ==============================================================================
# Service & Systemd Management
# ==============================================================================
def generate_systemd_unit(
    exec_path: str,
    host: str,
    port: int,
    users_file: str,
    server_url: str,
    in_place: bool,
    run_as_user: str | None = None,
) -> str:
    """Generates systemd unit file content."""
    args = [
        exec_path,
        f"--host {host}",
        f"--port {port}",
        f"--users-file {users_file}",
        f"--server-url {server_url}",
    ]
    if in_place:
        args.append("--in-place")

    exec_cmd = " \\\n    ".join(args)

    user_directive = f"User={run_as_user}\nGroup={run_as_user}\n" if run_as_user else ""

    return f"""[Unit]
Description=LanguageTool Self-Service Token Portal
Documentation=man:languagetool-portal(1) https://github.com/DanyaNADAMU/scripts
After=network.target

[Service]
Type=simple
{user_directive}ExecStart={exec_cmd}
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""


def setup_systemd_service(
    host: str,
    port: int,
    users_file: str,
    server_url: str,
    in_place: bool,
    force_user: bool,
    force_system: bool,
    run_as: str | None,
) -> None:
    """Installs and enables the systemd service."""
    # Determine binary path
    bin_path = shutil.which("languagetool-portal")
    if not bin_path:
        bin_path = os.path.abspath(__file__)

    is_user_service = False
    if force_user:
        is_user_service = True
    elif force_system:
        is_user_service = False
    else:
        is_user_service = (os.geteuid() != 0)

    if is_user_service:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / f"{SERVICE_NAME}.service"
        unit_content = generate_systemd_unit(
            bin_path, host, port, users_file, server_url, in_place, run_as_user=None
        )
        unit_path.write_text(unit_content, encoding="utf-8")
        print(f"✓ Installed user service: {unit_path}")

        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", f"{SERVICE_NAME}.service"], check=True)
        print(f"✓ Enabled and started user service '{SERVICE_NAME}'.")
        print(f"  Check status: systemctl --user status {SERVICE_NAME}")
    else:
        if os.geteuid() != 0:
            print("Error: System service installation requires root (run with sudo).", file=sys.stderr)
            sys.exit(1)

        unit_dir = Path("/etc/systemd/system")
        unit_path = unit_dir / f"{SERVICE_NAME}.service"
        unit_content = generate_systemd_unit(
            bin_path, host, port, users_file, server_url, in_place, run_as_user=run_as
        )
        unit_path.write_text(unit_content, encoding="utf-8")
        print(f"✓ Installed system service: {unit_path}")

        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", f"{SERVICE_NAME}.service"], check=True)
        print(f"✓ Enabled and started system service '{SERVICE_NAME}'.")
        print(f"  Check status: systemctl status {SERVICE_NAME}")


def remove_systemd_service(force_user: bool, force_system: bool) -> None:
    """Disables and removes the systemd service."""
    is_user_service = False
    if force_user:
        is_user_service = True
    elif force_system:
        is_user_service = False
    else:
        is_user_service = (os.geteuid() != 0)

    if is_user_service:
        unit_path = Path.home() / ".config" / "systemd" / "user" / f"{SERVICE_NAME}.service"
        subprocess.run(["systemctl", "--user", "disable", "--now", f"{SERVICE_NAME}.service"], check=False)
        if unit_path.exists():
            unit_path.unlink()
            print(f"✓ Removed user service unit: {unit_path}")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    else:
        if os.geteuid() != 0:
            print("Error: System service removal requires root (run with sudo).", file=sys.stderr)
            sys.exit(1)
        unit_path = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"
        subprocess.run(["systemctl", "disable", "--now", f"{SERVICE_NAME}.service"], check=False)
        if unit_path.exists():
            unit_path.unlink()
            print(f"✓ Removed system service unit: {unit_path}")
        subprocess.run(["systemctl", "daemon-reload"], check=False)


def check_status(host: str, port: int, users_file: str) -> None:
    """Checks the health and status of the portal."""
    print("=" * 60)
    print(f"LanguageTool Token Portal Status ({host}:{port})")
    print("=" * 60)

    # 1. Check HTTP healthz
    health_url = f"http://{host}:{port}/healthz"
    try:
        import urllib.request
        req = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            status = resp.status
            body = resp.read().decode("utf-8").strip()
            if status == 200 and body == "OK":
                print(f"  HTTP Healthcheck: \033[1;32m[OK]\033[0m ({health_url} responded 200 OK)")
            else:
                print(f"  HTTP Healthcheck: \033[1;33m[WARN]\033[0m ({health_url} responded {status}: {body})")
    except Exception as e:
        print(f"  HTTP Healthcheck: \033[1;31m[FAIL]\033[0m (Cannot connect to {health_url}: {e})")

    # 2. Check users.txt file
    abs_users = os.path.abspath(users_file)
    if os.path.exists(abs_users):
        try:
            stat_info = os.stat(abs_users)
            user_count = 0
            with open(abs_users, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#") and ":" in s:
                        user_count += 1
            print(f"  Users File:       \033[1;32m[EXISTS]\033[0m {abs_users}")
            print(f"  Active Tokens:    {user_count} registered users")
            print(f"  File Mode/Inode:  {oct(stat_info.st_mode & 0o777)} / inode {stat_info.st_ino}")
        except Exception as e:
            print(f"  Users File:       \033[1;33m[ERROR]\033[0m {abs_users} ({e})")
    else:
        print(f"  Users File:       \033[1;33m[NOT CREATED]\033[0m {abs_users} (will be initialized on first user login)")

    # 3. Check systemd unit if systemctl available
    if shutil.which("systemctl"):
        cmd = ["systemctl", "--user", "is-active", f"{SERVICE_NAME}.service"] if os.geteuid() != 0 else ["systemctl", "is-active", f"{SERVICE_NAME}.service"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        active_state = res.stdout.strip()
        print(f"  Systemd Service:  {active_state or 'inactive / not installed'}")
    print("=" * 60)


# ==============================================================================
# CLI Argument Parser
# ==============================================================================
def parse_arguments() -> argparse.Namespace:
    """Builds and returns command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="languagetool-portal",
        description="Lightweight self-service token portal for LanguageTool and Authentik forward auth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Environment Variables:
  LT_PORTAL_HOST    Listening host interface (default: 127.0.0.1)
  LT_PORTAL_PORT    Listening port (default: 8012)
  LT_USERS_FILE     Path to LanguageTool users.txt (default: ~/stacks/languagetool/data/users.txt)
  LT_SERVER_URL     Public LanguageTool endpoint URL (default: https://lt.nada.mu/v2)
  LT_IN_PLACE       Write users.txt in-place without replacing inode (true/false)

Docker / Podman Inode Note:
  If mounting users.txt directly into a container (Volume=.../users.txt:/LanguageTool/users.txt:ro,Z),
  Linux binds to the file's specific inode. Use '--in-place' to prevent atomic rename from breaking
  the container mount.
  Recommended approach: Mount the parent directory instead (Volume=.../data:/LanguageTool/data:ro,Z).
  In that case, the default atomic mode works out-of-the-box and provides maximum crash resilience.
""",
    )

    parser.add_argument(
        "-H", "--host",
        default=DEFAULT_HOST,
        help=f"Bind host address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Bind port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-f", "--users-file",
        default=DEFAULT_USERS_FILE,
        help=f"Path to users.txt (default: {DEFAULT_USERS_FILE})",
    )
    parser.add_argument(
        "-u", "--server-url",
        default=DEFAULT_SERVER_URL,
        help=f"LanguageTool public URL shown in portal UI (default: {DEFAULT_SERVER_URL})",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        default=DEFAULT_IN_PLACE,
        help="Update users.txt in-place with flock to keep inode unchanged (for single-file bind mounts)",
    )
    parser.add_argument(
        "--setup-service",
        action="store_true",
        help="Install, enable, and start systemd service",
    )
    parser.add_argument(
        "--remove-service",
        action="store_true",
        help="Disable, stop, and remove systemd service",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check portal HTTP healthcheck, users file, and systemd status",
    )
    parser.add_argument(
        "--print-service",
        action="store_true",
        help="Print systemd unit file content to stdout and exit",
    )
    parser.add_argument(
        "--user",
        action="store_true",
        help="Force user-level systemd service (~/.config/systemd/user)",
    )
    parser.add_argument(
        "--system",
        action="store_true",
        help="Force system-level systemd service (/etc/systemd/system)",
    )
    parser.add_argument(
        "--run-as",
        default="apps",
        help="User account to run service under when installing system service (default: apps)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser.parse_args()


# ==============================================================================
# Main Entry Point
# ==============================================================================
def main() -> None:
    """Main CLI execution flow."""
    args = parse_arguments()

    users_file = os.path.abspath(os.path.expanduser(args.users_file))

    # Handle service inspection/setup subcommands
    if args.print_service:
        bin_path = shutil.which("languagetool-portal") or os.path.abspath(__file__)
        unit = generate_systemd_unit(
            bin_path,
            args.host,
            args.port,
            users_file,
            args.server_url,
            args.in_place,
            run_as_user=args.run_as if args.system else None,
        )
        print(unit)
        return

    if args.setup_service:
        setup_systemd_service(
            args.host,
            args.port,
            users_file,
            args.server_url,
            args.in_place,
            args.user,
            args.system,
            args.run_as,
        )
        return

    if args.remove_service:
        remove_systemd_service(args.user, args.system)
        return

    if args.status:
        check_status(args.host, args.port, users_file)
        return

    # Start HTTP server
    server = ThreadingHTTPServer((args.host, args.port), PortalHandler)
    # Attach runtime configuration to server instance
    server.users_file = users_file  # type: ignore[attr-defined]
    server.server_url = args.server_url  # type: ignore[attr-defined]
    server.in_place = args.in_place  # type: ignore[attr-defined]

    mode_str = "in-place (preserving inode)" if args.in_place else "atomic (os.replace)"
    logger.info("LanguageTool Token Portal v%s starting up", VERSION)
    logger.info("Listening on: http://%s:%d", args.host, args.port)
    logger.info("Users file:   %s", users_file)
    logger.info("Write mode:   %s", mode_str)
    logger.info("Endpoint URL: %s", args.server_url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received, exiting cleanly...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
