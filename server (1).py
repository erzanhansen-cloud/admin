import os

# Щоб Flask не ліз у .env і не ловив помилку кодування
os.environ["FLASK_SKIP_DOTENV"] = "1"

import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    redirect,
    render_template_string,
    send_from_directory,
    session,
)
from werkzeug.utils import secure_filename

# ----------------- БАЗОВА КОНФІГА -----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db.sqlite3")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")  # куди лягають оновлення
os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "super-secret-local-key"  # поміняй

ADMIN_PIN = "Dev1234"  # PIN для входу в адмінку


# ----------------- ХЕЛПЕРИ БД + ЛОГИ -----------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Таблиця ключів
    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value   TEXT NOT NULL UNIQUE,
        owner       TEXT,
        note        TEXT,
        is_active   INTEGER NOT NULL DEFAULT 1,
        is_banned   INTEGER NOT NULL DEFAULT 0,
        ban_reason  TEXT,
        created_at  TEXT,
        expires_at  TEXT,
        hwid        TEXT
    )
    """)

    # Таблиця активацій (логи входу в лаунчер)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS activations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id          INTEGER,
        key_value       TEXT,
        hwid            TEXT,
        ip              TEXT,
        created_at      TEXT
    )
    """)
    try:
        cur.execute("ALTER TABLE activations ADD COLUMN ip TEXT")
    except sqlite3.OperationalError:
        pass

    # Таблиця оновлень лаунчера
    cur.execute("""
    CREATE TABLE IF NOT EXISTS updates (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        filename    TEXT,
        stored_path TEXT,
        version     TEXT,
        note        TEXT,
        uploaded_at TEXT,
        size_bytes  INTEGER
    )
    """)

    # Промокоди
    cur.execute("""
    CREATE TABLE IF NOT EXISTS promos (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        code        TEXT NOT NULL UNIQUE,
        max_uses    INTEGER NOT NULL,
        used_count  INTEGER NOT NULL DEFAULT 0,
        days_to_add INTEGER NOT NULL,
        note        TEXT,
        is_active   INTEGER NOT NULL DEFAULT 1,
        created_at  TEXT
    )
    """)

    # Конфіг Discord-бота
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bot_config (
        id                  INTEGER PRIMARY KEY CHECK (id = 1),
        token               TEXT,
        base_url            TEXT,
        key_channel_name    TEXT,
        admin_channel_name  TEXT,
        allowed_roles       TEXT,
        is_enabled          INTEGER NOT NULL DEFAULT 0
    )
    """)
    cur.execute("SELECT COUNT(*) FROM bot_config")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO bot_config "
            "(id, token, base_url, key_channel_name, admin_channel_name, allowed_roles, is_enabled) "
            "VALUES (1, NULL, 'http://127.0.0.1:5000', 'vip', 'vip-sliv', 'vip', 0)"
        )

    # Логи адмін-дій (панель + Discord бот)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        actor       TEXT,
        action      TEXT,
        key_id      INTEGER,
        key_value   TEXT,
        details     TEXT,
        ip          TEXT,
        created_at  TEXT
    )
    """)

    conn.commit()
    conn.close()


def rand_key(prefix="FARM-"):
    abc = string.ascii_uppercase + string.digits
    return prefix + "".join(secrets.choice(abc) for _ in range(16))


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def is_expired(row):
    dt = parse_dt(row["expires_at"])
    return bool(dt and datetime.now() > dt)


def get_client_ip():
    ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if not ip:
        ip = request.remote_addr or ""
    return ip


def log_admin_action(actor, action, key_id=None, key_value=None, details=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO admin_logs (actor, action, key_id, key_value, details, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor,
            action,
            key_id,
            key_value,
            details,
            get_client_ip(),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


# ----------------- CSS + ШАБЛОНИ -----------------

BASE_CSS = """
* { box-sizing:border-box; }
body {
    margin:0;
    padding:0;
    font-family: "Segoe UI", system-ui, sans-serif;
    color:#eee;
    background: radial-gradient(circle at top left, #ff6a00 0, #000 55%);
}
.bg-img {
    position:fixed;
    inset:0;
    background:
        linear-gradient(120deg, rgba(0,0,0,0.9), rgba(0,0,0,0.85)),
        url('/static/farmbot_bg.jpg') center/cover no-repeat fixed;
    z-index:-2;
}
.blur-bg {
    position:fixed;
    inset:0;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(3px);
    z-index:-1;
}
h1 {
    text-align:center;
    padding:20px 0 10px 0;
    margin:0;
    font-size:32px;
    color:#ff8c1a;
    letter-spacing:4px;
    text-shadow:0 0 18px #ff7b00;
}
.top-nav {
    max-width:1200px;
    margin:0 auto 16px auto;
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:8px 16px;
    background:rgba(5,8,11,0.9);
    border-radius:12px;
    border:1px solid #20262c;
    box-shadow:0 0 14px rgba(0,0,0,0.7);
}
.nav-links {
    display:flex;
    gap:12px;
    font-size:13px;
}
.nav-links a {
    color:#ffb35c;
    text-decoration:none;
    padding:4px 8px;
    border-radius:6px;
}
.nav-links a.active {
    background:rgba(255,140,26,0.18);
}
.nav-links a:hover {
    background:rgba(255,140,26,0.12);
}
.nav-right { display:flex; gap:8px; }
.panel {
    max-width:1200px;
    margin:0 auto 40px auto;
    background:rgba(5,8,11,0.96);
    border-radius:16px;
    border:1px solid #20262c;
    box-shadow:0 0 26px rgba(0,0,0,0.8);
    padding:20px 24px 24px 24px;
}
.section-title {
    font-size:20px;
    margin:16px 0 8px 0;
    color:#ffb35c;
}
.form-row {
    display:flex;
    flex-wrap:wrap;
    gap:8px;
    align-items:center;
    margin-bottom:10px;
    font-size:14px;
}
label { font-size:13px; color:#aaa; }
input, select {
    padding:6px 8px;
    background:#020509;
    border:1px solid #2b3138;
    color:#f5f5f5;
    border-radius:6px;
    font-size:13px;
    min-width:80px;
}
input:focus {
    outline:none;
    border-color:#ff8c1a;
    box-shadow:0 0 5px #ff8c1a;
}
button {
    border:none;
    border-radius:6px;
    padding:7px 14px;
    font-size:13px;
    cursor:pointer;
    font-weight:600;
}
.btn-main {
    background:linear-gradient(90deg,#ff8c1a,#ff5a0a);
    color:#000;
    text-shadow:0 0 2px rgba(0,0,0,0.5);
}
.btn-main:hover { box-shadow:0 0 12px #ff8c1a; }
.btn-small { padding:5px 9px; font-size:12px; margin:1px 0; }
.btn-danger   { background:#ff3b30; color:#fff; }
.btn-warning  { background:#ffcc00; color:#000; }
.btn-muted    { background:#555; color:#eee; }
table {
    width:100%;
    border-collapse:collapse;
    margin-top:8px;
    font-size:13px;
}
th, td {
    border:1px solid #14181d;
    padding:6px 6px;
    vertical-align:middle;
}
th {
    background:#06090f;
    color:#ffb35c;
    text-align:left;
}
tr:nth-child(even) { background:#070b10; }
.tbl-input {
    width:100%;
    background:#020509;
    border:1px solid #252a31;
    border-radius:4px;
    padding:4px 5px;
    font-size:12px;
    color:#f5f5f5;
}
.tbl-input:focus {
    outline:none;
    border-color:#ff8c1a;
    box-shadow:0 0 6px #ff8c1a;
}
.tbl-checkbox {
    display:flex;
    justify-content:center;
    align-items:center;
}
.actions {
    display:flex;
    flex-direction:column;
    gap:2px;
}
.hint{
    font-size:11px;
    color:#888;
    margin-top:3px;
}
footer{
    text-align:center;
    color:#b5b5b5;
    font-size:12px;
    margin-bottom:20px;
}
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="utf-8">
<title>FarmBot Login</title>
<style>
{{ base_css|safe }}
body {
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
}
.login-box {
    background:#101318;
    padding:24px 26px;
    border-radius:12px;
    width:280px;
    box-shadow:0 0 26px rgba(0,0,0,0.8);
    border:1px solid #262c33;
    text-align:center;
}
.login-box h2{
    margin:0 0 10px 0;
    color:#ffb35c;
}
input {
    width:100%;
    padding:9px 10px;
    background:#020509;
    border:1px solid #2b3138;
    color:#ffb35c;
    border-radius:6px;
    margin-top:10px;
}
button {
    margin-top:14px;
    width:100%;
    padding:9px 10px;
    border:none;
    border-radius:6px;
    font-weight:600;
    cursor:pointer;
    background:linear-gradient(90deg,#ff8c1a,#ff5a0a);
    color:#000;
}
.error{
    margin-top:8px;
    color:#ff4d4f;
    font-size:12px;
}
.hint{
    margin-top:8px;
    color:#888;
    font-size:11px;
}
</style>
</head>
<body>
<div class="bg-img"></div>
<div class="blur-bg"></div>

<div class="login-box">
    <h2>FARMBOT PANEL</h2>
    <form method="post">
        <input type="password" name="pin" placeholder="PIN" autofocus>
        <button type="submit">Увійти</button>
    </form>
    {% if error %}
    <div class="error">{{error}}</div>
    {% endif %}
    <div class="hint">Введи PIN для входу в адмін-панель (міняється в server.py).</div>
</div>
</body>
</html>
"""

KEYS_HTML = """
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<title>FARMBOT CONTROL PANEL – Keys</title>
<style>
{{ base_css|safe }}
.logs-table th, .logs-table td {
    font-size:12px;
    padding:4px 5px;
}
</style>
</head>
<body>
<div class="bg-img"></div>
<div class="blur-bg"></div>

<h1>FARMBOT CONTROL PANEL</h1>

<div class="top-nav">
    <div class="nav-links">
        <a href="/" class="{{ 'active' if active_tab=='keys' else '' }}">Ключі</a>
        <a href="/updates" class="{{ 'active' if active_tab=='updates' else '' }}">Залив оновлення</a>
        <a href="/bot" class="{{ 'active' if active_tab=='bot' else '' }}">Discord бот</a>
    </div>
    <div class="nav-right">
        <form method="get" action="/download_latest">
            <button class="btn-main btn-small" type="submit">Скачати останню версію</button>
        </form>
        <form method="get" action="/logout">
            <button class="btn-muted btn-small" type="submit">Вийти</button>
        </form>
    </div>
</div>

<div class="panel">

    <div class="section-title">Генерація ключів</div>
    <form method="post" action="/gen_keys">
        <div class="form-row">
            <label>Префікс</label>
            <input name="prefix" value="FARM-" style="max-width:90px;">
            <label>Кількість</label>
            <input type="number" name="count" min="1" max="500" value="5" style="max-width:80px;">
            <label>TTL (днів, 0 = без)</label>
            <input type="number" name="days" min="0" max="365" value="0" style="max-width:80px;">
            <button type="submit" class="btn-main">Згенерувати</button>
        </div>
    </form>

    <div class="section-title">Ключі (редагування як в БД)</div>
    <div class="hint">
        Всі поля окрім ID можна міняти. ID краще не чіпати (це первинний ключ).
        Для своєї нумерації використовуй поле <b>Note</b>.
    </div>

    <table>
        <tr>
            <th style="width:40px;">ID</th>
            <th style="width:210px;">Key</th>
            <th>Owner</th>
            <th>Note</th>
            <th style="width:80px;">Active</th>
            <th style="width:80px;">Banned</th>
            <th>Reason</th>
            <th style="width:150px;">Expires</th>
            <th style="width:160px;">HWID</th>
            <th style="width:200px;">Дії</th>
        </tr>

        {% for k in keys %}
        <tr>
            <form id="f{{k.id}}" method="post" action="/key/update/{{k.id}}"></form>

            <td>{{k.id}}</td>

            <td>
                <input class="tbl-input" name="key_value" form="f{{k.id}}" value="{{k.key_value}}">
            </td>

            <td>
                <input class="tbl-input" name="owner" form="f{{k.id}}" value="{{k.owner or ''}}">
            </td>

            <td>
                <input class="tbl-input" name="note" form="f{{k.id}}" value="{{k.note or ''}}">
            </td>

            <td class="tbl-checkbox">
                <input type="checkbox" name="is_active" value="1" form="f{{k.id}}" {% if k.is_active %}checked{% endif %}>
            </td>

            <td class="tbl-checkbox">
                <input type="checkbox" name="is_banned" value="1" form="f{{k.id}}" {% if k.is_banned %}checked{% endif %}>
            </td>

            <td>
                <input class="tbl-input" name="ban_reason" form="f{{k.id}}" value="{{k.ban_reason or ''}}">
            </td>

            <td>
                <input class="tbl-input" name="expires_at" form="f{{k.id}}" placeholder="YYYY-MM-DD HH:MM:SS" value="{{k.expires_at or ''}}">
            </td>

            <td>
                <input class="tbl-input" name="hwid" form="f{{k.id}}" value="{{k.hwid or ''}}">
            </td>

            <td>
                <div class="actions">
                    <button class="btn-main btn-small" form="f{{k.id}}">Save</button>
                    <form method="post" action="/key/ban/{{k.id}}" style="display:inline;">
                        <button class="btn-danger btn-small" type="submit">Ban</button>
                    </form>
                    <form method="post" action="/key/unban/{{k.id}}" style="display:inline;">
                        <button class="btn-warning btn-small" type="submit">Unban</button>
                    </form>
                    <form method="post" action="/key/clear_hwid/{{k.id}}" style="display:inline;">
                        <button class="btn-muted btn-small" type="submit">Clear HWID</button>
                    </form>
                    <form method="post" action="/key/delete/{{k.id}}" style="display:inline;">
                        <button class="btn-muted btn-small" type="submit">Del</button>
                    </form>
                </div>
            </td>
        </tr>
        {% endfor %}
    </table>

    <div class="section-title" style="margin-top:24px;">Логи активацій (HWID + IP)</div>
    <div class="hint">
        Останні активації лаунчера: який ключ, HWID і з якого IP.
    </div>

    <table class="logs-table">
        <tr>
            <th style="width:40px;">ID</th>
            <th style="width:210px;">Key</th>
            <th style="width:200px;">HWID</th>
            <th style="width:140px;">IP</th>
            <th style="width:170px;">Дата</th>
        </tr>
        {% for a in activations %}
        <tr>
            <td>{{a.id}}</td>
            <td>{{a.key_value}}</td>
            <td>{{a.hwid or ''}}</td>
            <td>{{a.ip or ''}}</td>
            <td>{{a.created_at}}</td>
        </tr>
        {% endfor %}
    </table>

</div>

<footer>
VOVK DEV SYNDICATE • FarmBot DB-style panel + activation logs
</footer>

</body>
</html>
"""

UPDATES_HTML = """
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<title>FARMBOT CONTROL PANEL – Updates</title>
<style>
{{ base_css|safe }}
.logs-table th, .logs-table td {
    font-size:12px;
    padding:4px 5px;
}
.logs-header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
}
.logs-search-form {
    display:flex;
    align-items:center;
    gap:6px;
    font-size:12px;
}
</style>
</head>
<body>
<div class="bg-img"></div>
<div class="blur-bg"></div>

<h1>FARMBOT CONTROL PANEL</h1>

<div class="top-nav">
    <div class="nav-links">
        <a href="/" class="{{ 'active' if active_tab=='keys' else '' }}">Ключі</a>
        <a href="/updates" class="{{ 'active' if active_tab=='updates' else '' }}">Залив оновлення</a>
        <a href="/bot" class="{{ 'active' if active_tab=='bot' else '' }}">Discord бот</a>
    </div>
    <div class="nav-right">
        <form method="get" action="/download_latest">
            <button class="btn-main btn-small" type="submit">Скачати останню версію</button>
        </form>
        <form method="get" action="/logout">
            <button class="btn-muted btn-small" type="submit">Вийти</button>
        </form>
    </div>
</div>

<div class="panel">

    <div class="section-title">Оновлення лаунчера</div>
    <div class="hint">Заливаєш .exe/.zip → файл летить у <code>storage/</code> + пишеться лог, як в phpMyAdmin.</div>

    <form method="post" action="/upload_update" enctype="multipart/form-data">
        <div class="form-row">
            <label>Файл лаунчера</label>
            <input type="file" name="file" required>
            <label>Версія</label>
            <input type="text" name="version" placeholder="наприклад 1.3.2">
            <label>Коментар</label>
            <input type="text" name="note" placeholder="що змінилось">
            <button type="submit" class="btn-main">Залити оновлення</button>
        </div>
    </form>

    <div class="section-title">Логи оновлень (phpMyAdmin style)</div>

    <div class="logs-header">
        <div class="hint">Можеш шукати по назві файлу, версії або коментарю.</div>
        <form class="logs-search-form" method="get" action="/updates">
            <input type="text" name="q" placeholder="пошук по логам" value="{{q or ''}}">
            <button class="btn-main btn-small" type="submit">Шукати</button>
        </form>
    </div>

    <table class="logs-table">
        <tr>
            <th style="width:40px;">ID</th>
            <th style="width:160px;">Дата</th>
            <th>Файл</th>
            <th style="width:100px;">Версія</th>
            <th style="width:110px;">Розмір (MB)</th>
            <th>Коментар</th>
        </tr>
        {% for u in updates %}
        <tr>
            <td>{{u.id}}</td>
            <td>{{u.uploaded_at}}</td>
            <td>{{u.filename}}</td>
            <td>{{u.version or '-'}}</td>
            <td>{{"%.2f"|format((u.size_bytes or 0)/1024/1024)}}</td>
            <td>{{u.note or ''}}</td>
        </tr>
        {% endfor %}
    </table>

</div>

<footer>
VOVK DEV SYNDICATE • FarmBot Updates logs
</footer>

</body>
</html>
"""

BOT_HTML = """
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<title>FARMBOT CONTROL PANEL – Discord Bot</title>
<style>
{{ base_css|safe }}
.form-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px;font-size:14px;}
textarea{width:100%;min-height:70px;background:#020509;border:1px solid #2b3138;color:#f5f5f5;border-radius:6px;font-size:13px;padding:6px 8px;}
.logs-table th, .logs-table td {
    font-size:12px;
    padding:4px 5px;
}
</style>
</head>
<body>
<div class="bg-img"></div>
<div class="blur-bg"></div>

<h1>FARMBOT CONTROL PANEL</h1>

<div class="top-nav">
    <div class="nav-links">
        <a href="/" class="{{ 'active' if active_tab=='keys' else '' }}">Ключі</a>
        <a href="/updates" class="{{ 'active' if active_tab=='updates' else '' }}">Залив оновлення</a>
        <a href="/bot" class="{{ 'active' if active_tab=='bot' else '' }}">Discord бот</a>
    </div>
    <div class="nav-right">
        <form method="get" action="/download_latest">
            <button class="btn-main btn-small" type="submit">Скачати останню версію</button>
        </form>
        <form method="get" action="/logout">
            <button class="btn-muted btn-small" type="submit">Вийти</button>
        </form>
    </div>
</div>

<div class="panel">
    <div class="section-title">Discord бот – конфігурація</div>
    <div class="hint">
        Токен зберігається в БД, через сайт лише записується/оновлюється.
        Поточний токен не показується (щоб не світився).
    </div>

    <form method="post" action="/bot">
        <div class="form-row">
            <label><input type="checkbox" name="is_enabled" value="1" {% if cfg.is_enabled %}checked{% endif %}> Увімкнути бота</label>
        </div>

        <div class="form-row">
            <label style="width:100%;">Новий токен (якщо залишиш пустим – токен не зміниться)</label>
            <input name="token" type="password" style="width:100%;" placeholder="Paste Discord bot token тут">
        </div>

        <div class="form-row">
            <label>Base URL панелі</label>
            <input name="base_url" value="{{ cfg.base_url }}" style="min-width:260px;">
        </div>

        <div class="form-row">
            <label>Канал для !getkey</label>
            <input name="key_channel_name" value="{{ cfg.key_channel_name }}" style="min-width:160px;">
            <label>Адмін-канал</label>
            <input name="admin_channel_name" value="{{ cfg.admin_channel_name }}" style="min-width:160px;">
        </div>

        <div class="form-row" style="width:100%;flex-direction:column;align-items:flex-start;">
            <label>Дозволені ролі (через кому, напр. <code>vip,vip+</code>)</label>
            <input name="allowed_roles" value="{{ cfg.allowed_roles or '' }}" style="width:100%;">
        </div>

        <button type="submit" class="btn-main">Зберегти конфіг</button>
    </form>

    <div class="hint" style="margin-top:14px;">
        Бот при старті звертається до <code>/api/ds/bot/config</code> і бере звідти токен та інші параметри.
        Просто перезапусти процес бота після зміни конфіга.
    </div>

    <div class="section-title" style="margin-top:24px;">Логи дій бота / панелі</div>
    <div class="hint">
        Тут видно всі дії з ключами, які йдуть через Discord-бота / API / панель.
    </div>

    <table class="logs-table">
        <tr>
            <th style="width:40px;">ID</th>
            <th style="width:160px;">Дата</th>
            <th style="width:140px;">Actor</th>
            <th style="width:130px;">Action</th>
            <th style="width:180px;">Key</th>
            <th>Details</th>
            <th style="width:120px;">IP</th>
        </tr>
        {% for l in logs %}
        <tr>
            <td>{{l.id}}</td>
            <td>{{l.created_at}}</td>
            <td>{{l.actor or ''}}</td>
            <td>{{l.action or ''}}</td>
            <td>{{l.key_value or ''}}</td>
            <td>{{l.details or ''}}</td>
            <td>{{l.ip or ''}}</td>
        </tr>
        {% endfor %}
    </table>

</div>

<footer>
VOVK DEV SYNDICATE • Discord bot config + logs
</footer>

</body>
</html>
"""


# ----------------- АВТОРИЗАЦІЯ -----------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authed"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        pin = (request.form.get("pin") or "").strip()
        if pin == ADMIN_PIN:
            session["admin_authed"] = True
            return redirect("/")
        else:
            error = "Неправильний PIN"
    return render_template_string(LOGIN_HTML, base_css=BASE_CSS, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ----------------- ROUTES: ПАНЕЛЬ -----------------

@app.route("/")
@login_required
def panel_index():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys ORDER BY id DESC")
    keys = cur.fetchall()

    cur.execute(
        "SELECT id, key_value, hwid, ip, created_at "
        "FROM activations ORDER BY id DESC LIMIT 200"
    )
    activations = cur.fetchall()
    conn.close()

    return render_template_string(
        KEYS_HTML,
        keys=keys,
        activations=activations,
        base_css=BASE_CSS,
        active_tab="keys",
    )


@app.route("/updates")
@login_required
def updates_page():
    q = (request.args.get("q") or "").strip()
    conn = get_db()
    cur = conn.cursor()

    if q:
        pattern = f"%{q}%"
        cur.execute(
            """
            SELECT * FROM updates
            WHERE filename LIKE ? OR version LIKE ? OR note LIKE ?
            ORDER BY uploaded_at DESC, id DESC
            LIMIT 200
            """,
            (pattern, pattern, pattern),
        )
    else:
        cur.execute(
            "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 200"
        )
    updates = cur.fetchall()
    conn.close()

    return render_template_string(
        UPDATES_HTML,
        updates=updates,
        q=q,
        base_css=BASE_CSS,
        active_tab="updates",
    )


@app.route("/bot", methods=["GET", "POST"])
@login_required
def bot_config_page():
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        is_enabled = 1 if request.form.get("is_enabled") == "1" else 0
        base_url = (request.form.get("base_url") or "").strip() or "http://127.0.0.1:5000"
        key_channel_name = (request.form.get("key_channel_name") or "").strip() or "vip"
        admin_channel_name = (request.form.get("admin_channel_name") or "").strip() or "vip-sliv"
        allowed_roles = (request.form.get("allowed_roles") or "").strip()
        new_token = (request.form.get("token") or "").strip()

        if new_token:
            cur.execute(
                """
                UPDATE bot_config
                SET token=?, base_url=?, key_channel_name=?, admin_channel_name=?, allowed_roles=?, is_enabled=?
                WHERE id=1
                """,
                (new_token, base_url, key_channel_name, admin_channel_name, allowed_roles, is_enabled),
            )
        else:
            cur.execute(
                """
                UPDATE bot_config
                SET base_url=?, key_channel_name=?, admin_channel_name=?, allowed_roles=?, is_enabled=?
                WHERE id=1
                """,
                (base_url, key_channel_name, admin_channel_name, allowed_roles, is_enabled),
            )
        conn.commit()

    cur.execute("SELECT * FROM bot_config WHERE id=1")
    cfg = cur.fetchone()

    cur.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 300")
    logs = cur.fetchall()

    conn.close()

    return render_template_string(
        BOT_HTML,
        base_css=BASE_CSS,
        cfg=cfg,
        logs=logs,
        active_tab="bot",
    )


@app.route("/gen_keys", methods=["POST"])
@login_required
def panel_gen_keys():
    prefix = (request.form.get("prefix") or "FARM-").strip() or "FARM-"
    try:
        count = int(request.form.get("count") or "1")
    except ValueError:
        count = 1
    try:
        days = int(request.form.get("days") or "0")
    except ValueError:
        days = 0

    count = max(1, min(500, count))
    days = max(0, min(365, days))

    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = None
    if days > 0:
        expires_at = (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    for _ in range(count):
        key_value = rand_key(prefix)
        try:
            cur.execute(
                "INSERT INTO keys (key_value, is_active, is_banned, created_at, expires_at) "
                "VALUES (?,1,0,?,?)",
                (key_value, created_at, expires_at),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    log_admin_action("panel", "gen_keys", None, None, f"prefix={prefix}, count={count}, days={days}")
    return redirect("/")


@app.route("/key/update/<int:key_id>", methods=["POST"])
@login_required
def panel_key_update(key_id):
    form = request.form

    key_value = (form.get("key_value") or "").strip()
    owner = (form.get("owner") or "").strip()
    note = (form.get("note") or "").strip()
    ban_reason = (form.get("ban_reason") or "").strip()
    expires_at = (form.get("expires_at") or "").strip()
    hwid = (form.get("hwid") or "").strip()

    is_active = 1 if form.get("is_active") == "1" else 0
    is_banned = 1 if form.get("is_banned") == "1" else 0

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE keys
        SET key_value=?,
            owner=?,
            note=?,
            is_active=?,
            is_banned=?,
            ban_reason=?,
            expires_at=?,
            hwid=?
        WHERE id=?
        """,
        (key_value, owner, note, is_active, is_banned, ban_reason, expires_at, hwid, key_id),
    )
    conn.commit()
    conn.close()

    log_admin_action("panel", "update_key", key_id, key_value, f"owner={owner}, note={note}")
    return redirect("/")


@app.route("/key/ban/<int:key_id>", methods=["POST"])
@login_required
def panel_key_ban(key_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key_value FROM keys WHERE id=?", (key_id,))
    row = cur.fetchone()
    key_val = row["key_value"] if row else None

    cur.execute(
        "UPDATE keys SET is_banned=1, ban_reason='panel ban' WHERE id=?",
        (key_id,),
    )
    conn.commit()
    conn.close()

    log_admin_action("panel", "ban_key", key_id, key_val, "panel ban")
    return redirect("/")


@app.route("/key/unban/<int:key_id>", methods=["POST"])
@login_required
def panel_key_unban(key_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key_value FROM keys WHERE id=?", (key_id,))
    row = cur.fetchone()
    key_val = row["key_value"] if row else None

    cur.execute(
        "UPDATE keys SET is_banned=0, ban_reason=NULL WHERE id=?",
        (key_id,),
    )
    conn.commit()
    conn.close()

    log_admin_action("panel", "unban_key", key_id, key_val, None)
    return redirect("/")


@app.route("/key/clear_hwid/<int:key_id>", methods=["POST"])
@login_required
def panel_key_clear_hwid(key_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key_value FROM keys WHERE id=?", (key_id,))
    row = cur.fetchone()
    key_val = row["key_value"] if row else None

    cur.execute("UPDATE keys SET hwid=NULL WHERE id=?", (key_id,))
    conn.commit()
    conn.close()

    log_admin_action("panel", "clear_hwid", key_id, key_val, None)
    return redirect("/")


@app.route("/key/delete/<int:key_id>", methods=["POST"])
@login_required
def panel_key_delete(key_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key_value FROM keys WHERE id=?", (key_id,))
    row = cur.fetchone()
    key_val = row["key_value"] if row else None

    cur.execute("DELETE FROM keys WHERE id=?", (key_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    log_admin_action("panel", "delete_key", key_id, key_val, f"deleted={deleted}")
    return redirect("/")


@app.route("/upload_update", methods=["POST"])
@login_required
def upload_update():
    file = request.files.get("file")
    if not file or file.filename == "":
        return redirect("/updates")

    version = (request.form.get("version") or "").strip()
    note = (request.form.get("note") or "").strip()

    safe_name = secure_filename(file.filename)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_name = f"{ts}_{safe_name}"
    stored_path = os.path.join(STORAGE_DIR, stored_name)
    file.save(stored_path)
    size_bytes = os.path.getsize(stored_path)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO updates (filename, stored_path, version, note, uploaded_at, size_bytes) "
        "VALUES (?,?,?,?,?,?)",
        (
            safe_name,
            stored_name,
            version,
            note,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            size_bytes,
        ),
    )
    conn.commit()
    conn.close()

    log_admin_action("panel", "upload_update", None, None, f"file={safe_name}, version={version}")
    return redirect("/updates")


@app.route("/download_latest")
@login_required
def download_latest():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 1"
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return redirect("/updates")

    return send_from_directory(
        STORAGE_DIR,
        row["stored_path"],
        as_attachment=True,
        download_name=row["filename"],
    )


# ----------------- PUBLIC API (лаунчер / бот) -----------------

@app.route("/api/get_key")
def api_get_key():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM keys
        WHERE is_active=1 AND is_banned=0 AND (owner IS NULL OR owner='')
        ORDER BY id ASC
    """)
    rows = cur.fetchall()

    chosen = None
    for r in rows:
        if not is_expired(r):
            chosen = r
            break

    if not chosen:
        conn.close()
        return jsonify({"ok": False, "error": "no_free_keys"}), 404

    user = request.args.get("user") or ""
    uid = request.args.get("uid") or ""
    owner = f"ds:{user}:{uid}"[:200]

    cur.execute("UPDATE keys SET owner=? WHERE id=?", (owner, chosen["id"]))
    conn.commit()
    conn.close()

    log_admin_action(f"ds:auto", "get_key", chosen["id"], chosen["key_value"], f"user={owner}")
    return jsonify({"ok": True, "key": chosen["key_value"]})


@app.route("/api/check_key", methods=["POST"])
def api_check_key():
    data = request.get_json(silent=True) or request.form
    key_value = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not key_value or not hwid:
        return jsonify({"ok": False, "reason": "missing"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys WHERE key_value=?", (key_value,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "reason": "not_found"})

    if not row["is_active"]:
        conn.close()
        return jsonify({"ok": False, "reason": "inactive"})

    if row["is_banned"]:
        conn.close()
        return jsonify({"ok": False, "reason": "banned"})

    if is_expired(row):
        conn.close()
        return jsonify({"ok": False, "reason": "expired"})

    saved_hwid = row["hwid"] or ""
    if saved_hwid and saved_hwid != hwid:
        conn.close()
        return jsonify({"ok": False, "reason": "hwid_mismatch"})

    ip = get_client_ip()

    if not saved_hwid:
        cur.execute("UPDATE keys SET hwid=? WHERE id=?", (hwid, row["id"]))
        conn.commit()

    cur.execute(
        "INSERT INTO activations (key_id, key_value, hwid, ip, created_at) VALUES (?,?,?,?,?)",
        (
            row["id"],
            row["key_value"],
            hwid,
            ip,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "reason": "ok"})


# ----------------- DS ADMIN API: KEYS -----------------

@app.route("/api/ds/key/info")
def ds_key_info():
    key = (request.args.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys WHERE key_value=?", (key,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "not_found"}), 404

    return jsonify({"ok": True, "key": {k: row[k] for k in row.keys()}})


@app.route("/api/ds/key/ban", methods=["POST"])
def ds_key_ban():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    reason = (data.get("reason") or "ban from discord").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM keys WHERE key_value=?", (key,))
    r = cur.fetchone()
    key_id = r["id"] if r else None

    cur.execute(
        "UPDATE keys SET is_banned=1, ban_reason=? WHERE key_value=?",
        (reason, key),
    )
    conn.commit()
    conn.close()

    log_admin_action(actor, "ban_key", key_id, key, reason)
    return jsonify({"ok": True})


@app.route("/api/ds/key/unban", methods=["POST"])
def ds_key_unban():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM keys WHERE key_value=?", (key,))
    r = cur.fetchone()
    key_id = r["id"] if r else None

    cur.execute(
        "UPDATE keys SET is_banned=0, ban_reason=NULL WHERE key_value=?",
        (key,),
    )
    conn.commit()
    conn.close()

    log_admin_action(actor, "unban_key", key_id, key, None)
    return jsonify({"ok": True})


@app.route("/api/ds/key/toggle", methods=["POST"])
def ds_key_toggle():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, is_active FROM keys WHERE key_value=?", (key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404
    new_state = 0 if row["is_active"] else 1
    cur.execute("UPDATE keys SET is_active=? WHERE key_value=?", (new_state, key))
    conn.commit()
    conn.close()

    log_admin_action(actor, "toggle_key", row["id"], key, f"is_active={new_state}")
    return jsonify({"ok": True, "is_active": bool(new_state)})


@app.route("/api/ds/key/extend", methods=["POST"])
def ds_key_extend():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    try:
        days = int(data.get("days") or "0")
    except ValueError:
        days = 0
    if not key or days <= 0:
        return jsonify({"ok": False, "error": "bad params"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys WHERE key_value=?", (key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    base = parse_dt(row["expires_at"]) or datetime.now()
    new_exp = (base + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE keys SET expires_at=? WHERE key_value=?", (new_exp, key))
    conn.commit()
    conn.close()

    log_admin_action(actor, "extend_key", row["id"], key, f"+{days}d -> {new_exp}")
    return jsonify({"ok": True, "new_expires_at": new_exp})


@app.route("/api/ds/key/clear_hwid", methods=["POST"])
def ds_key_clear_hwid():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM keys WHERE key_value=?", (key,))
    r = cur.fetchone()
    key_id = r["id"] if r else None

    cur.execute("UPDATE keys SET hwid=NULL WHERE key_value=?", (key,))
    conn.commit()
    conn.close()

    log_admin_action(actor, "clear_hwid", key_id, key, None)
    return jsonify({"ok": True})


@app.route("/api/ds/key/delete", methods=["POST"])
def ds_key_delete():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM keys WHERE key_value=?", (key,))
    r = cur.fetchone()
    key_id = r["id"] if r else None

    cur.execute("DELETE FROM keys WHERE key_value=?", (key,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    log_admin_action(actor, "delete_key", key_id, key, f"deleted={deleted}")
    return jsonify({"ok": True, "deleted": deleted})


@app.route("/api/ds/key/create", methods=["POST"])
def ds_key_create():
    data = request.get_json(silent=True) or request.form
    key = (data.get("key") or "").strip()
    owner = (data.get("owner") or "").strip()
    note = (data.get("note") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    try:
        days = int(data.get("days") or "0")
    except ValueError:
        days = 0

    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = None
    if days > 0:
        expires_at = (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO keys (key_value, owner, note, is_active, is_banned, created_at, expires_at)
            VALUES (?, ?, ?, 1, 0, ?, ?)
            """,
            (key, owner, note, created_at, expires_at),
        )
        key_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "key_exists"}), 400

    conn.close()
    log_admin_action(actor, "create_key", key_id, key, f"owner={owner}, note={note}, days={days}")
    return jsonify({"ok": True, "id": key_id})


@app.route("/api/ds/key/generate", methods=["POST"])
def ds_key_generate():
    data = request.get_json(silent=True) or request.form
    try:
        count = int(data.get("count") or "1")
    except ValueError:
        count = 1
    prefix = (data.get("prefix") or "FARM-").strip() or "FARM-"
    try:
        days = int(data.get("days") or "0")
    except ValueError:
        days = 0
    actor = (data.get("actor") or "ds_api").strip()

    count = max(1, min(500, count))
    days = max(0, min(365, days))

    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = None
    if days > 0:
        expires_at = (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    res_keys = []
    for _ in range(count):
        key_value = rand_key(prefix)
        try:
            cur.execute(
                """
                INSERT INTO keys (key_value, is_active, is_banned, created_at, expires_at)
                VALUES (?,1,0,?,?)
                """,
                (key_value, created_at, expires_at),
            )
            res_keys.append(key_value)
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    log_admin_action(actor, "generate_keys", None, None, f"prefix={prefix}, count={count}, days={days}")
    return jsonify({"ok": True, "keys": res_keys})


# ----------------- DS ADMIN API: PROMO -----------------

@app.route("/api/ds/promo/create", methods=["POST"])
def ds_promo_create():
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    try:
        max_uses = int(data.get("max_uses") or "0")
        days_to_add = int(data.get("days_to_add") or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "bad params"}), 400
    note = (data.get("note") or "").strip()

    if not code or max_uses <= 0 or days_to_add <= 0:
        return jsonify({"ok": False, "error": "bad params"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO promos (code, max_uses, days_to_add, note, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (code, max_uses, days_to_add, note, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),

        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "code_exists"}), 400

    conn.close()
    log_admin_action(actor, "create_promo", None, None, f"code={code}, uses={max_uses}, days={days_to_add}")
    return jsonify({"ok": True})


@app.route("/api/ds/promo/toggle", methods=["POST"])
def ds_promo_toggle():
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not code:
        return jsonify({"ok": False, "error": "missing code"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM promos WHERE code=?", (code,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    new_state = 0 if row["is_active"] else 1
    cur.execute("UPDATE promos SET is_active=? WHERE code=?", (new_state, code))
    conn.commit()
    conn.close()

    log_admin_action(actor, "toggle_promo", None, None, f"code={code}, is_active={new_state}")
    return jsonify({"ok": True, "is_active": bool(new_state)})


@app.route("/api/ds/promo/delete", methods=["POST"])
def ds_promo_delete():
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or "").strip()
    actor = (data.get("actor") or "ds_api").strip()
    if not code:
        return jsonify({"ok": False, "error": "missing code"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM promos WHERE code=?", (code,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    log_admin_action(actor, "delete_promo", None, None, f"code={code}, deleted={deleted}")
    return jsonify({"ok": True, "deleted": deleted})


# ----------------- DS ADMIN API: STATS -----------------

@app.route("/api/ds/stats")
def ds_stats():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM keys")
    total_keys = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM keys WHERE is_active=1")
    active_keys = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM keys WHERE is_banned=1")
    banned_keys = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM keys WHERE owner IS NOT NULL AND owner!=''")
    used_keys = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM activations")
    total_activations = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT hwid) FROM activations")
    unique_hwids = cur.fetchone()[0]
    conn.close()

    return jsonify(
        {
            "ok": True,
            "total_keys": total_keys,
            "active_keys": active_keys,
            "banned_keys": banned_keys,
            "used_keys": used_keys,
            "total_activations": total_activations,
            "unique_hwids": unique_hwids,
        }
    )


# ----------------- API ЛОГІВ ВІД БОТА -----------------

@app.route("/api/ds/log", methods=["POST"])
def ds_log():
    """Універсальний лог для Discord-бота / інших сервісів."""
    data = request.get_json(silent=True) or request.form
    actor = (data.get("actor") or "ds_api").strip()
    action = (data.get("action") or "info").strip()
    key_value = (data.get("key_value") or "").strip() or None
    details = (data.get("details") or "").strip() or None

    key_id = None
    if key_value:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM keys WHERE key_value=?", (key_value,))
        r = cur.fetchone()
        conn.close()
        if r:
            key_id = r["id"]

    log_admin_action(actor, action, key_id, key_value, details)
    return jsonify({"ok": True})


# ----------------- API ДЛЯ БОТА: КОНФІГ -----------------

@app.route("/api/ds/bot/config")
def api_bot_config():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM bot_config WHERE id=1")
    cfg = cur.fetchone()
    conn.close()

    if not cfg or not cfg["is_enabled"]:
        return jsonify({"ok": False, "error": "bot_disabled"}), 400

    roles_raw = cfg["allowed_roles"] or ""
    roles = [r.strip() for r in roles_raw.split(",") if r.strip()]

    return jsonify(
        {
            "ok": True,
            "token": cfg["token"] or "",
            "base_url": cfg["base_url"] or "http://127.0.0.1:5000",
            "key_channel_name": cfg["key_channel_name"] or "vip",
            "admin_channel_name": cfg["admin_channel_name"] or "vip-sliv",
            "allowed_roles": roles,
        }
    )


# ----------------- RUN -----------------

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"SERVER STARTED on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
