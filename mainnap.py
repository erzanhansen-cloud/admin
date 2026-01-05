import os
import json
import sqlite3
import secrets
import string
import hashlib
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
import urllib.request

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




# =========================
# CONFIG (NO ENV)
# =========================

APP_SECRET = "AdminGatylo"          # для flask session (будь-який довгий)
ADMIN_PIN = "Dev1234"              # перший пін, тільки для першого входу (потім буде з БД)

RUNNING_WINDOW_SEC = 90
ACTIVATION_LOG_COOLDOWN_SEC = 600

# --- BOT CONTROL API секрет (має співпадати з ботом 1:1) ---
BOT_API_SECRET = "Dev1234"

# --- optional webhook from server -> bot (можеш НЕ юзати взагалі) ---
BOT_ACTIVATION_HOOK_URL = ""       # лишай пустим
BOT_HOOK_SECRET = "CHANGE_ME_SUPER_SECRET"  # лишай як є (не використовується якщо URL пустий)

# --- Discord logging webhooks (вставив твої) ---
DISCORD_WEBHOOK_ACTIVATIONS = "https://discord.com/api/webhooks/1457747485081731207/H1lxtguaXHk8kyHuFyyIJKfcGwfGnglbgfw5F_tQlBqm1yQYOYRzQfP4v11R1xyEw8pj"
DISCORD_WEBHOOK_LAUNCHER     = "https://discord.com/api/webhooks/1457747799167992004/ebGQI7td9BXZ5xInJ3wa6AJxmGestA1ZXb-hSTVwgi3Wm0xdwvGlOoG9pZan1QtjdAXF"
DISCORD_WEBHOOK_ADMIN        = "https://discord.com/api/webhooks/1457747886421840007/ZDHzyIJ4TaVFTG8KrxcnqhNP7tjD5GnySXPZXru4r-ca22bYWVp8uqX7dnRFT5mKnEb6"

# --- bootstrap admin (твій discord id) ---
BOOTSTRAP_DISCORD_ADMIN_ID = "1185724094734405735"



# =========================
# PATHS (LOCAL)
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "db.sqlite3")
STORAGE_DIR = os.path.join(DATA_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)


# =========================
# APP
# =========================

app = Flask(__name__)
app.secret_key = APP_SECRET


# =========================
# HEALTH CHECK
# =========================
@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


# =========================
# TIME / DB HELPERS
# =========================

def kyiv_now():
    return datetime.now(KYIV_TZ)

def now_value():
    # ✅ ЧИСТИЙ Київський час, БЕЗ +0200
    return kyiv_now().strftime("%Y-%m-%d %H:%M:%S")

def parse_dt(x):
    if not x:
        return None
    try:
        return datetime.strptime(str(x), "%Y-%m-%d %H:%M:%S").replace(tzinfo=KYIV_TZ)
    except ValueError:
        return None

def is_expired_row(expires_at) -> bool:
    if not expires_at:
        return False
    dt = parse_dt(expires_at)
    return bool(dt and kyiv_now() > dt)

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=8000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def db_execute(cur, sql: str, params=()):
    return cur.execute(sql, params)

def db_fetchone(cur, sql: str, params=()):
    db_execute(cur, sql, params)
    return cur.fetchone()

def db_fetchall(cur, sql: str, params=()):
    db_execute(cur, sql, params)
    return cur.fetchall()

def db_insert_returning_id(cur, sql: str, params=()):
    db_execute(cur, sql, params)
    return cur.lastrowid


# =========================
# INIT DB
# =========================

def init_db():
    conn = get_db()
    cur = conn.cursor()

    db_execute(cur, """
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
        hwid        TEXT,
        last_seen   TEXT
    )
    """)

    db_execute(cur, """
    CREATE TABLE IF NOT EXISTS activations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id          INTEGER,
        key_value       TEXT,
        hwid            TEXT,
        ip              TEXT,
        event           TEXT,
        created_at      TEXT
    )
    """)

    # ✅ якщо таблиця була стара без колонки event — додамо
    try:
        db_execute(cur, "ALTER TABLE activations ADD COLUMN event TEXT")
    except sqlite3.OperationalError:
        pass

    db_execute(cur, """
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

    db_execute(cur, """
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

    db_execute(cur, """
    CREATE TABLE IF NOT EXISTS app_settings (
        id                  INTEGER PRIMARY KEY CHECK (id = 1),
        maintenance_enabled INTEGER NOT NULL DEFAULT 0,
        maintenance_message TEXT
    )
    """)

    row = db_fetchone(cur, "SELECT COUNT(*) AS c FROM app_settings")
    if (row["c"] if row else 0) == 0:
        db_execute(
            cur,
            "INSERT INTO app_settings (id, maintenance_enabled, maintenance_message) VALUES (1, 0, ?)",
            ("Тех роботи. Спробуй пізніше.",),
        )

    # ===== BOT USERS + ADMIN PIN IN DB =====
    db_execute(cur, """
    CREATE TABLE IF NOT EXISTS bot_users (
        discord_id TEXT PRIMARY KEY,
        role       TEXT NOT NULL DEFAULT 'viewer',   -- viewer/staff/admin
        note       TEXT,
        created_at TEXT
    )
    """)

    db_execute(cur, """
    CREATE TABLE IF NOT EXISTS admin_auth (
        id               INTEGER PRIMARY KEY CHECK (id = 1),
        enabled          INTEGER NOT NULL DEFAULT 1,
        pin_hash         TEXT,
        fallback_enabled INTEGER NOT NULL DEFAULT 0
    )
    """)

    row = db_fetchone(cur, "SELECT COUNT(*) AS c FROM admin_auth")
    if (row["c"] if row else 0) == 0:
        db_execute(cur, "INSERT INTO admin_auth (id, enabled, pin_hash, fallback_enabled) VALUES (1, 1, NULL, 0)")

    try:
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_value ON activations(key_value)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_hwid ON activations(key_value, hwid, id)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_event ON activations(event)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_actor ON admin_logs(actor)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_updates_uploaded ON updates(uploaded_at)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_bot_users_role ON bot_users(role)")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

init_db()


# =========================
# HELPERS
# =========================

def rand_key(prefix="FARM-"):
    abc = string.ascii_uppercase + string.digits
    return prefix + "".join(secrets.choice(abc) for _ in range(16))

def get_client_ip():
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    xr = (request.headers.get("X-Real-IP") or "").strip()
    if xr:
        return xr
    return request.remote_addr or ""

def log_action(actor, action, key_id=None, key_value=None, details=None):
    conn = get_db()
    cur = conn.cursor()
    db_execute(
        cur,
        """
        INSERT INTO admin_logs (actor, action, key_id, key_value, details, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (actor, action, key_id, key_value, details, get_client_ip(), now_value()),
    )
    conn.commit()
    conn.close()

def get_settings():
    conn = get_db()
    cur = conn.cursor()
    s = db_fetchone(cur, "SELECT * FROM app_settings WHERE id=1")
    conn.close()
    return s

def maintenance_guard():
    s = get_settings()
    if not s:
        return None
    sd = dict(s)
    enabled = int(sd.get("maintenance_enabled") or 0) == 1
    if enabled:
        msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."
        return jsonify({"ok": False, "reason": "maintenance", "message": msg}), 503
    return None

def is_running(last_seen, window_sec=RUNNING_WINDOW_SEC) -> bool:
    dt = parse_dt(last_seen)
    if not dt:
        return False
    return (kyiv_now() - dt).total_seconds() <= window_sec


# =========================
# ADMIN PIN stored in DB
# =========================

def _pin_hash(pin: str) -> str:
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()

def get_admin_auth():
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM admin_auth WHERE id=1")
    conn.close()
    return dict(row) if row else {"enabled": 1, "pin_hash": None, "fallback_enabled": 0}

def set_admin_pin_hash(new_hash, enabled: int = 1):
    conn = get_db()
    cur = conn.cursor()
    db_execute(cur, "UPDATE admin_auth SET pin_hash=?, enabled=? WHERE id=1", (new_hash, int(enabled)))
    conn.commit()
    conn.close()

def set_admin_enabled(enabled: int):
    conn = get_db()
    cur = conn.cursor()
    db_execute(cur, "UPDATE admin_auth SET enabled=? WHERE id=1", (int(enabled),))
    conn.commit()
    conn.close()

def verify_admin_pin(pin: str) -> bool:
    a = get_admin_auth()
    if int(a.get("enabled", 1)) != 1:
        return False

    pin = (pin or "").strip()
    if not pin:
        return False

    h = a.get("pin_hash")
    if h:
        return _pin_hash(pin) == h

    # if DB pin not set yet -> allow ADMIN_PIN once, then write into DB
    if pin == ADMIN_PIN:
        set_admin_pin_hash(_pin_hash(pin), enabled=1)
        return True

    return False


# =========================
# MAINTENANCE GLOBAL
# =========================

@app.before_request
def global_maintenance():
    if request.endpoint == "static":
        return None

    # allow login/logout/health + settings page
    ep = request.endpoint or ""
    allowed = {"healthz", "login", "logout", "page_settings"}
    if ep in allowed:
        return None

    s = get_settings()
    if not s:
        return None

    sd = dict(s)
    enabled = int(sd.get("maintenance_enabled") or 0) == 1
    if not enabled:
        return None

    msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."

    # API: allow bot-admin endpoints during maintenance
    if request.path.startswith("/api/"):
        if request.path.startswith("/api/bot/"):
            return None
        return jsonify({"ok": False, "reason": "maintenance", "message": msg}), 503

    return (
        f"""
        <!doctype html>
        <html><head><meta charset="utf-8"><title>Maintenance</title></head>
        <body style="background:#0b0b0b;color:#fff;font-family:system-ui;padding:40px">
          <h2 style="margin:0 0 8px 0;">{msg}</h2>
          <div style="opacity:.7">Спробуй пізніше.</div>
        </body></html>
        """,
        503,
    )


# =========================
# BOT NOTIFY (optional)
# =========================

def notify_bot_activation(key_value: str, hwid: str, ip: str, created_at: str):
    if not BOT_ACTIVATION_HOOK_URL:
        return

    payload = {
        "event": "activation",
        "key": key_value,
        "hwid": hwid,
        "ip": ip,
        "created_at": str(created_at or ""),
    }

    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            BOT_ACTIVATION_HOOK_URL,
            data=data,
            headers={"Content-Type": "application/json", "X-Hook-Secret": BOT_HOOK_SECRET},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            _ = resp.read()
    except Exception as e:
        try:
            log_action("panel", "bot_notify_failed", None, key_value, str(e))
        except Exception:
            pass


# =========================
# ANTI-FLOOD (event='activation')
# =========================

def should_log_activation(cur, key_value: str, hwid: str, cooldown_sec: int) -> bool:
    """
    1 activation log per (key_value, hwid) per cooldown_sec
    """
    if cooldown_sec <= 0:
        return True

    last = db_fetchone(
        cur,
        """
        SELECT created_at
        FROM activations
        WHERE key_value=? AND hwid=? AND event='activation'
        ORDER BY id DESC
        LIMIT 1
        """,
        (key_value, hwid),
    )
    if not last:
        return True

    last_dt = parse_dt(last["created_at"])
    if not last_dt:
        return True

    diff = (kyiv_now() - last_dt).total_seconds()
    return diff >= float(cooldown_sec)


# =========================
# UI STYLE
# =========================

BASE_CSS = """
*{box-sizing:border-box}
body{
  margin:0;padding:0;
  font-family:"Segoe UI",system-ui,sans-serif;
  color:#eee;
  background: radial-gradient(circle at top left,#ff6a00 0,#000 55%);
}
.bg-img{
  position:fixed;inset:0;
  background:
    linear-gradient(120deg,rgba(0,0,0,.90),rgba(0,0,0,.85)),
    url('/static/farmbot_bg.jpg') center/cover no-repeat fixed;
  z-index:-2;
}
.blur-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(3px);z-index:-1}
h1{
  text-align:center;
  padding:18px 0 10px;
  margin:0;
  font-size:34px;
  color:#ff8c1a;
  letter-spacing:3px;
  text-shadow:0 0 18px #ff7b00;
}
.top-nav{
  max-width:1600px;
  margin:0 auto 16px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:10px;
  flex-wrap:wrap;
  padding:10px 14px;
  background:rgba(5,8,11,.90);
  border-radius:14px;
  border:1px solid #20262c;
  box-shadow:0 0 16px rgba(0,0,0,.7);
}
.nav-left{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.nav-links{display:flex;gap:10px;font-size:13px;flex-wrap:wrap}
.nav-links a{
  color:#ffb35c;
  text-decoration:none;
  padding:7px 10px;
  border-radius:10px;
  border:1px solid transparent;
  transition:.15s ease;
}
.nav-links a.active{
  background:rgba(255,140,26,.15);
  border-color:rgba(255,140,26,.18);
}
.nav-links a:hover{
  background:rgba(255,140,26,.10);
  border-color:rgba(255,140,26,.14);
}
.nav-right{display:flex;gap:8px;flex-wrap:wrap}
.panel{
  max-width:1600px;
  margin:0 auto 40px;
  background:rgba(5,8,11,.96);
  border-radius:18px;
  border:1px solid #20262c;
  box-shadow:0 0 28px rgba(0,0,0,.8);
  padding:18px 20px 22px;
  overflow-x:auto;
}
.section-title{
  font-size:20px;
  margin:10px 0 10px;
  color:#ffb35c;
  letter-spacing:.6px;
}
.form-row{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  align-items:center;
  margin-bottom:10px;
  font-size:14px;
}
label{font-size:13px;color:#bbb}
input,select,textarea{
  padding:8px 10px;
  background:#020509;
  border:1px solid #2b3138;
  color:#f5f5f5;
  border-radius:10px;
  font-size:13px;
  transition:.15s ease;
}
textarea{min-height:90px; width:100%}
input:focus,select:focus,textarea:focus{
  outline:none;
  border-color:#ff8c1a;
  box-shadow:0 0 0 3px rgba(255,140,26,.15);
}
button{
  border:1px solid transparent;
  border-radius:12px;
  padding:9px 14px;
  font-size:13px;
  cursor:pointer;
  font-weight:800;
  transition:.15s ease;
  box-shadow:0 12px 22px rgba(0,0,0,.24);
  user-select:none;
}
button:active{transform:translateY(1px) scale(.99)}
.btn-small{padding:7px 10px;font-size:12px;border-radius:11px}
.btn-main{
  background:linear-gradient(135deg,#ff9a2a,#ff3b0a);
  border-color:rgba(255,140,26,.35);
  color:#0b0b0b;
}
.btn-main:hover{
  transform:translateY(-1px);
  box-shadow:0 0 0 3px rgba(255,140,26,.14),0 18px 36px rgba(0,0,0,.35);
  filter:saturate(1.08);
}
.btn-muted{
  background:linear-gradient(135deg,#343a41,#1a1f26);
  border-color:rgba(255,255,255,.08);
  color:#e8eaed;
}
.btn-muted:hover{
  transform:translateY(-1px);
  box-shadow:0 0 0 3px rgba(255,255,255,.07),0 18px 36px rgba(0,0,0,.35);
}
.btn-warning{
  background:linear-gradient(135deg,#ffd24a,#ff9f1a);
  border-color:rgba(255,210,74,.30);
  color:#141414;
}
.btn-warning:hover{
  transform:translateY(-1px);
  box-shadow:0 0 0 3px rgba(255,210,74,.12),0 18px 36px rgba(0,0,0,.35);
}
.btn-danger{
  background:linear-gradient(135deg,#ff5a5f,#c81d25);
  border-color:rgba(255,90,95,.30);
  color:#fff;
}
.btn-danger:hover{
  transform:translateY(-1px);
  box-shadow:0 0 0 3px rgba(255,90,95,.12),0 18px 36px rgba(0,0,0,.35);
}
table{
  width:100%;
  min-width:1400px;
  border-collapse:collapse;
  margin-top:10px;
  font-size:13px;
  border-radius:14px;
}
th,td{
  border:1px solid #14181d;
  padding:10px 10px;
  vertical-align:middle;
  white-space:nowrap;
}
th{
  background:#06090f;
  color:#ffb35c;
  text-align:left;
  position:sticky;
  top:0;
  z-index:2;
}
tr:nth-child(even){background:#070b10}
tr:hover{background:rgba(255,140,26,.06)}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.badge{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:6px 12px;
  border-radius:999px;
  font-size:12px;
  font-weight:900;
  min-width:120px;
  justify-content:center;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.04);
}
.dot{width:9px;height:9px;border-radius:999px;background:#999}
.badge.on{border-color:rgba(50,255,150,.18); background:rgba(50,255,150,.08)}
.badge.on .dot{background:#31f28b}
.badge.off{border-color:rgba(255,120,80,.18); background:rgba(255,120,80,.07)}
.badge.off .dot{background:#ff6b3d}
.badge.maint{border-color:rgba(255,210,74,.22); background:rgba(255,210,74,.10); color:#ffd24a}
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="utf-8">
<title>FarmBot Login</title>
<style>{{ base_css|safe }}</style>
</head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<div style="display:flex;justify-content:center;align-items:center;height:100vh;">
  <div style="background:#0f1318;padding:24px 26px;border-radius:16px;width:320px;box-shadow:0 0 28px rgba(0,0,0,0.85);border:1px solid #262c33;text-align:center;">
    <h2 style="margin:0 0 14px 0; color:#ffb35c; letter-spacing:1px;">FARMBOT PANEL</h2>
    <form method="post">
      <input type="password" name="pin" placeholder="PIN" autofocus style="width:100%;">
      <button class="btn-main" type="submit" style="width:100%; margin-top:14px;">Увійти</button>
    </form>
    {% if error %}
      <div style="margin-top:10px; color:#ff4d4f; font-size:12px;">{{error}}</div>
    {% endif %}
  </div>
</div>
</body>
</html>
"""

def nav_html(active_tab: str):
    s = get_settings()
    sd = dict(s) if s else {}
    maint = int(sd.get("maintenance_enabled") or 0) == 1

    maint_badge = ""
    if maint:
        maint_badge = """
        <span class="badge maint">
          <span class="dot" style="background:#ffd24a"></span> ТЕХ РОБОТИ
        </span>
        """
    return f"""
<div class="top-nav">
  <div class="nav-left">
    {maint_badge}
    <div class="nav-links">
      <a href="/" class="{'active' if active_tab=='keys' else ''}">Ключі</a>
      <a href="/activations" class="{'active' if active_tab=='activations' else ''}">Активації</a>
      <a href="/launcher_logs" class="{'active' if active_tab=='launcher' else ''}">Логи лаунчера</a>
      <a href="/updates" class="{'active' if active_tab=='updates' else ''}">Оновлення</a>
      <a href="/settings" class="{'active' if active_tab=='settings' else ''}">Налаштування</a>
    </div>
  </div>
  <div class="nav-right">
    <form method="get" action="/download_latest">
      <button class="btn-main btn-small" type="submit">Скачати останнє</button>
    </form>
    <form method="get" action="/logout">
      <button class="btn-muted btn-small" type="submit">Вийти</button>
    </form>
  </div>
</div>
"""


# =========================
# AUTH
# =========================

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
        if verify_admin_pin(pin):
            session["admin_authed"] = True
            return redirect("/")
        error = "Неправильний PIN або логін вимкнений"
    return render_template_string(LOGIN_HTML, base_css=BASE_CSS, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# PAGES
# =========================

@app.route("/")
@login_required
def page_keys():
    conn = get_db()
    cur = conn.cursor()
    keys_rows = db_fetchall(cur, "SELECT * FROM keys ORDER BY id DESC")
    conn.close()

    keys_view = []
    for k in keys_rows:
        d = dict(k)
        d["running"] = is_running(d.get("last_seen") or "", RUNNING_WINDOW_SEC)
        keys_view.append(d)

    html = f"""
<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><title>FARMBOT – Keys</title><style>{{{{ base_css|safe }}}}</style></head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<h1>FARMBOT PANEL</h1>
{nav_html('keys')}
<div class="panel">

  <div class="section-title">Генерація ключів</div>
  <form method="post" action="/gen_keys">
    <div class="form-row">
      <label>Префікс</label>
      <input name="prefix" value="FARM-" style="max-width:130px;">
      <label>Кількість</label>
      <input type="number" name="count" min="1" max="500" value="5" style="max-width:110px;">
      <label>TTL (днів)</label>
      <input type="number" name="days" min="0" max="365" value="0" style="max-width:110px;">
      <button type="submit" class="btn-main">Згенерувати</button>
    </div>
  </form>

  <div class="section-title">Ключі</div>

  <table style="min-width:1750px;">
    <tr>
      <th style="width:70px;">ID</th>
      <th style="width:320px;">Key</th>
      <th style="width:160px;">Статус</th>
      <th style="width:240px;">Owner</th>
      <th style="width:280px;">Note</th>
      <th style="width:90px;">Active</th>
      <th style="width:90px;">Banned</th>
      <th style="width:240px;">Reason</th>
      <th style="width:220px;">Expires</th>
      <th style="width:360px;">HWID</th>
      <th style="width:200px;">Last seen</th>
      <th style="width:220px;">Дії</th>
    </tr>

    {{% for k in keys %}}
    <tr>
      <form id="f{{{{k.id}}}}" method="post" action="/key/update/{{{{k.id}}}}"></form>

      <td>{{{{k.id}}}}</td>

      <td>
        <input style="min-width:260px;" name="key_value" form="f{{{{k.id}}}}" value="{{{{k.key_value}}}}">
      </td>

      <td>
        {{% if k.running %}}
          <span class="badge on"><span class="dot"></span> Запущений</span>
        {{% else %}}
          <span class="badge off"><span class="dot"></span> Офлайн</span>
        {{% endif %}}
      </td>

      <td><input style="min-width:200px;" name="owner" form="f{{{{k.id}}}}" value="{{{{k.owner or ''}}}}"></td>
      <td><input style="min-width:240px;" name="note" form="f{{{{k.id}}}}" value="{{{{k.note or ''}}}}"></td>

      <td style="text-align:center;">
        <input type="checkbox" name="is_active" value="1" form="f{{{{k.id}}}}" {{% if k.is_active %}}checked{{% endif %}}>
      </td>

      <td style="text-align:center;">
        <input type="checkbox" name="is_banned" value="1" form="f{{{{k.id}}}}" {{% if k.is_banned %}}checked{{% endif %}}>
      </td>

      <td><input name="ban_reason" form="f{{{{k.id}}}}" value="{{{{k.ban_reason or ''}}}}"></td>

      <td><input style="min-width:200px;" name="expires_at" form="f{{{{k.id}}}}" placeholder="YYYY-MM-DD HH:MM:SS" value="{{{{k.expires_at or ''}}}}"></td>

      <td><input style="min-width:320px;" name="hwid" form="f{{{{k.id}}}}" value="{{{{k.hwid or ''}}}}"></td>

      <td style="font-size:12px;color:#ddd;">{{{{k.last_seen or ''}}}}</td>

      <td>
        <div class="actions">
          <button class="btn-main btn-small" form="f{{{{k.id}}}}">Save</button>

          <form method="post" action="/key/ban/{{{{k.id}}}}">
            <button class="btn-danger btn-small" type="submit">Ban</button>
          </form>

          <form method="post" action="/key/unban/{{{{k.id}}}}">
            <button class="btn-warning btn-small" type="submit">Unban</button>
          </form>

          <form method="post" action="/key/clear_hwid/{{{{k.id}}}}">
            <button class="btn-muted btn-small" type="submit">Clear HWID</button>
          </form>

          <form method="post" action="/key/delete/{{{{k.id}}}}" onsubmit="return confirm('Видалити ключ?');">
            <button class="btn-muted btn-small" type="submit">Del</button>
          </form>
        </div>
      </td>
    </tr>
    {{% endfor %}}
  </table>

</div>
</body></html>
"""
    return render_template_string(html, base_css=BASE_CSS, keys=keys_view)

@app.route("/activations")
@login_required
def page_activations():
    q = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit") or "300")
    except ValueError:
        limit = 300
    limit = max(50, min(5000, limit))

    conn = get_db()
    cur = conn.cursor()
    if q:
        pat = f"%{q}%"
        rows = db_fetchall(
            cur,
            """
            SELECT id, event, key_value, hwid, ip, created_at
            FROM activations
            WHERE key_value LIKE ? OR hwid LIKE ? OR ip LIKE ? OR event LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (pat, pat, pat, pat, limit),
        )
    else:
        rows = db_fetchall(
            cur,
            "SELECT id, event, key_value, hwid, ip, created_at FROM activations ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    conn.close()

    html = f"""
<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><title>FARMBOT – Activations</title><style>{{{{ base_css|safe }}}}</style></head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<h1>FARMBOT PANEL</h1>
{nav_html('activations')}
<div class="panel">
  <div class="section-title">Активації / Входи лаунчера</div>

  <form method="get" action="/activations">
    <div class="form-row">
      <label>Пошук</label>
      <input name="q" value="{{{{q}}}}" placeholder="key / hwid / ip / event" style="min-width:320px;">
      <label>Ліміт</label>
      <input type="number" name="limit" min="50" max="5000" value="{{{{limit}}}}" style="max-width:140px;">
      <button class="btn-main btn-small" type="submit">Показати</button>
    </div>
  </form>

  <form method="post" action="/activations/clear" onsubmit="return confirm('Очистити всі логи активацій?');">
    <div class="form-row">
      <button class="btn-danger btn-small" type="submit">Очистити логи</button>
    </div>
  </form>

  <table style="min-width:1400px;">
    <tr>
      <th style="width:80px;">ID</th>
      <th style="width:140px;">Event</th>
      <th style="width:320px;">Key</th>
      <th style="width:420px;">HWID</th>
      <th style="width:220px;">IP</th>
      <th style="width:220px;">Дата (Kyiv)</th>
    </tr>
    {{% for a in rows %}}
    <tr>
      <td>{{{{a.id}}}}</td>
      <td>{{{{a.event or ''}}}}</td>
      <td>{{{{a.key_value}}}}</td>
      <td>{{{{a.hwid or ''}}}}</td>
      <td>{{{{a.ip or ''}}}}</td>
      <td>{{{{a.created_at}}}}</td>
    </tr>
    {{% endfor %}}
  </table>
</div>
</body></html>
"""
    return render_template_string(html, base_css=BASE_CSS, rows=rows, q=q, limit=limit)

@app.route("/activations/clear", methods=["POST"])
@login_required
def activations_clear():
    conn = get_db()
    cur = conn.cursor()
    db_execute(cur, "DELETE FROM activations")
    conn.commit()
    conn.close()
    log_action("panel", "clear_activations", None, None, "deleted all activation logs")
    return redirect("/activations")

@app.route("/launcher_logs")
@login_required
def page_launcher_logs():
    q = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit") or "400")
    except ValueError:
        limit = 400
    limit = max(50, min(5000, limit))

    conn = get_db()
    cur = conn.cursor()
    if q:
        pat = f"%{q}%"
        rows = db_fetchall(
            cur,
            """
            SELECT id, action, key_value, details, ip, created_at
            FROM admin_logs
            WHERE actor='launcher' AND (action LIKE ? OR key_value LIKE ? OR details LIKE ? OR ip LIKE ?)
            ORDER BY id DESC
            LIMIT ?
            """,
            (pat, pat, pat, pat, limit),
        )
    else:
        rows = db_fetchall(
            cur,
            """
            SELECT id, action, key_value, details, ip, created_at
            FROM admin_logs
            WHERE actor='launcher'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    conn.close()

    html = f"""
<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><title>FARMBOT – Launcher logs</title><style>{{{{ base_css|safe }}}}</style></head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<h1>FARMBOT PANEL</h1>
{nav_html('launcher')}
<div class="panel">
  <div class="section-title">Логи лаунчера (admin_logs)</div>

  <form method="get" action="/launcher_logs">
    <div class="form-row">
      <label>Пошук</label>
      <input name="q" value="{{{{q}}}}" placeholder="event / key / ip" style="min-width:320px;">
      <label>Ліміт</label>
      <input type="number" name="limit" min="50" max="5000" value="{{{{limit}}}}" style="max-width:140px;">
      <button class="btn-main btn-small" type="submit">Показати</button>
    </div>
  </form>

  <table style="min-width:1500px;">
    <tr>
      <th style="width:90px;">ID</th>
      <th style="width:220px;">Дата (Kyiv)</th>
      <th style="width:220px;">Event</th>
      <th style="width:360px;">Key</th>
      <th>Details</th>
      <th style="width:220px;">IP</th>
    </tr>
    {{% for l in rows %}}
    <tr>
      <td>{{{{l.id}}}}</td>
      <td>{{{{l.created_at}}}}</td>
      <td>{{{{l.action}}}}</td>
      <td>{{{{l.key_value or ''}}}}</td>
      <td style="font-size:12px;color:#ddd; white-space:normal;">{{{{l.details or ''}}}}</td>
      <td>{{{{l.ip or ''}}}}</td>
    </tr>
    {{% endfor %}}
  </table>
</div>
</body></html>
"""
    return render_template_string(html, base_css=BASE_CSS, rows=rows, q=q, limit=limit)

@app.route("/updates")
@login_required
def page_updates():
    q = (request.args.get("q") or "").strip()

    conn = get_db()
    cur = conn.cursor()
    if q:
        pat = f"%{q}%"
        rows = db_fetchall(
            cur,
            """
            SELECT * FROM updates
            WHERE filename LIKE ? OR version LIKE ? OR note LIKE ?
            ORDER BY uploaded_at DESC, id DESC
            LIMIT 300
            """,
            (pat, pat, pat),
        )
    else:
        rows = db_fetchall(cur, "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 300")
    conn.close()

    html = f"""
<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><title>FARMBOT – Updates</title><style>{{{{ base_css|safe }}}}</style></head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<h1>FARMBOT PANEL</h1>
{nav_html('updates')}
<div class="panel">

  <div class="section-title">Залив оновлення</div>
  <form method="post" action="/upload_update" enctype="multipart/form-data">
    <div class="form-row">
      <label>Файл</label>
      <input type="file" name="file" required>
      <label>Версія</label>
      <input type="text" name="version" placeholder="1.3.2" style="min-width:160px;">
      <label>Коментар</label>
      <input type="text" name="note" placeholder="..." style="min-width:300px;">
      <button type="submit" class="btn-main">Залити</button>
    </div>
  </form>

  <div class="section-title">Логи оновлень</div>
  <form method="get" action="/updates">
    <div class="form-row">
      <label>Пошук</label>
      <input type="text" name="q" placeholder="filename / version / note" value="{{{{q}}}}" style="min-width:320px;">
      <button class="btn-main btn-small" type="submit">Шукати</button>
    </div>
  </form>

  <table style="min-width:1400px;">
    <tr>
      <th style="width:90px;">ID</th>
      <th style="width:240px;">Дата (Kyiv)</th>
      <th style="width:380px;">Файл</th>
      <th style="width:160px;">Версія</th>
      <th style="width:160px;">Розмір (MB)</th>
      <th>Коментар</th>
    </tr>
    {{% for u in rows %}}
    <tr>
      <td>{{{{u.id}}}}</td>
      <td>{{{{u.uploaded_at}}}}</td>
      <td>{{{{u.filename}}}}</td>
      <td>{{{{u.version or '-' }}}}</td>
      <td>{{{{"%.2f"|format((u.size_bytes or 0)/1024/1024)}}}}</td>
      <td style="white-space:normal;">{{{{u.note or ''}}}}</td>
    </tr>
    {{% endfor %}}
  </table>

</div>
</body></html>
"""
    return render_template_string(html, base_css=BASE_CSS, rows=rows, q=q)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def page_settings():
    if request.method == "POST":
        enabled = 1 if (request.form.get("maintenance_enabled") == "1") else 0
        msg = (request.form.get("maintenance_message") or "").strip() or "Тех роботи. Спробуй пізніше."

        conn = get_db()
        cur = conn.cursor()
        db_execute(cur, "UPDATE app_settings SET maintenance_enabled=?, maintenance_message=? WHERE id=1", (enabled, msg))
        conn.commit()
        conn.close()

        log_action("panel", "set_maintenance", None, None, f"enabled={enabled}")
        return redirect("/settings")

    s = get_settings() or {}
    sd = dict(s) if s else {}
    enabled = int(sd.get("maintenance_enabled") or 0)
    msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."

    a = get_admin_auth()
    pin_enabled = bool(int(a.get("enabled", 1)))
    has_db_pin = bool(a.get("pin_hash"))

    html = f"""
<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><title>FARMBOT – Settings</title><style>{{{{ base_css|safe }}}}</style></head>
<body>
<div class="bg-img"></div><div class="blur-bg"></div>
<h1>FARMBOT PANEL</h1>
{nav_html('settings')}
<div class="panel">

  <div class="section-title">Тех роботи (вимкнути лаунчер/API)</div>
  <form method="post" action="/settings">
    <div class="form-row">
      <label style="display:flex; align-items:center; gap:8px;">
        <input type="checkbox" name="maintenance_enabled" value="1" {'checked' if enabled else ''}>
        Увімкнути тех роботи
      </label>
    </div>

    <div class="form-row" style="align-items:flex-start;">
      <label style="min-width:170px;">Повідомлення</label>
      <textarea name="maintenance_message">{msg}</textarea>
    </div>

    <button class="btn-main" type="submit">Зберегти</button>
  </form>

  <div class="section-title" style="margin-top:22px;">Admin PIN (через БД)</div>
  <div style="font-size:13px;color:#cfcfcf;opacity:.9;line-height:1.5">
    Статус: <b style="color:#ffb35c">{'ENABLED' if pin_enabled else 'DISABLED'}</b> ·
    PIN у БД: <b style="color:#ffb35c">{'YES' if has_db_pin else 'NO (візьме ADMIN_PIN при першому логіні)'}</b>
    <div style="opacity:.75;margin-top:6px;">
      PIN ротейтиш/вимикаєш через Discord-бот API: <code>/api/bot/admin_pin/*</code>
    </div>
  </div>

</div>
</body></html>
"""
    return render_template_string(html, base_css=BASE_CSS)


# =========================
# PANEL ACTIONS
# =========================

@app.route("/gen_keys", methods=["POST"])
@login_required
def gen_keys():
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

    created_at = now_value()
    expires_at = None
    if days > 0:
        expires_at = (kyiv_now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    made = 0
    for _ in range(count):
        key_value = rand_key(prefix)
        try:
            db_execute(
                cur,
                "INSERT INTO keys (key_value, is_active, is_banned, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key_value, 1, 0, created_at, expires_at),
            )
            made += 1
        except Exception:
            pass
    conn.commit()
    conn.close()

    log_action("panel", "gen_keys", None, None, f"prefix={prefix}, count={count}, days={days}, made={made}")
    return redirect("/")

@app.route("/key/update/<int:key_id>", methods=["POST"])
@login_required
def key_update(key_id):
    f = request.form
    key_value = (f.get("key_value") or "").strip()
    owner = (f.get("owner") or "").strip()
    note = (f.get("note") or "").strip()
    ban_reason = (f.get("ban_reason") or "").strip()
    expires_at = (f.get("expires_at") or "").strip()
    hwid = (f.get("hwid") or "").strip()

    is_active = 1 if (f.get("is_active") == "1") else 0
    is_banned = 1 if (f.get("is_banned") == "1") else 0

    conn = get_db()
    cur = conn.cursor()
    db_execute(
        cur,
        """
        UPDATE keys
        SET key_value=?, owner=?, note=?, is_active=?, is_banned=?, ban_reason=?, expires_at=?, hwid=?
        WHERE id=?
        """,
        (key_value, owner, note, is_active, is_banned, ban_reason, expires_at, hwid, key_id),
    )
    conn.commit()
    conn.close()

    log_action("panel", "update_key", key_id, key_value, f"owner={owner}")
    return redirect("/")

@app.route("/key/ban/<int:key_id>", methods=["POST"])
@login_required
def key_ban(key_id):
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT key_value FROM keys WHERE id=?", (key_id,))
    key_val = row["key_value"] if row else None

    db_execute(cur, "UPDATE keys SET is_banned=1, ban_reason='panel ban' WHERE id=?", (key_id,))
    conn.commit()
    conn.close()

    log_action("panel", "ban_key", key_id, key_val, "panel ban")
    return redirect("/")

@app.route("/key/unban/<int:key_id>", methods=["POST"])
@login_required
def key_unban(key_id):
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT key_value FROM keys WHERE id=?", (key_id,))
    key_val = row["key_value"] if row else None

    db_execute(cur, "UPDATE keys SET is_banned=0, ban_reason=NULL WHERE id=?", (key_id,))
    conn.commit()
    conn.close()

    log_action("panel", "unban_key", key_id, key_val, None)
    return redirect("/")

@app.route("/key/clear_hwid/<int:key_id>", methods=["POST"])
@login_required
def key_clear_hwid(key_id):
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT key_value FROM keys WHERE id=?", (key_id,))
    key_val = row["key_value"] if row else None

    db_execute(cur, "UPDATE keys SET hwid=NULL WHERE id=?", (key_id,))
    conn.commit()
    conn.close()

    log_action("panel", "clear_hwid", key_id, key_val, None)
    return redirect("/")

@app.route("/key/delete/<int:key_id>", methods=["POST"])
@login_required
def key_delete(key_id):
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT key_value FROM keys WHERE id=?", (key_id,))
    key_val = row["key_value"] if row else None

    db_execute(cur, "DELETE FROM keys WHERE id=?", (key_id,))
    deleted = getattr(cur, "rowcount", 0)
    conn.commit()
    conn.close()

    log_action("panel", "delete_key", key_id, key_val, f"deleted={deleted}")
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
    new_id = db_insert_returning_id(
        cur,
        "INSERT INTO updates (filename, stored_path, version, note, uploaded_at, size_bytes) VALUES (?,?,?,?,?,?)",
        (safe_name, stored_name, version, note, now_value(), size_bytes),
    )
    conn.commit()
    conn.close()

    log_action("panel", "upload_update", None, None, f"id={new_id}, file={safe_name}, version={version}")
    return redirect("/updates")

@app.route("/download_latest")
@login_required
def download_latest():
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 1")
    conn.close()

    if not row:
        return redirect("/updates")

    return send_from_directory(
        STORAGE_DIR,
        row["stored_path"],
        as_attachment=True,
        download_name=row["filename"],
    )


# =========================
# PUBLIC API (launcher)
# =========================

@app.route("/api/status")
def api_status():
    s = get_settings()
    sd = dict(s) if s else {}
    enabled = bool(int(sd.get("maintenance_enabled") or 0))
    return jsonify({
        "ok": True,
        "maintenance_enabled": enabled,
        "maintenance_message": sd.get("maintenance_message") or ""
    })

# ✅ check_key:
# - якщо ключ валідний -> ЗАВЖДИ пишемо event='enter' в activations
# - додатково (антифлуд) event='activation' раз на cooldown
@app.route("/api/check_key", methods=["POST"])
def api_check_key():
    guard = maintenance_guard()
    if guard:
        return guard

    data = request.get_json(silent=True) or request.form
    key_value = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not key_value or not hwid:
        return jsonify({"ok": False, "reason": "missing"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM keys WHERE key_value=?", (key_value,))

    if not row:
        conn.close()
        return jsonify({"ok": False, "reason": "not_found"})

    if not row["is_active"]:
        conn.close()
        return jsonify({"ok": False, "reason": "inactive"})

    if row["is_banned"]:
        conn.close()
        return jsonify({"ok": False, "reason": "banned"})

    if is_expired_row(row["expires_at"]):
        conn.close()
        return jsonify({"ok": False, "reason": "expired"})

    saved_hwid = (row["hwid"] or "").strip()
    ip = get_client_ip()
    nowv = now_value()

    first_activation = False

    # bind HWID only once
    if not saved_hwid:
        db_execute(cur, "UPDATE keys SET hwid=? WHERE id=?", (hwid, row["id"]))
        first_activation = True
    else:
        if saved_hwid != hwid:
            conn.close()
            return jsonify({"ok": False, "reason": "hwid_mismatch"})

    # ✅ 1) LOG входу
    db_execute(
        cur,
        "INSERT INTO activations (key_id, key_value, hwid, ip, event, created_at) VALUES (?,?,?,?,?,?)",
        (row["id"], row["key_value"], hwid, ip, "enter", nowv),
    )

    # ✅ 2) activation anti-flood
    do_log = should_log_activation(cur, row["key_value"], hwid, ACTIVATION_LOG_COOLDOWN_SEC)
    if do_log:
        db_execute(
            cur,
            "INSERT INTO activations (key_id, key_value, hwid, ip, event, created_at) VALUES (?,?,?,?,?,?)",
            (row["id"], row["key_value"], hwid, ip, "activation", nowv),
        )

    conn.commit()
    conn.close()

    # ✅ webhook
    if do_log and first_activation:
        try:
            notify_bot_activation(key_value=row["key_value"], hwid=hwid, ip=ip, created_at=nowv)
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "reason": "ok",
        "enter_logged": True,
        "activation_logged": bool(do_log),
        "first": bool(first_activation)
    })

@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    guard = maintenance_guard()
    if guard:
        return guard

    data = request.get_json(silent=True) or request.form
    key_value = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not key_value or not hwid:
        return jsonify({"ok": False, "reason": "missing"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM keys WHERE key_value=?", (key_value,))

    if not row:
        conn.close()
        return jsonify({"ok": False, "reason": "not_found"})

    if row["hwid"] and row["hwid"] != hwid:
        conn.close()
        return jsonify({"ok": False, "reason": "hwid_mismatch"})

    if row["is_banned"] or (not row["is_active"]) or is_expired_row(row["expires_at"]):
        conn.close()
        return jsonify({"ok": False, "reason": "inactive"})

    db_execute(cur, "UPDATE keys SET last_seen=? WHERE id=?", (now_value(), row["id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

SPAM_EVENTS = {"license_ok", "heartbeat_ok", "update_check"}

@app.route("/api/launcher/log", methods=["POST"])
def api_launcher_log():
    data = request.get_json(silent=True) or {}
    event = (data.get("event") or "event").strip()

    if event in SPAM_EVENTS:
        return jsonify({"ok": True})

    key_value = (data.get("key") or "").strip() or None
    hwid = (data.get("hwid") or "").strip() or None
    details = (data.get("details") or "").strip() or None

    payload = {"hwid": hwid, "details": details}
    log_action("launcher", event, None, key_value, json.dumps(payload, ensure_ascii=False))
    return jsonify({"ok": True})


# =========================
# PUBLIC API (updates)
# =========================

@app.route("/api/updates/latest")
def api_updates_latest():
    guard = maintenance_guard()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 1")
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "no_updates"}), 404

    return jsonify({
        "ok": True,
        "id": row["id"],
        "version": row["version"] or "",
        "note": row["note"] or "",
        "filename": row["filename"] or "",
        "size_bytes": row["size_bytes"] or 0,
        "uploaded_at": str(row["uploaded_at"] or "")
    })

@app.route("/api/updates/latest/download")
def api_updates_latest_download():
    guard = maintenance_guard()
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT * FROM updates ORDER BY uploaded_at DESC, id DESC LIMIT 1")
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "no_updates"}), 404

    return send_from_directory(
        STORAGE_DIR,
        row["stored_path"],
        as_attachment=True,
        download_name=row["filename"],
    )


# =========================
# DS API (KEYS) - create (admin pin from DB)
# =========================

@app.route("/api/ds/key/create", methods=["POST"])
def api_ds_key_create():
    pin = (request.headers.get("X-Admin-Pin") or "").strip()
    if not verify_admin_pin(pin):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or request.form

    prefix = (data.get("prefix") or "FARM-").strip() or "FARM-"
    owner = (data.get("owner") or "").strip() or None
    note = (data.get("note") or "").strip() or None

    try:
        count = int(data.get("count") or 1)
    except ValueError:
        count = 1
    try:
        days = int(data.get("days") or 0)
    except ValueError:
        days = 0

    count = max(1, min(500, count))
    days = max(0, min(365, days))

    created_at = now_value()
    expires_at = None
    if days > 0:
        expires_at = (kyiv_now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()

    keys = []
    made = 0
    for _ in range(count):
        for _attempt in range(7):
            kv = rand_key(prefix)
            try:
                db_execute(
                    cur,
                    """
                    INSERT INTO keys (key_value, owner, note, is_active, is_banned, created_at, expires_at)
                    VALUES (?, ?, ?, 1, 0, ?, ?)
                    """,
                    (kv, owner, note, created_at, expires_at),
                )
                keys.append(kv)
                made += 1
                break
            except Exception:
                continue

    conn.commit()
    conn.close()

    log_action("ds", "ds_key_create", None, None, f"prefix={prefix}, requested={count}, made={made}, days={days}, owner={owner or ''}")

    return jsonify({
        "ok": True,
        "requested": count,
        "made": made,
        "keys": keys,
        "prefix": prefix,
        "days": days,
        "owner": owner or "",
        "note": note or "",
        "expires_at": expires_at or "",
    })


# =========================
# BOT ADMIN API (Discord bot)
# =========================

ROLE_ORDER = {"viewer": 0, "staff": 1, "admin": 2}

def bot_auth_guard():
    sec = (request.headers.get("X-Bot-Secret") or "").strip()
    if not BOT_HOOK_SECRET or sec != BOT_HOOK_SECRET:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def bot_count_users() -> int:
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT COUNT(*) AS c FROM bot_users")
    conn.close()
    return int(row["c"] if row else 0)

def get_bot_role(discord_id: str) -> str:
    if not discord_id:
        return "viewer"
    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT role FROM bot_users WHERE discord_id=?", (discord_id,))
    conn.close()
    if not row:
        return "viewer"
    return (row["role"] or "viewer").strip().lower()

def is_bootstrap_admin(discord_id: str) -> bool:
    return bool(BOOTSTRAP_DISCORD_ADMIN_ID and discord_id == BOOTSTRAP_DISCORD_ADMIN_ID)

def require_bot_role(min_role: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            g = bot_auth_guard()
            if g:
                return g

            actor = (request.headers.get("X-Discord-Id") or "").strip()
            role = get_bot_role(actor)

            # bootstrap: якщо bot_users пустий -> BOOTSTRAP_DISCORD_ADMIN_ID має admin
            if bot_count_users() == 0 and is_bootstrap_admin(actor):
                role = "admin"

            if ROLE_ORDER.get(role, 0) < ROLE_ORDER.get(min_role, 0):
                return jsonify({"ok": False, "error": "forbidden", "role": role}), 403

            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.route("/api/bot/ping")
@require_bot_role("viewer")
def api_bot_ping():
    return jsonify({"ok": True})

# ---- users/roles ----
@app.route("/api/bot/users/set_role", methods=["POST"])
@require_bot_role("admin")
def api_bot_users_set_role():
    data = request.get_json(silent=True) or {}
    discord_id = (data.get("discord_id") or "").strip()
    role = (data.get("role") or "viewer").strip().lower()
    note = (data.get("note") or "").strip() or None

    if not discord_id:
        return jsonify({"ok": False, "error": "missing_discord_id"}), 400
    if role not in ROLE_ORDER:
        return jsonify({"ok": False, "error": "bad_role"}), 400

    conn = get_db()
    cur = conn.cursor()
    exists = db_fetchone(cur, "SELECT discord_id FROM bot_users WHERE discord_id=?", (discord_id,))
    if exists:
        db_execute(cur, "UPDATE bot_users SET role=?, note=? WHERE discord_id=?", (role, note, discord_id))
    else:
        db_execute(cur, "INSERT INTO bot_users (discord_id, role, note, created_at) VALUES (?,?,?,?)",
                   (discord_id, role, note, now_value()))
    conn.commit()
    conn.close()

    log_action("bot", "set_role", None, None, f"{discord_id} => {role}")
    return jsonify({"ok": True, "discord_id": discord_id, "role": role})

@app.route("/api/bot/users/list")
@require_bot_role("admin")
def api_bot_users_list():
    conn = get_db()
    cur = conn.cursor()
    rows = db_fetchall(cur, "SELECT discord_id, role, note, created_at FROM bot_users ORDER BY created_at DESC LIMIT 300")
    conn.close()
    return jsonify({"ok": True, "rows": [dict(r) for r in rows]})

# ---- admin pin management ----
def _gen_admin_pin():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(10))

@app.route("/api/bot/admin_pin/rotate", methods=["POST"])
@require_bot_role("admin")
def api_bot_admin_pin_rotate():
    new_pin = _gen_admin_pin()
    set_admin_pin_hash(_pin_hash(new_pin), enabled=1)
    log_action("bot", "admin_pin_rotate", None, None, "rotated")
    return jsonify({"ok": True, "new_pin": new_pin, "note": "Показано 1 раз. Збережи!"})

@app.route("/api/bot/admin_pin/disable", methods=["POST"])
@require_bot_role("admin")
def api_bot_admin_pin_disable():
    set_admin_enabled(0)
    log_action("bot", "admin_pin_disable", None, None, "disabled admin login")
    return jsonify({"ok": True, "enabled": False})

@app.route("/api/bot/admin_pin/enable", methods=["POST"])
@require_bot_role("admin")
def api_bot_admin_pin_enable():
    set_admin_enabled(1)
    log_action("bot", "admin_pin_enable", None, None, "enabled admin login")
    return jsonify({"ok": True, "enabled": True})

@app.route("/api/bot/admin_pin/status")
@require_bot_role("admin")
def api_bot_admin_pin_status():
    a = get_admin_auth()
    return jsonify({
        "ok": True,
        "enabled": bool(int(a.get("enabled", 1))),
        "has_pin": bool(a.get("pin_hash")),
        "fallback_enabled": bool(int(a.get("fallback_enabled", 0))),
    })

# ---- maintenance ----
@app.route("/api/bot/maintenance/set", methods=["POST"])
@require_bot_role("admin")
def api_bot_maintenance_set():
    data = request.get_json(silent=True) or {}
    enabled = 1 if bool(data.get("enabled")) else 0
    msg = (data.get("message") or "").strip() or "Тех роботи. Спробуй пізніше."

    conn = get_db()
    cur = conn.cursor()
    db_execute(cur, "UPDATE app_settings SET maintenance_enabled=?, maintenance_message=? WHERE id=1", (enabled, msg))
    conn.commit()
    conn.close()

    log_action("bot", "set_maintenance", None, None, f"enabled={enabled}")
    return jsonify({"ok": True, "enabled": bool(enabled), "message": msg})

# ---- logs ----
@app.route("/api/bot/logs/activations")
@require_bot_role("viewer")
def api_bot_logs_activations():
    q = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit") or "50")
    except ValueError:
        limit = 50
    limit = max(1, min(200, limit))

    conn = get_db()
    cur = conn.cursor()
    if q:
        pat = f"%{q}%"
        rows = db_fetchall(
            cur,
            """
            SELECT id, event, key_value, hwid, ip, created_at
            FROM activations
            WHERE key_value LIKE ? OR hwid LIKE ? OR ip LIKE ? OR event LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (pat, pat, pat, pat, limit),
        )
    else:
        rows = db_fetchall(
            cur,
            "SELECT id, event, key_value, hwid, ip, created_at FROM activations ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    conn.close()
    return jsonify({"ok": True, "rows": [dict(r) for r in rows]})

@app.route("/api/bot/logs/launcher")
@require_bot_role("viewer")
def api_bot_logs_launcher():
    q = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit") or "50")
    except ValueError:
        limit = 50
    limit = max(1, min(200, limit))

    conn = get_db()
    cur = conn.cursor()
    if q:
        pat = f"%{q}%"
        rows = db_fetchall(
            cur,
            """
            SELECT id, action, key_value, details, ip, created_at
            FROM admin_logs
            WHERE actor='launcher' AND (action LIKE ? OR key_value LIKE ? OR details LIKE ? OR ip LIKE ?)
            ORDER BY id DESC
            LIMIT ?
            """,
            (pat, pat, pat, pat, limit),
        )
    else:
        rows = db_fetchall(
            cur,
            """
            SELECT id, action, key_value, details, ip, created_at
            FROM admin_logs
            WHERE actor='launcher'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    conn.close()
    return jsonify({"ok": True, "rows": [dict(r) for r in rows]})

# ---- key actions ----
@app.route("/api/bot/key/ban", methods=["POST"])
@require_bot_role("staff")
def api_bot_key_ban():
    data = request.get_json(silent=True) or {}
    key_value = (data.get("key") or "").strip()
    reason = (data.get("reason") or "bot ban").strip()
    if not key_value:
        return jsonify({"ok": False, "error": "missing_key"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT id, key_value FROM keys WHERE key_value=?", (key_value,))
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    db_execute(cur, "UPDATE keys SET is_banned=1, ban_reason=? WHERE id=?", (reason, row["id"]))
    conn.commit()
    conn.close()
    log_action("bot", "ban_key", row["id"], row["key_value"], reason)
    return jsonify({"ok": True})

@app.route("/api/bot/key/unban", methods=["POST"])
@require_bot_role("staff")
def api_bot_key_unban():
    data = request.get_json(silent=True) or {}
    key_value = (data.get("key") or "").strip()
    if not key_value:
        return jsonify({"ok": False, "error": "missing_key"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT id, key_value FROM keys WHERE key_value=?", (key_value,))
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    db_execute(cur, "UPDATE keys SET is_banned=0, ban_reason=NULL WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    log_action("bot", "unban_key", row["id"], row["key_value"], None)
    return jsonify({"ok": True})

@app.route("/api/bot/key/clear_hwid", methods=["POST"])
@require_bot_role("staff")
def api_bot_key_clear_hwid():
    data = request.get_json(silent=True) or {}
    key_value = (data.get("key") or "").strip()
    if not key_value:
        return jsonify({"ok": False, "error": "missing_key"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT id, key_value FROM keys WHERE key_value=?", (key_value,))
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    db_execute(cur, "UPDATE keys SET hwid=NULL WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    log_action("bot", "clear_hwid", row["id"], row["key_value"], None)
    return jsonify({"ok": True})

@app.route("/api/bot/key/delete", methods=["POST"])
@require_bot_role("admin")
def api_bot_key_delete():
    data = request.get_json(silent=True) or {}
    key_value = (data.get("key") or "").strip()
    if not key_value:
        return jsonify({"ok": False, "error": "missing_key"}), 400

    conn = get_db()
    cur = conn.cursor()
    row = db_fetchone(cur, "SELECT id, key_value FROM keys WHERE key_value=?", (key_value,))
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404

    db_execute(cur, "DELETE FROM keys WHERE id=?", (row["id"],))
    deleted = getattr(cur, "rowcount", 0)
    conn.commit()
    conn.close()
    log_action("bot", "delete_key", row["id"], row["key_value"], f"deleted={deleted}")
    return jsonify({"ok": True, "deleted": int(deleted)})

# ---- upload update via bot ----
@app.route("/api/bot/update/upload", methods=["POST"])
@require_bot_role("admin")
def api_bot_update_upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"ok": False, "error": "missing_file"}), 400

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
    new_id = db_insert_returning_id(
        cur,
        "INSERT INTO updates (filename, stored_path, version, note, uploaded_at, size_bytes) VALUES (?,?,?,?,?,?)",
        (safe_name, stored_name, version, note, now_value(), size_bytes),
    )
    conn.commit()
    conn.close()

    log_action("bot", "upload_update", None, None, f"id={new_id}, file={safe_name}, version={version}")

    return jsonify({
        "ok": True,
        "id": new_id,
        "filename": safe_name,
        "version": version,
        "note": note,
        "size_bytes": size_bytes,
        "uploaded_at": now_value(),
    })


# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)



