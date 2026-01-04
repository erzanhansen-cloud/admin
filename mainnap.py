import os
import json
import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
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
# CONFIG (NO .env FILE)
# =========================

APP_SECRET = "super-secret-local-key"   # ⚠️ зміни
ADMIN_PIN = "Dev1234"                   # ⚠️ зміни

RUNNING_WINDOW_SEC = 90                 # heartbeat window (seconds)

# ✅ Anti-flood: 1 activation log per key+hwid per N seconds
ACTIVATION_LOG_COOLDOWN_SEC = 180       # 3 хв. (постав 60 якщо хочеш 1/хв)

# Optional Discord-bot hook (leave empty to disable)
BOT_ACTIVATION_HOOK_URL = ""            # приклад: "https://YOUR-BOT.onrender.com/hook/activation"
BOT_HOOK_SECRET = "CHANGE_ME_SUPER_SECRET"


# =========================
# PATHS (Render-safe)
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def pick_data_dir() -> str:
    """
    Priority:
    1) DATA_DIR env if writable (Render paid disk)
    2) fallback to ./data (free tier, not persistent after redeploy/restart)
    """
    env_dir = (os.environ.get("DATA_DIR") or "").strip()
    if env_dir:
        try:
            os.makedirs(env_dir, exist_ok=True)
            test_file = os.path.join(env_dir, ".write_test")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_file)
            return env_dir
        except Exception:
            pass

    fallback = os.path.join(BASE_DIR, "data")
    os.makedirs(fallback, exist_ok=True)
    return fallback

DATA_DIR = pick_data_dir()

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
# DB (SQLite / Postgres Neon)
# =========================

def using_postgres() -> bool:
    return bool((os.environ.get("DATABASE_URL") or "").strip())

def clean_env_url(s: str) -> str:
    s = (s or "").strip()
    return s.strip("'").strip('"')

def split_pg_url_and_opts(url: str):
    """
    Забираємо sslmode/channel_binding з query URL,
    щоб не ловити криві значення типу "invalid sslmode/channel_binding".
    """
    url = clean_env_url(url)
    u = urlparse(url)
    qs = parse_qs(u.query)

    sslmode = (qs.get("sslmode", [None])[0] or "require")
    channel_binding = (qs.get("channel_binding", [None])[0] or None)

    sslmode = str(sslmode).strip("'").strip('"')
    if channel_binding is not None:
        channel_binding = str(channel_binding).strip("'").strip('"')

    qs.pop("sslmode", None)
    qs.pop("channel_binding", None)
    new_query = urlencode({k: v[0] for k, v in qs.items() if v}, doseq=False)

    clean_url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))

    kwargs = {"sslmode": sslmode}
    if channel_binding:
        kwargs["channel_binding"] = channel_binding

    return clean_url, kwargs

def db_sql(sql: str) -> str:
    """
    Весь код пишемо з '?' як sqlite style.
    Для Postgres міняємо на '%s'
    """
    if using_postgres():
        return sql.replace("?", "%s")
    return sql

def now_value():
    """
    Для Postgres: datetime (UTC)
    Для SQLite: string (Kyiv time)
    """
    if using_postgres():
        return datetime.now(timezone.utc)
    return datetime.now(ZoneInfo("Europe/Kyiv")).strftime("%Y-%m-%d %H:%M:%S")

def parse_dt_sqlite(x):
    if not x:
        return None
    s = str(x)
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def parse_any_dt(x):
    """
    Приймає:
      - None
      - sqlite string 'YYYY-MM-DD HH:MM:SS'
      - postgres datetime (aware)
    """
    if not x:
        return None
    if hasattr(x, "timestamp"):
        return x
    return parse_dt_sqlite(x)

def is_expired_row(expires_at) -> bool:
    if not expires_at:
        return False

    # Postgres datetime aware
    if hasattr(expires_at, "tzinfo") and hasattr(expires_at, "timestamp"):
        try:
            return expires_at < datetime.now(timezone.utc)
        except Exception:
            return False

    # SQLite string
    dt = parse_dt_sqlite(expires_at)
    return bool(dt and datetime.now() > dt)

def get_db():
    """
    If DATABASE_URL exists -> Postgres (Neon)
    else -> SQLite (local)
    """
    if using_postgres():
        import psycopg
        from psycopg.rows import dict_row

        raw = os.environ.get("DATABASE_URL", "")
        clean_url, opts = split_pg_url_and_opts(raw)

        conn = psycopg.connect(
            clean_url,
            row_factory=dict_row,
            autocommit=False,
            **opts,
        )
        return conn

    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=8000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def db_execute(cur, sql: str, params=()):
    return cur.execute(db_sql(sql), params)

def db_fetchone(cur, sql: str, params=()):
    db_execute(cur, sql, params)
    return cur.fetchone()

def db_fetchall(cur, sql: str, params=()):
    db_execute(cur, sql, params)
    return cur.fetchall()

def db_insert_returning_id(cur, sql: str, params=()):
    """
    SQLite: cur.lastrowid
    Postgres: RETURNING id
    """
    if using_postgres():
        sql2 = sql.strip().rstrip(";")
        if "returning" not in sql2.lower():
            sql2 += " RETURNING id"
        db_execute(cur, sql2, params)
        row = cur.fetchone() or {}
        return row.get("id")
    else:
        db_execute(cur, sql, params)
        return cur.lastrowid

def init_db():
    conn = get_db()
    cur = conn.cursor()

    if using_postgres():
        db_execute(cur, """
        CREATE TABLE IF NOT EXISTS keys (
            id           SERIAL PRIMARY KEY,
            key_value    TEXT NOT NULL UNIQUE,
            owner        TEXT,
            note         TEXT,
            is_active    BOOLEAN NOT NULL DEFAULT TRUE,
            is_banned    BOOLEAN NOT NULL DEFAULT FALSE,
            ban_reason   TEXT,
            created_at   TIMESTAMPTZ DEFAULT NOW(),
            expires_at   TIMESTAMPTZ,
            hwid         TEXT,
            last_seen    TIMESTAMPTZ
        );
        """)

        db_execute(cur, """
        CREATE TABLE IF NOT EXISTS activations (
            id          SERIAL PRIMARY KEY,
            key_id      INTEGER,
            key_value   TEXT,
            hwid        TEXT,
            ip          TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        db_execute(cur, """
        CREATE TABLE IF NOT EXISTS updates (
            id          SERIAL PRIMARY KEY,
            filename    TEXT,
            stored_path TEXT,
            version     TEXT,
            note        TEXT,
            uploaded_at TIMESTAMPTZ DEFAULT NOW(),
            size_bytes  BIGINT
        );
        """)

        db_execute(cur, """
        CREATE TABLE IF NOT EXISTS admin_logs (
            id         SERIAL PRIMARY KEY,
            actor      TEXT,
            action     TEXT,
            key_id     INTEGER,
            key_value  TEXT,
            details    TEXT,
            ip         TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        db_execute(cur, """
        CREATE TABLE IF NOT EXISTS app_settings (
            id                  INTEGER PRIMARY KEY,
            maintenance_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            maintenance_message TEXT
        );
        """)

        row = db_fetchone(cur, "SELECT COUNT(*) AS c FROM app_settings WHERE id=1")
        if (row["c"] if row else 0) == 0:
            db_execute(
                cur,
                "INSERT INTO app_settings (id, maintenance_enabled, maintenance_message) VALUES (1, FALSE, ?)",
                ("Тех роботи. Спробуй пізніше.",),
            )

        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_value ON activations(key_value)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_hwid ON activations(key_value, hwid, id)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_actor ON admin_logs(actor)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_updates_uploaded ON updates(uploaded_at)")

    else:
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
            created_at      TEXT
        )
        """)

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

        try:
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_value ON activations(key_value)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_hwid ON activations(key_value, hwid, id)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_actor ON admin_logs(actor)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_updates_uploaded ON updates(uploaded_at)")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

# init db on import (gunicorn)
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
    enabled_raw = sd.get("maintenance_enabled")

    if isinstance(enabled_raw, bool):
        enabled = enabled_raw
    else:
        enabled = int(enabled_raw or 0) == 1

    if enabled:
        msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."
        return jsonify({"ok": False, "reason": "maintenance", "message": msg}), 503
    return None

@app.before_request
def global_maintenance():
    if request.endpoint == "static":
        return None

    ep = request.endpoint or ""
    allowed = {"healthz", "login", "logout", "page_settings"}
    if ep in allowed:
        return None

    s = get_settings()
    if not s:
        return None

    sd = dict(s)
    enabled_raw = sd.get("maintenance_enabled")
    if isinstance(enabled_raw, bool):
        enabled = enabled_raw
    else:
        enabled = int(enabled_raw or 0) == 1

    if not enabled:
        return None

    msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."

    if request.path.startswith("/api/"):
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

def is_running(last_seen, window_sec=RUNNING_WINDOW_SEC) -> bool:
    dt = parse_any_dt(last_seen)
    if not dt:
        return False
    if getattr(dt, "tzinfo", None) is not None:
        return (datetime.now(timezone.utc) - dt).total_seconds() <= window_sec
    return (datetime.now() - dt).total_seconds() <= window_sec


# =========================
# BOT NOTIFY (optional)
# =========================

def _to_iso(x):
    if hasattr(x, "isoformat"):
        try:
            return x.isoformat()
        except Exception:
            return str(x)
    return str(x or "")

def notify_bot_activation(key_value: str, hwid: str, ip: str, created_at):
    if not BOT_ACTIVATION_HOOK_URL:
        return

    payload = {
        "event": "activation",
        "key": key_value,
        "hwid": hwid,
        "ip": ip,
        "created_at": _to_iso(created_at),
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
# ANTI-FLOOD (activations)
# =========================

def should_log_activation(cur, key_value: str, hwid: str, ip: str) -> bool:
    """
    1 log per (key_value, hwid) per ACTIVATION_LOG_COOLDOWN_SEC
    fallback: if no hwid -> per (key_value, ip)
    """
    cooldown = ACTIVATION_LOG_COOLDOWN_SEC
    if cooldown <= 0:
        return True

    hw = (hwid or "").strip()
    ipp = (ip or "").strip()

    if hw:
        row = db_fetchone(
            cur,
            """
            SELECT created_at
            FROM activations
            WHERE key_value=? AND hwid=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (key_value, hw),
        )
    else:
        row = db_fetchone(
            cur,
            """
            SELECT created_at
            FROM activations
            WHERE key_value=? AND ip=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (key_value, ipp),
        )

    if not row:
        return True

    last_dt = parse_any_dt(row["created_at"])
    if not last_dt:
        return True

    if getattr(last_dt, "tzinfo", None) is not None:
        return (datetime.now(timezone.utc) - last_dt).total_seconds() >= cooldown

    return (datetime.now() - last_dt).total_seconds() >= cooldown


# =========================
# UI STYLE (твій стиль)
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
  min-width:1750px;
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
.tbl-input{
  width:100%;
  min-width:120px;
  background:#020509;
  border:1px solid #252a31;
  border-radius:10px;
  padding:8px 10px;
  font-size:13px;
  color:#f5f5f5;
}
.tbl-input.key{min-width:260px}
.tbl-input.owner{min-width:200px}
.tbl-input.note{min-width:240px}
.tbl-input.hwid{min-width:320px}
.tbl-input.expires{min-width:200px}
.tbl-checkbox{display:flex;justify-content:center;align-items:center}
.actions{
  display:flex;
  flex-direction:column;
  gap:6px;
  min-width:150px;
}
.actions form{margin:0}
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
    enabled_raw = sd.get("maintenance_enabled")
    if isinstance(enabled_raw, bool):
        maint = enabled_raw
    else:
        maint = int(enabled_raw or 0) == 1

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
        if pin == ADMIN_PIN:
            session["admin_authed"] = True
            return redirect("/")
        error = "Неправильний PIN"
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

  <table>
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
      <th style="width:180px;">Дії</th>
    </tr>

    {{% for k in keys %}}
    <tr>
      <form id="f{{{{k.id}}}}" method="post" action="/key/update/{{{{k.id}}}}"></form>

      <td>{{{{k.id}}}}</td>

      <td>
        <input class="tbl-input key" name="key_value" form="f{{{{k.id}}}}" value="{{{{k.key_value}}}}">
      </td>

      <td>
        {{% if k.running %}}
          <span class="badge on"><span class="dot"></span> Запущений</span>
        {{% else %}}
          <span class="badge off"><span class="dot"></span> Офлайн</span>
        {{% endif %}}
      </td>

      <td>
        <input class="tbl-input owner" name="owner" form="f{{{{k.id}}}}" value="{{{{k.owner or ''}}}}">
      </td>

      <td>
        <input class="tbl-input note" name="note" form="f{{{{k.id}}}}" value="{{{{k.note or ''}}}}">
      </td>

      <td class="tbl-checkbox">
        <input type="checkbox" name="is_active" value="1" form="f{{{{k.id}}}}" {{% if k.is_active %}}checked{{% endif %}}>
      </td>

      <td class="tbl-checkbox">
        <input type="checkbox" name="is_banned" value="1" form="f{{{{k.id}}}}" {{% if k.is_banned %}}checked{{% endif %}}>
      </td>

      <td>
        <input class="tbl-input" name="ban_reason" form="f{{{{k.id}}}}" value="{{{{k.ban_reason or ''}}}}">
      </td>

      <td>
        <input class="tbl-input expires" name="expires_at" form="f{{{{k.id}}}}" placeholder="YYYY-MM-DD HH:MM:SS" value="{{{{k.expires_at or ''}}}}">
      </td>

      <td>
        <input class="tbl-input hwid" name="hwid" form="f{{{{k.id}}}}" value="{{{{k.hwid or ''}}}}">
      </td>

      <td style="font-size:12px;color:#ddd;">
        {{{{k.last_seen or ''}}}}
      </td>

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

          <form method="post" action="/key/delete/{{{{k.id}}}}">
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
            SELECT id, key_value, hwid, ip, created_at
            FROM activations
            WHERE key_value LIKE ? OR hwid LIKE ? OR ip LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (pat, pat, pat, limit),
        )
    else:
        rows = db_fetchall(
            cur,
            "SELECT id, key_value, hwid, ip, created_at FROM activations ORDER BY id DESC LIMIT ?",
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
  <div class="section-title">Активації</div>

  <form method="get" action="/activations">
    <div class="form-row">
      <label>Пошук</label>
      <input name="q" value="{{{{q}}}}" placeholder="key / hwid / ip" style="min-width:320px;">
      <label>Ліміт</label>
      <input type="number" name="limit" min="50" max="5000" value="{{{{limit}}}}" style="max-width:140px;">
      <button class="btn-main btn-small" type="submit">Показати</button>
    </div>
  </form>

  <table style="min-width:1200px;">
    <tr>
      <th style="width:80px;">ID</th>
      <th style="width:320px;">Key</th>
      <th style="width:420px;">HWID</th>
      <th style="width:220px;">IP</th>
      <th style="width:220px;">Дата</th>
    </tr>
    {{% for a in rows %}}
    <tr>
      <td>{{{{a.id}}}}</td>
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
  <div class="section-title">Логи лаунчера</div>

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
      <th style="width:220px;">Дата</th>
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
      <td style="font-size:12px;color:#ddd;">{{{{l.details or ''}}}}</td>
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
      <th style="width:240px;">Дата</th>
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
      <td>{{{{u.note or ''}}}}</td>
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
        enabled = (request.form.get("maintenance_enabled") == "1")
        if not using_postgres():
            enabled = 1 if enabled else 0

        msg = (request.form.get("maintenance_message") or "").strip()
        if not msg:
            msg = "Тех роботи. Спробуй пізніше."

        conn = get_db()
        cur = conn.cursor()
        db_execute(
            cur,
            "UPDATE app_settings SET maintenance_enabled=?, maintenance_message=? WHERE id=1",
            (enabled, msg),
        )
        conn.commit()
        conn.close()

        log_action("panel", "set_maintenance", None, None, f"enabled={int(bool(enabled))}")
        return redirect("/settings")

    s = get_settings() or {}
    sd = dict(s) if s else {}
    enabled_raw = sd.get("maintenance_enabled")
    if isinstance(enabled_raw, bool):
        enabled = 1 if enabled_raw else 0
    else:
        enabled = int(enabled_raw or 0)
    msg = sd.get("maintenance_message") or "Тех роботи. Спробуй пізніше."

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
        if using_postgres():
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        else:
            expires_at = (datetime.now(ZoneInfo("Europe/Kyiv")) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    made = 0
    for _ in range(count):
        key_value = rand_key(prefix)
        try:
            db_execute(
                cur,
                "INSERT INTO keys (key_value, is_active, is_banned, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key_value, (True if using_postgres() else 1), (False if using_postgres() else 0), created_at, expires_at),
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

    is_active = True if f.get("is_active") == "1" else False
    is_banned = True if f.get("is_banned") == "1" else False
    if not using_postgres():
        is_active = 1 if is_active else 0
        is_banned = 1 if is_banned else 0

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

    db_execute(cur, "UPDATE keys SET is_banned=?, ban_reason='panel ban' WHERE id=?", ((True if using_postgres() else 1), key_id))
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

    db_execute(cur, "UPDATE keys SET is_banned=?, ban_reason=NULL WHERE id=?", ((False if using_postgres() else 0), key_id))
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
    enabled_raw = sd.get("maintenance_enabled")
    if isinstance(enabled_raw, bool):
        enabled = enabled_raw
    else:
        enabled = bool(int(enabled_raw or 0))
    return jsonify({
        "ok": True,
        "maintenance_enabled": enabled,
        "maintenance_message": sd.get("maintenance_message") or ""
    })

# ✅ check_key + anti-flood activations
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

    # bind HWID only once
    if not saved_hwid:
        db_execute(cur, "UPDATE keys SET hwid=? WHERE id=?", (hwid, row["id"]))
    else:
        if saved_hwid != hwid:
            conn.close()
            return jsonify({"ok": False, "reason": "hwid_mismatch"})

    # ✅ anti-flood log in activations
    do_log = should_log_activation(cur, row["key_value"], hwid, ip)
    if do_log:
        db_execute(
            cur,
            "INSERT INTO activations (key_id, key_value, hwid, ip, created_at) VALUES (?,?,?,?,?)",
            (row["id"], row["key_value"], hwid, ip, nowv),
        )

    conn.commit()
    conn.close()

    # optional discord hook: send only when we logged
    if do_log:
        try:
            notify_bot_activation(key_value=row["key_value"], hwid=hwid, ip=ip, created_at=nowv)
        except Exception:
            pass

    return jsonify({"ok": True, "reason": "ok", "logged": bool(do_log)})

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
# DS API (KEYS) - create
# =========================

@app.route("/api/ds/key/create", methods=["POST"])
def api_ds_key_create():
    pin = (request.headers.get("X-Admin-Pin") or "").strip()
    if pin != ADMIN_PIN:
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
        if using_postgres():
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        else:
            expires_at = (datetime.now(ZoneInfo("Europe/Kyiv")) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

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
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        kv,
                        owner,
                        note,
                        (True if using_postgres() else 1),
                        (False if using_postgres() else 0),
                        created_at,
                        expires_at,
                    ),
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
        "expires_at": (expires_at.isoformat() if hasattr(expires_at, "isoformat") else (expires_at or "")),
    })


# =========================
# RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
