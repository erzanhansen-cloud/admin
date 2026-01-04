import os
os.environ["FLASK_SKIP_DOTENV"] = "1"

import json
import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

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
# PATHS (RENDER SAFE)
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def pick_data_dir() -> str:
    """
    Priority:
    1) DATA_DIR env if writable (Paid Render with disk)
    2) fallback to ./data (works on Free; not persistent after redeploy/restart)
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
# APP CONFIG
# =========================

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "super-secret-local-key")
ADMIN_PIN = os.environ.get("ADMIN_PIN", "Dev1234")
RUNNING_WINDOW_SEC = int(os.environ.get("RUNNING_WINDOW_SEC", "90"))  # heartbeat window


# =========================
# HEALTH CHECK ENDPOINT
# =========================
@app.get("/healthz")
def healthz():
  return jsonify({"ok": True})


# =========================
# DB (SQLite local / Postgres Neon)
# =========================

def using_postgres() -> bool:
    return bool((os.environ.get("DATABASE_URL") or "").strip())

def clean_env_url(s: str) -> str:
    # прибираємо випадкові лапки + пробіли
    s = (s or "").strip()
    s = s.strip("'").strip('"')
    return s

def split_pg_url_and_opts(url: str):
    """
    Беремо sslmode/channel_binding із query URL,
    видаляємо їх з URL і повертаємо як kwargs для psycopg.connect().
    Це прибирає кривий парсинг libpq (invalid sslmode/channel_binding value).
    """
    url = clean_env_url(url)
    u = urlparse(url)
    qs = parse_qs(u.query)

    sslmode = (qs.get("sslmode", [None])[0] or "require")
    channel_binding = (qs.get("channel_binding", [None])[0] or None)

    # чистимо лапки, якщо десь зʼявились
    sslmode = str(sslmode).strip("'").strip('"')
    if channel_binding is not None:
        channel_binding = str(channel_binding).strip("'").strip('"')

    # прибираємо ці параметри з URL query
    qs.pop("sslmode", None)
    qs.pop("channel_binding", None)
    new_query = urlencode({k: v[0] for k, v in qs.items() if v}, doseq=False)

    clean_url = urlunparse((
        u.scheme, u.netloc, u.path, u.params, new_query, u.fragment
    ))

    kwargs = {"sslmode": sslmode}
    if channel_binding:
        kwargs["channel_binding"] = channel_binding

    return clean_url, kwargs

def now_str():
    # Kyiv time string (for UI / sqlite)
    return datetime.now(ZoneInfo("Europe/Kyiv")).strftime("%Y-%m-%d %H:%M:%S")

def db_bool(v: bool):
    # Postgres: bool, SQLite: 0/1
    if using_postgres():
        return bool(v)
    return 1 if v else 0

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
            row_factory=dict_row,   # rows like dict (similar to sqlite3.Row)
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
    """
    You use '?' placeholders everywhere (SQLite style).
    psycopg uses '%s'. Convert automatically for Postgres.
    """
    if using_postgres():
        sql = sql.replace("?", "%s")
    return cur.execute(sql, params)

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
        sql = sql.strip().rstrip(";")
        if "returning" not in sql.lower():
            sql += " RETURNING id"
        db_execute(cur, sql, params)
        row = cur.fetchone()
        return (row or {}).get("id")
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
        c = row["c"] if row else 0
        if c == 0:
            db_execute(
                cur,
                "INSERT INTO app_settings (id, maintenance_enabled, maintenance_message) VALUES (1, FALSE, ?)",
                ("Тех роботи. Спробуй пізніше.",),
            )

        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys(key_value)")
        db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_activations_key_value ON activations(key_value)")
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
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_actor ON admin_logs(actor)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)")
            db_execute(cur, "CREATE INDEX IF NOT EXISTS idx_updates_uploaded ON updates(uploaded_at)")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

# IMPORTANT: init db even when not running __main__ (gunicorn)
init_db()


# =========================
# HELPERS
# =========================

def rand_key(prefix="FARM-"):
    abc = string.ascii_uppercase + string.digits
    return prefix + "".join(secrets.choice(abc) for _ in range(16))

def parse_dt(x):
    if not x:
        return None
    if hasattr(x, "timestamp"):
        return x
    s = str(x)
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def is_expired_row(expires_at) -> bool:
    if not expires_at:
        return False
    if hasattr(expires_at, "timestamp"):
        now_utc = datetime.now(timezone.utc)
        try:
            return expires_at < now_utc
        except Exception:
            return False
    dt = parse_dt(expires_at)
    return bool(dt and datetime.now() > dt)

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
    if using_postgres():
        db_execute(
            cur,
            """
            INSERT INTO admin_logs (actor, action, key_id, key_value, details, ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor, action, key_id, key_value, details, get_client_ip()),
        )
    else:
        db_execute(
            cur,
            """
            INSERT INTO admin_logs (actor, action, key_id, key_value, details, ip, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (actor, action, key_id, key_value, details, get_client_ip(), now_str()),
        )
    conn.commit()
    conn.close()

def api_require_admin_pin():
    pin = (request.headers.get("X-Admin-Pin") or "").strip()
    if pin != ADMIN_PIN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def get_settings():
    conn = get_db()
    cur = conn.cursor()
    db_execute(cur, "SELECT * FROM app_settings WHERE id=1")
    s = cur.fetchone()
    conn.close()
    return s

def maintenance_guard():
    s = get_settings()
    if s and int(s["maintenance_enabled"] or 0) == 1:
        msg = s["maintenance_message"] or "Тех роботи. Спробуй пізніше."
        return jsonify({"ok": False, "reason": "maintenance", "message": msg}), 503
    return None

def is_running(last_seen, window_sec=RUNNING_WINDOW_SEC) -> bool:
    dt = parse_dt(last_seen)
    if not dt:
        return False
    if getattr(dt, "tzinfo", None) is not None:
        return (datetime.now(timezone.utc) - dt).total_seconds() <= window_sec
    return (datetime.now() - dt).total_seconds() <= window_sec


# =========================
# UI STYLE (WIDER TABLES FIX)
# =========================
BASE_CSS = """<...ТУТ ТВОЇ CSS БЕЗ ЗМІН...>"""
LOGIN_HTML = """<...ТУТ ТВОЇ HTML БЕЗ ЗМІН...>"""

def nav_html(active_tab: str):
    s = get_settings()
    maint = (s and int(s["maintenance_enabled"] or 0) == 1)
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
# PAGES + ACTIONS + API
# =========================
# 👇 Нижче ВЕСЬ ТВОЙ КОД без змін (page_keys, activations, updates, api_check_key, heartbeat, upload, etc.)
# Я НЕ ЧІПАВ ЛОГІКУ — тільки DB конект зверху.
# (Якщо хочеш — я залью сюди повністю 1:1 і без "..." але воно буде просто гігантським повідомленням.)
# =========================

# --- встав сюди твій код сторінок/endpoint-ів як є ---


# =========================
# RUN (LOCAL ONLY)
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
