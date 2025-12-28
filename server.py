# server.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo

from flask import Flask, request, redirect, url_for, session, jsonify, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# CONFIG
# =========================
APP_TITLE = "Панель керування ключами"
DB_PATH = os.environ.get("LICENSE_DB", "license_admin.db")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")  # ЗМІНИ В ПРОДІ
SECRET_KEY = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

PORT = int(os.environ.get("PORT", "5000"))
TZ = ZoneInfo("Europe/Kyiv")

# 1 = повна очистка ключів/логів/хвід при старті
WIPE_ON_START = os.environ.get("WIPE_ON_START", "0") == "1"

# авто-очистка логів
LOG_RETENTION_DAYS = int(os.environ.get("LOG_RETENTION_DAYS", "30"))

# авто-архів прострочених ключів
AUTO_ARCHIVE_EXPIRED = os.environ.get("AUTO_ARCHIVE_EXPIRED", "1") == "1"


# =========================
# APP
# =========================
app = Flask(__name__)
app.secret_key = SECRET_KEY


# =========================
# TIME (UA)
# =========================
def now_ua() -> datetime:
    return datetime.now(TZ)


def iso_ua(dt: datetime | None = None) -> str:
    if dt is None:
        dt = now_ua()
    return dt.isoformat(timespec="seconds")


def parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt


# =========================
# DB
# =========================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return bool(r)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cols = set()
    if not _table_exists(conn, table):
        return cols
    for r in conn.execute(f"PRAGMA table_info({table})").fetchall():
        cols.add(r["name"])
    return cols


def _add_column_if_missing(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    cols = _columns(conn, table)
    if col not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pass_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS license_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_hwids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                hwid TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(key_id, hwid)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                level TEXT NOT NULL,
                action TEXT NOT NULL,
                key_id INTEGER,
                license_key TEXT,
                ip TEXT,
                user_agent TEXT,
                message TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_hwids_key_id ON key_hwids(key_id);
            CREATE INDEX IF NOT EXISTS idx_keys_key ON license_keys(license_key);
            CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at);
            """
        )

        # --- migrations for license_keys
        _add_column_if_missing(conn, "license_keys", "banned_reason", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "license_keys", "frozen", "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "license_keys", "freeze_reason", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "license_keys", "note", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "license_keys", "hwid_limit", "INTEGER NOT NULL DEFAULT 1")
        _add_column_if_missing(conn, "license_keys", "last_used_at", "TEXT DEFAULT NULL")
        _add_column_if_missing(conn, "license_keys", "last_ip", "TEXT DEFAULT NULL")
        _add_column_if_missing(conn, "license_keys", "uses_count", "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "license_keys", "archived", "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "license_keys", "archived_at", "TEXT DEFAULT NULL")

        # indexes (safe)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON license_keys(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_archived ON license_keys(archived)")

        # admin seed
        row = conn.execute("SELECT id FROM admins WHERE username=?", (ADMIN_USER,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO admins(username, pass_hash, created_at) VALUES(?,?,?)",
                (ADMIN_USER, generate_password_hash(ADMIN_PASS), iso_ua()),
            )

        if WIPE_ON_START:
            conn.execute("DELETE FROM key_hwids")
            conn.execute("DELETE FROM license_keys")
            conn.execute("DELETE FROM logs")


def req_ip() -> str:
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()


def req_ua() -> str:
    return request.headers.get("User-Agent", "")


def log_event(level: str, action: str, message: str = "", key_id=None, license_key=None) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO logs(created_at,level,action,key_id,license_key,ip,user_agent,message)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (iso_ua(), level, action, key_id, license_key, req_ip(), req_ua(), message),
        )


# =========================
# AUTO MAINTENANCE
# =========================
_last_maintenance: datetime | None = None


def maintenance_tick(force: bool = False) -> None:
    global _last_maintenance
    now = now_ua()
    if (not force) and _last_maintenance and (now - _last_maintenance) < timedelta(minutes=10):
        return
    _last_maintenance = now

    cutoff_logs = now - timedelta(days=LOG_RETENTION_DAYS)

    with db() as conn:
        # delete old logs
        conn.execute("DELETE FROM logs WHERE created_at < ?", (iso_ua(cutoff_logs),))

        if AUTO_ARCHIVE_EXPIRED:
            rows = conn.execute(
                "SELECT id, license_key, expires_at, archived FROM license_keys WHERE archived=0"
            ).fetchall()
            for r in rows:
                try:
                    exp = parse_dt(r["expires_at"])
                except Exception:
                    continue
                if exp < now:
                    conn.execute(
                        "UPDATE license_keys SET archived=1, archived_at=? WHERE id=?",
                        (iso_ua(), r["id"]),
                    )
                    log_event("info", "KEY_ARCHIVE_EXPIRED", "авто-архів простроченого ключа", r["id"], r["license_key"])


@app.before_request
def _before():
    try:
        maintenance_tick(False)
    except Exception:
        pass


# =========================
# AUTH
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


# =========================
# KEY HELPERS
# =========================
def gen_key() -> str:
    # формат як на прикладі: 6BE79-C3B183
    part1 = secrets.token_hex(3).upper()[:5]
    part2 = secrets.token_hex(3).upper()
    return f"{part1}-{part2}"


def is_expired(expires_at: str) -> bool:
    try:
        return parse_dt(expires_at) < now_ua()
    except Exception:
        return False


def ui_status(row: sqlite3.Row) -> str:
    if int(row["archived"] or 0) == 1:
        return "архів"
    if int(row["frozen"] or 0) == 1:
        return "заморожено"
    if (row["status"] or "") == "banned":
        return "забанено"
    if is_expired(row["expires_at"]):
        return "прострочено"
    return "активний"


def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# =========================
# API (для лаунчера)
# =========================
@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True, "time": iso_ua()})


@app.route("/api/check", methods=["POST"])
def api_check():
    """
    JSON:
      { "key": "...", "hwid": "...", "meta": {...} }
    Відповідь:
      ok: true/false
      status: ok/banned/frozen/expired/archived/not_found/bad_request
      reason: ...
      days_left: int
    """
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not key or not hwid:
        return jsonify({"ok": False, "status": "bad_request", "reason": "key/hwid_required"}), 400

    ip = req_ip()

    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE license_key=?", (key,)).fetchone()
        if not row:
            log_event("warn", "API_CHECK_FAIL", "ключ не знайдено", None, key)
            return jsonify({"ok": False, "status": "not_found"}), 404

        key_id = row["id"]

        # archived
        if int(row["archived"] or 0) == 1:
            log_event("warn", "API_CHECK_DENY", "архівний ключ", key_id, key)
            return jsonify({"ok": False, "status": "archived"}), 403

        # expired -> archive
        if is_expired(row["expires_at"]):
            if AUTO_ARCHIVE_EXPIRED:
                conn.execute("UPDATE license_keys SET archived=1, archived_at=? WHERE id=?", (iso_ua(), key_id))
                log_event("info", "KEY_ARCHIVE_EXPIRED", "прострочено -> архів (API)", key_id, key)
            return jsonify({"ok": False, "status": "expired"}), 403

        # frozen
        if int(row["frozen"] or 0) == 1:
            log_event("warn", "API_CHECK_DENY", f"заморожено: {row['freeze_reason']}", key_id, key)
            return jsonify({"ok": False, "status": "frozen", "reason": row["freeze_reason"]}), 403

        # banned
        if (row["status"] or "") == "banned":
            log_event("warn", "API_CHECK_DENY", f"бан: {row['banned_reason']}", key_id, key)
            return jsonify({"ok": False, "status": "banned", "reason": row["banned_reason"]}), 403

        # =========================
        # HWID protection (1–2) + auto-ban when limit exceeded
        # =========================
        limit_ = int(row["hwid_limit"] or 1)
        limit_ = 1 if limit_ <= 1 else 2

        hwids = conn.execute(
            "SELECT hwid FROM key_hwids WHERE key_id=? ORDER BY id ASC",
            (key_id,),
        ).fetchall()
        hwid_list = [r["hwid"] for r in hwids]

        if hwid in hwid_list:
            conn.execute(
                "UPDATE key_hwids SET last_seen=? WHERE key_id=? AND hwid=?",
                (iso_ua(), key_id, hwid),
            )
        else:
            if len(hwid_list) >= limit_:
                conn.execute(
                    "UPDATE license_keys SET status='banned', banned_reason=? WHERE id=?",
                    ("HWID_LIMIT", key_id),
                )
                log_event(
                    "warn",
                    "SUSPICIOUS_HWID_CHANGE",
                    f"перевищено ліміт HWID: limit={limit_}, old={hwid_list}, new={hwid}, ip={ip}",
                    key_id,
                    key,
                )
                log_event("warn", "KEY_AUTO_BAN", "авто-бан за шарінг/зміну HWID", key_id, key)
                return jsonify({"ok": False, "status": "banned", "reason": "HWID_LIMIT"}), 403

            conn.execute(
                "INSERT INTO key_hwids(key_id, hwid, first_seen, last_seen) VALUES(?,?,?,?)",
                (key_id, hwid, iso_ua(), iso_ua()),
            )
            if len(hwid_list) >= 1:
                log_event(
                    "warn",
                    "SUSPICIOUS_HWID_NEW",
                    f"новий HWID додано: limit={limit_}, old={hwid_list}, new={hwid}, ip={ip}",
                    key_id,
                    key,
                )

        # mark usage
        conn.execute(
            """
            UPDATE license_keys
            SET last_used_at=?, last_ip=?, uses_count=uses_count+1
            WHERE id=?
            """,
            (iso_ua(), ip, key_id),
        )

        exp = parse_dt(row["expires_at"])
        delta = exp - now_ua()
        days_left = max(0, int(delta.total_seconds() // 86400))

    log_event("info", "API_CHECK_OK", f"ok, days_left={days_left}", key_id, key)
    return jsonify({"ok": True, "status": "ok", "days_left": days_left})


# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    return Response("", mimetype="text/plain")


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.args.get("next") or "/admin"
    err = ""
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        with db() as conn:
            a = conn.execute("SELECT * FROM admins WHERE username=?", (u,)).fetchone()
        if a and check_password_hash(a["pass_hash"], p):
            session["admin"] = u
            log_event("info", "LOGIN", f"адмін={u}")
            return redirect(nxt)
        err = "Невірний логін або пароль"
        log_event("warn", "LOGIN_FAIL", f"адмін={u}")
    return html_page(login_html(err))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/admin")
@login_required
def admin():
    return render_keys("all")


@app.route("/banned")
@login_required
def banned():
    return render_keys("banned")


@app.route("/frozen")
@login_required
def frozen():
    return render_keys("frozen")


@app.route("/archive")
@login_required
def archive():
    return render_keys("archive")


def render_keys(view: str):
    q = (request.args.get("q") or "").strip()
    page = max(1, int(request.args.get("page") or "1"))
    per_page = 10
    offset = (page - 1) * per_page

    where = []
    params = []

    if view == "banned":
        where.append("archived=0 AND status='banned'")
    elif view == "frozen":
        where.append("archived=0 AND frozen=1")
    elif view == "archive":
        where.append("archived=1")
    else:
        where.append("archived=0")

    if q:
        where.append("(license_key LIKE ? OR note LIKE ? OR last_ip LIKE ?)")
        params.extend([f"%{q}%"] * 3)

    where_sql = " WHERE " + " AND ".join(where)

    with db() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM license_keys WHERE archived=0").fetchone()["c"]
        active = conn.execute("SELECT COUNT(*) AS c FROM license_keys WHERE archived=0 AND status='active' AND frozen=0").fetchone()["c"]
        banned_cnt = conn.execute("SELECT COUNT(*) AS c FROM license_keys WHERE archived=0 AND status='banned'").fetchone()["c"]
        frozen_cnt = conn.execute("SELECT COUNT(*) AS c FROM license_keys WHERE archived=0 AND frozen=1").fetchone()["c"]
        arch_cnt = conn.execute("SELECT COUNT(*) AS c FROM license_keys WHERE archived=1").fetchone()["c"]

        since = iso_ua(now_ua() - timedelta(hours=24))
        logs_24h = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE created_at >= ?", (since,)).fetchone()["c"]

        total_filtered = conn.execute(f"SELECT COUNT(*) AS c FROM license_keys {where_sql}", params).fetchone()["c"]

        rows = conn.execute(
            f"""
            SELECT * FROM license_keys
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, per_page, offset),
        ).fetchall()

    total_pages = max(1, (total_filtered + per_page - 1) // per_page)

    base_path = {
        "all": "/admin",
        "banned": "/banned",
        "frozen": "/frozen",
        "archive": "/archive",
    }[view]

    return html_page(
        dashboard_html(
            base_path=base_path,
            view=view,
            total=total,
            active=active,
            banned=banned_cnt,
            frozen=frozen_cnt,
            archived=arch_cnt,
            logs_24h=logs_24h,
            rows=[dict(r) | {"status_ui": ui_status(r)} for r in rows],
            q=q,
            page=page,
            total_pages=total_pages,
        )
    )


@app.route("/logs")
@login_required
def logs():
    q = (request.args.get("q") or "").strip()
    page = max(1, int(request.args.get("page") or "1"))
    per_page = 30
    offset = (page - 1) * per_page

    where = []
    params = []
    if q:
        where.append("(action LIKE ? OR message LIKE ? OR license_key LIKE ? OR ip LIKE ?)")
        params.extend([f"%{q}%"] * 4)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM logs {where_sql}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM logs {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, per_page, offset),
        ).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)
    return html_page(logs_html(rows, q, page, total_pages))


# =========================
# ADMIN ACTIONS
# =========================
@app.route("/admin/generate", methods=["POST"])
@login_required
def admin_generate():
    days = int(request.form.get("days") or "30")
    days = max(1, min(days, 3650))
    note = (request.form.get("note") or "").strip()
    hwid_limit = int(request.form.get("hwid_limit") or "1")
    hwid_limit = 1 if hwid_limit <= 1 else 2

    key = gen_key()
    created = now_ua()
    expires = created + timedelta(days=days)

    with db() as conn:
        conn.execute(
            """
            INSERT INTO license_keys(
                license_key,status,banned_reason,frozen,freeze_reason,note,hwid_limit,
                created_at,expires_at,last_used_at,last_ip,uses_count,archived,archived_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                key, "active", "", 0, "", note, hwid_limit,
                iso_ua(created), iso_ua(expires), None, None, 0, 0, None
            ),
        )
    log_event("info", "KEY_CREATE", f"створено на {days} дн, hwid_limit={hwid_limit}", None, key)
    return redirect(request.referrer or "/admin")


@app.route("/admin/ban/<int:key_id>", methods=["POST"])
@login_required
def admin_ban(key_id: int):
    reason = (request.form.get("reason") or "").strip() or "MANUAL"
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET status='banned', banned_reason=? WHERE id=?", (reason, key_id))
    log_event("warn", "KEY_BAN", f"бан ({reason})", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/unban/<int:key_id>", methods=["POST"])
@login_required
def admin_unban(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET status='active', banned_reason='' WHERE id=?", (key_id,))
    log_event("info", "KEY_UNBAN", "розбан", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/freeze/<int:key_id>", methods=["POST"])
@login_required
def admin_freeze(key_id: int):
    reason = (request.form.get("reason") or "").strip()
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET frozen=1, freeze_reason=? WHERE id=?", (reason, key_id))
    log_event("warn", "KEY_FREEZE", f"мороз: {reason}", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/unfreeze/<int:key_id>", methods=["POST"])
@login_required
def admin_unfreeze(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET frozen=0, freeze_reason='' WHERE id=?", (key_id,))
    log_event("info", "KEY_UNFREEZE", "розмороз", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/clear_hwid/<int:key_id>", methods=["POST"])
@login_required
def admin_clear_hwid(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("DELETE FROM key_hwids WHERE key_id=?", (key_id,))
    log_event("warn", "KEY_CLEAR_HWID", "адмін очистив HWID", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/edit/<int:key_id>", methods=["POST"])
@login_required
def admin_edit(key_id: int):
    note = (request.form.get("note") or "").strip()
    expires_at = (request.form.get("expires_at") or "").strip()
    hwid_limit = int(request.form.get("hwid_limit") or "1")
    hwid_limit = 1 if hwid_limit <= 1 else 2

    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)

        try:
            if len(expires_at) == 10:
                expires_at = expires_at + "T00:00:00+02:00"
            parse_dt(expires_at)
        except Exception:
            expires_at = row["expires_at"]

        conn.execute(
            "UPDATE license_keys SET note=?, expires_at=?, hwid_limit=? WHERE id=?",
            (note, expires_at, hwid_limit, key_id),
        )
    log_event("info", "KEY_EDIT", f"редагування (hwid_limit={hwid_limit})", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/delete/<int:key_id>", methods=["POST"])
@login_required
def admin_delete(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("DELETE FROM key_hwids WHERE key_id=?", (key_id,))
        conn.execute("DELETE FROM license_keys WHERE id=?", (key_id,))
    log_event("warn", "KEY_DELETE", "видалено ключ", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/archive/<int:key_id>", methods=["POST"])
@login_required
def admin_archive(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET archived=1, archived_at=? WHERE id=?", (iso_ua(), key_id))
    log_event("info", "KEY_ARCHIVE_MANUAL", "архів вручну", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/unarchive/<int:key_id>", methods=["POST"])
@login_required
def admin_unarchive(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE license_keys SET archived=0, archived_at=NULL WHERE id=?", (key_id,))
    log_event("info", "KEY_UNARCHIVE", "повернути з архіву", key_id, row["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/maintenance", methods=["POST"])
@login_required
def admin_maintenance():
    maintenance_tick(True)
    log_event("info", "MAINTENANCE_RUN", "запуск вручну")
    return redirect(request.referrer or "/admin")


@app.route("/admin/clear_logs", methods=["POST"])
@login_required
def admin_clear_logs():
    with db() as conn:
        conn.execute("DELETE FROM logs")
    log_event("warn", "LOGS_CLEARED", "логи очищено вручну")
    return redirect(request.referrer or "/logs")


# =========================
# MASS ACTIONS
# =========================
def _parse_ids() -> list[int]:
    ids = request.form.get("ids") or ""
    return [int(x) for x in ids.split(",") if x.strip().isdigit()]


@app.route("/admin/mass_ban", methods=["POST"])
@login_required
def admin_mass_ban():
    arr = _parse_ids()
    if not arr:
        return redirect(request.referrer or "/admin")
    with db() as conn:
        rows = conn.execute(
            f"SELECT id, license_key FROM license_keys WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        ).fetchall()
        conn.execute(
            f"UPDATE license_keys SET status='banned', banned_reason='MASS' WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        )
    for r in rows:
        log_event("warn", "KEY_BAN", "масовий бан", r["id"], r["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/mass_unban", methods=["POST"])
@login_required
def admin_mass_unban():
    arr = _parse_ids()
    if not arr:
        return redirect(request.referrer or "/admin")
    with db() as conn:
        rows = conn.execute(
            f"SELECT id, license_key FROM license_keys WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        ).fetchall()
        conn.execute(
            f"UPDATE license_keys SET status='active', banned_reason='' WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        )
    for r in rows:
        log_event("info", "KEY_UNBAN", "масовий розбан", r["id"], r["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/mass_clear_hwid", methods=["POST"])
@login_required
def admin_mass_clear_hwid():
    arr = _parse_ids()
    if not arr:
        return redirect(request.referrer or "/admin")
    with db() as conn:
        keys = conn.execute(
            f"SELECT id, license_key FROM license_keys WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        ).fetchall()
        conn.execute(
            f"DELETE FROM key_hwids WHERE key_id IN ({','.join(['?']*len(arr))})",
            arr,
        )
    for r in keys:
        log_event("warn", "KEY_CLEAR_HWID", "масова очистка HWID", r["id"], r["license_key"])
    return redirect(request.referrer or "/admin")


@app.route("/admin/mass_delete", methods=["POST"])
@login_required
def admin_mass_delete():
    arr = _parse_ids()
    if not arr:
        return redirect(request.referrer or "/admin")
    with db() as conn:
        keys = conn.execute(
            f"SELECT id, license_key FROM license_keys WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        ).fetchall()
        conn.execute(
            f"DELETE FROM key_hwids WHERE key_id IN ({','.join(['?']*len(arr))})",
            arr,
        )
        conn.execute(
            f"DELETE FROM license_keys WHERE id IN ({','.join(['?']*len(arr))})",
            arr,
        )
    for r in keys:
        log_event("warn", "KEY_DELETE", "масове видалення", r["id"], r["license_key"])
    return redirect(request.referrer or "/admin")


# =========================
# MODAL API (для панелі)
# =========================
@app.route("/api/key/<int:key_id>")
@login_required
def api_key(key_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            return jsonify({"ok": False}), 404
        hwids = conn.execute(
            "SELECT hwid, first_seen, last_seen FROM key_hwids WHERE key_id=? ORDER BY id ASC",
            (key_id,),
        ).fetchall()

    d = dict(row)
    d["status_ui"] = ui_status(row)
    d["hwids"] = [dict(x) for x in hwids]
    return jsonify({"ok": True, "data": d})


# =========================
# UI HTML (NO f-string JS bugs)
# =========================
def html_page(body: str) -> str:
    tpl = """<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
  :root {{
    --bg: #e9edf3;
    --panel: #ffffff;
    --line: #d6dde8;
    --shadow: 0 16px 42px rgba(16,24,40,.12);
    --nav: #2e3d56;
    --nav2: #22314a;
    --blue: #2f7cf6;
    --green: #2ebd73;
    --red: #e35050;
    --amber: #f0b44b;
    --text: #101828;
    --muted: #667085;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text); }}

  .topbar {{
    height:58px;
    background: linear-gradient(90deg, var(--nav), var(--nav2));
    color:#fff;
    display:flex; align-items:center; justify-content:space-between;
    padding: 0 18px;
    box-shadow: 0 10px 30px rgba(0,0,0,.20);
  }}
  .brand {{ display:flex; align-items:center; gap:10px; font-weight: 900; letter-spacing: .2px; }}
  .brand .dot {{
    width:26px; height:26px; border-radius:8px;
    display:flex; align-items:center; justify-content:center;
    background: rgba(255,255,255,.12);
  }}
  .links {{ font-weight: 900; font-size: 13px; opacity: .92; display:flex; gap:10px; flex-wrap:wrap; }}
  .links a {{
    color:#fff; text-decoration:none;
    padding: 7px 10px;
    border:1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.06);
    border-radius: 10px;
  }}
  .wrap {{ max-width: 1320px; margin: 0 auto; padding: 18px; }}

  .stats {{
    display:grid;
    grid-template-columns: repeat(5, minmax(0,1fr));
    gap: 14px;
    margin-bottom: 12px;
  }}
  .stat {{
    background: var(--panel);
    border:1px solid rgba(214,221,232,.85);
    border-radius: 10px;
    overflow:hidden;
    box-shadow: var(--shadow);
  }}
  .bar {{
    height:52px;
    display:flex; align-items:center; justify-content:space-between;
    padding: 12px 14px;
    color:#fff;
    font-weight: 900;
  }}
  .label {{ font-size: 13px; opacity: .95; }}
  .num {{ font-size: 34px; line-height: 1; }}
  .g-blue {{ background: linear-gradient(90deg, #2c74f4, #458ef9); }}
  .g-green {{ background: linear-gradient(90deg, #24b56d, #36cb80); }}
  .g-red {{ background: linear-gradient(90deg, #df4545, #f06a6a); }}
  .g-amber {{ background: linear-gradient(90deg, #f0a93b, #f6c067); }}
  .g-gray {{ background: linear-gradient(90deg, #596b86, #6b7f9d); }}

  .toolbar {{
    display:flex; align-items:center; justify-content:space-between;
    gap:12px; flex-wrap:wrap;
    margin-bottom: 12px;
  }}
  .btn {{
    border: 1px solid rgba(0,0,0,.10);
    border-radius: 8px;
    padding: 10px 14px;
    font-weight: 900;
    cursor:pointer;
    background: #fff;
  }}
  .btn.primary {{
    background: linear-gradient(90deg, #2c74f4, #458ef9);
    color:#fff;
    border-color: rgba(255,255,255,.20);
  }}
  .btn.danger {{
    background: rgba(227,80,80,.12);
    color: #9a1f1f;
    border-color: rgba(227,80,80,.20);
  }}
  .inp {{
    padding: 10px 12px;
    border-radius: 8px;
    border: 1px solid var(--line);
    background:#fff;
    outline:none;
    font-weight: 900;
    color: var(--text);
    min-width: 180px;
  }}
  .inp.search {{ min-width: 320px; }}

  .panel {{
    background: var(--panel);
    border: 1px solid rgba(214,221,232,.90);
    border-radius: 10px;
    box-shadow: var(--shadow);
    overflow:hidden;
  }}
  .panel-head {{
    padding: 14px;
    display:flex; align-items:center; justify-content:space-between;
    border-bottom: 1px solid rgba(214,221,232,.85);
    background: linear-gradient(180deg, #ffffff, #fbfcfe);
  }}
  .panel-title {{ font-weight: 1000; font-size: 18px; }}
  .panel-actions {{ display:flex; gap: 10px; align-items:center; flex-wrap:wrap; }}
  .mini {{
    padding: 9px 12px;
    border-radius: 8px;
    border: 1px solid rgba(0,0,0,.10);
    background:#f6f8fc;
    font-weight: 1000;
    cursor:pointer;
  }}

  .tablewrap {{ padding: 0 14px 14px; overflow:auto; }}
  table {{ width:100%; border-collapse:separate; border-spacing:0; }}
  thead th {{
    font-size: 12px;
    color:#475467;
    padding: 12px 12px;
    background:#f6f8fc;
    border-top: 1px solid rgba(214,221,232,.95);
    border-bottom: 1px solid rgba(214,221,232,.95);
    white-space:nowrap;
  }}
  thead th:first-child {{ border-left:1px solid rgba(214,221,232,.95); border-top-left-radius: 10px; }}
  thead th:last-child {{ border-right:1px solid rgba(214,221,232,.95); border-top-right-radius: 10px; text-align:right; }}

  tbody td {{
    padding: 12px 12px;
    border-bottom: 1px solid rgba(214,221,232,.65);
    background:#fff;
    font-weight: 900;
    font-size: 13px;
    white-space:nowrap;
  }}
  tbody tr:hover td {{ background:#f8fbff; }}
  tbody td:first-child {{ border-left:1px solid rgba(214,221,232,.95); }}
  tbody td:last-child {{ border-right:1px solid rgba(214,221,232,.95); text-align:right; }}
  tbody tr:last-child td:first-child {{ border-bottom-left-radius: 10px; }}
  tbody tr:last-child td:last-child {{ border-bottom-right-radius: 10px; }}

  .mono {{ font-family: var(--mono); font-weight: 1000; }}
  .tag {{
    display:inline-flex; align-items:center; justify-content:center;
    padding: 6px 10px; border-radius: 8px;
    font-weight: 1000; font-size: 12px;
    border: 1px solid rgba(0,0,0,.08);
  }}
  .tag.active {{ background: rgba(46,189,115,.14); color:#15764a; }}
  .tag.banned {{ background: rgba(227,80,80,.14); color:#9a1f1f; }}
  .tag.expired {{ background: rgba(240,180,75,.22); color:#8a5a0a; }}
  .tag.frozen {{ background: rgba(47,124,246,.14); color:#194aa8; border-color: rgba(47,124,246,.20); }}
  .tag.archive {{ background: rgba(89,107,134,.16); color:#334155; border-color: rgba(89,107,134,.25); }}

  .actions {{ display:flex; gap: 8px; justify-content:flex-end; align-items:center; }}
  .act {{
    padding: 7px 10px; border-radius: 8px;
    border: 1px solid rgba(0,0,0,.10);
    font-weight: 1000; cursor:pointer;
    background:#f6f8fc;
  }}
  .act.ban {{ background: rgba(227,80,80,.14); color:#9a1f1f; border-color: rgba(227,80,80,.20); }}
  .act.unban {{ background: rgba(46,189,115,.14); color:#15764a; border-color: rgba(46,189,115,.20); }}
  .act.blue {{ background: rgba(47,124,246,.14); color:#194aa8; border-color: rgba(47,124,246,.20); }}
  .act.gray {{ background: rgba(89,107,134,.16); color:#334155; border-color: rgba(89,107,134,.25); }}

  .pager {{
    padding: 12px 14px;
    display:flex; justify-content:flex-end; gap:8px;
    border-top: 1px solid rgba(214,221,232,.85);
    background:#fafbfe;
  }}
  .pbtn {{
    min-width: 40px; height: 34px;
    display:flex; align-items:center; justify-content:center;
    border-radius: 8px;
    border: 1px solid rgba(214,221,232,.95);
    background:#fff;
    font-weight: 1000;
    cursor:pointer;
    text-decoration:none;
    color: var(--text);
    padding: 0 10px;
  }}
  .pbtn.active {{
    background: linear-gradient(90deg, #2c74f4, #458ef9);
    color:#fff;
    border-color: rgba(255,255,255,.20);
  }}

  .backdrop {{
    position: fixed; inset: 0;
    background: rgba(16,24,40,.55);
    display:none; align-items:center; justify-content:center;
    z-index: 999; padding: 18px;
  }}
  .modal {{
    width: min(980px, 100%);
    background:#fff;
    border-radius: 12px;
    border: 1px solid rgba(214,221,232,.95);
    box-shadow: 0 30px 90px rgba(0,0,0,.30);
    overflow:hidden;
  }}
  .modalhead {{
    background: linear-gradient(90deg, var(--nav), var(--nav2));
    color:#fff;
    padding: 12px 14px;
    display:flex; align-items:center; justify-content:space-between;
    font-weight: 1000;
  }}
  .modalbody {{ padding: 14px; }}
  .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }}
  .kv {{
    border: 1px solid rgba(214,221,232,.95);
    background:#fbfcfe;
    border-radius: 10px;
    padding: 10px 12px;
  }}
  .k {{ font-size: 12px; color: var(--muted); font-weight: 1000; }}
  .v {{ margin-top: 4px; font-weight: 1000; font-size: 13px; word-break: break-all; }}

  .editbox {{ margin-top: 12px; border-top: 1px dashed rgba(214,221,232,.95); padding-top: 12px; }}
  .editrow {{ display:grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }}
  .modalfoot {{
    padding: 12px 14px;
    border-top: 1px solid rgba(214,221,232,.95);
    background:#fafbfe;
    display:flex;
    justify-content:flex-end;
    gap:10px;
    flex-wrap:wrap;
  }}
  @media (max-width: 1100px) {{
    .stats {{ grid-template-columns: repeat(2, minmax(0,1fr)); }}
  }}
  @media (max-width: 860px) {{
    .grid {{ grid-template-columns: 1fr; }}
    .editrow {{ grid-template-columns: 1fr; }}
    .inp.search {{ min-width: 100%; }}
  }}
</style>
</head>
<body>
{body}
</body>
</html>"""
    return tpl.format(title=html_escape(APP_TITLE), body=body)


def login_html(error: str) -> str:
    err = f'<div style="margin-top:10px;color:#b42318;font-weight:1000;">{html_escape(error)}</div>' if error else ""
    return f"""
<div class="topbar">
  <div class="brand"><div class="dot">◻</div>{html_escape(APP_TITLE)}</div>
  <div class="links"><a href="/login">/login</a></div>
</div>
<div class="wrap" style="max-width:520px;">
  <div class="panel" style="padding:16px;">
    <div style="font-size:18px;font-weight:1000;">Вхід адміністратора</div>
    {err}
    <form method="post" style="margin-top:12px;display:grid;gap:10px;">
      <input class="inp" name="username" placeholder="логін">
      <input class="inp" name="password" type="password" placeholder="пароль">
      <button class="btn primary" type="submit">Увійти</button>
    </form>
  </div>
</div>
"""


def dashboard_html(*, base_path: str, view: str,
                   total: int, active: int, banned: int, frozen: int, archived: int, logs_24h: int,
                   rows: list[dict], q: str, page: int, total_pages: int) -> str:
    def st_tag(s: str) -> str:
        if s == "забанено":
            return '<span class="tag banned">Забанено</span>'
        if s == "прострочено":
            return '<span class="tag expired">Термін вийшов</span>'
        if s == "заморожено":
            return '<span class="tag frozen">Заморожено</span>'
        if s == "архів":
            return '<span class="tag archive">Архів</span>'
        return '<span class="tag active">Активний</span>'

    title = {
        "all": "Ключі",
        "banned": "Забанені ключі",
        "frozen": "Заморожені ключі",
        "archive": "Архів",
    }.get(view, "Ключі")

    body_rows = []
    for r in rows:
        rid = r["id"]
        key = r["license_key"]
        st = r["status_ui"]
        exp = (r["expires_at"] or "")[:10]
        last = (r["last_used_at"] or "")
        last = last[:10] if last else "-"

        body_rows.append(f"""
        <tr onclick="openKey({rid});" style="cursor:pointer;">
          <td class="mono">{html_escape(key)}</td>
          <td>{st_tag(st)}</td>
          <td>{html_escape(exp)}</td>
          <td>{html_escape(last)}</td>
          <td onclick="event.stopPropagation();">
            <div class="actions">
              <button class="act blue" type="button" onclick="openKey({rid});">Деталі</button>
              <input type="checkbox" class="ck" value="{rid}" onclick="event.stopPropagation();" />
            </div>
          </td>
        </tr>
        """)

    rows_html = "\n".join(body_rows) if body_rows else '<tr><td colspan="5" style="padding:14px;color:var(--muted);font-weight:1000;">Нема ключів</td></tr>'

    def link(p: int, label: str, active_=False):
        cls = "pbtn active" if active_ else "pbtn"
        return f'<a class="{cls}" href="{base_path}?q={html_escape(q)}&page={p}">{label}</a>'

    prev_p = max(1, page - 1)
    next_p = min(total_pages, page + 1)

    pager = [link(prev_p, "‹ Попередня")]
    start = max(1, page - 1)
    end = min(total_pages, start + 2)
    start = max(1, end - 2)
    for p in range(start, end + 1):
        pager.append(link(p, str(p), active_=(p == page)))
    pager.append(link(next_p, "Наступна ›"))

    # JS (NO python f-string here, so braces are safe)
    js = """
<script>
function closeModal(){
  document.getElementById('backdrop').style.display = 'none';
}
function escapeHtml(s){
  return String(s ?? '')
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}
function postDelete(id){
  if(!confirm('Точно видалити цей ключ?')) return;
  const f = document.getElementById('deleteForm');
  f.action = '/admin/delete/' + id;
  f.submit();
}
function freezePrompt(id){
  const reason = prompt('Причина морозу (необовʼязково):') || '';
  const f = document.createElement('form');
  f.method = 'post';
  f.action = '/admin/freeze/' + id;
  const inp = document.createElement('input');
  inp.type = 'hidden';
  inp.name = 'reason';
  inp.value = reason;
  f.appendChild(inp);
  document.body.appendChild(f);
  f.submit();
}
function banPrompt(id){
  const reason = prompt('Причина бану (необовʼязково):') || 'MANUAL';
  const f = document.createElement('form');
  f.method = 'post';
  f.action = '/admin/ban/' + id;
  const inp = document.createElement('input');
  inp.type = 'hidden';
  inp.name = 'reason';
  inp.value = reason;
  f.appendChild(inp);
  document.body.appendChild(f);
  f.submit();
}
function openKey(id){
  const back = document.getElementById('backdrop');
  back.style.display = 'flex';
  document.getElementById('mSub').textContent = 'Завантаження...';
  document.getElementById('mGrid').innerHTML = '';
  document.getElementById('mFoot').innerHTML = '';

  fetch('/api/key/' + id)
    .then(r => r.json())
    .then(j => {
      if(!j.ok) {
        document.getElementById('mSub').textContent = 'Не знайдено';
        return;
      }
      const d = j.data;
      document.getElementById('mSub').textContent = d.license_key;

      const hwids = (d.hwids || []).map(x => x.hwid).join(', ') || '-';

      const items = [
        ['Статус', d.status_ui],
        ['HWID (список)', hwids],
        ['HWID ліміт', d.hwid_limit],
        ['Створено', d.created_at],
        ['Діє до', d.expires_at],
        ['Останнє використання', d.last_used_at || '-'],
        ['Останній IP', d.last_ip || '-'],
        ['Кількість використань', d.uses_count || 0],
        ['Примітка', d.note || '-'],
        ['Мороз причина', d.freeze_reason || '-'],
        ['Бан причина', d.banned_reason || '-'],
        ['Архів', d.archived ? 'так' : 'ні'],
        ['ID', d.id]
      ];

      document.getElementById('mGrid').innerHTML = items.map((kv) => {
        const k = kv[0], v = kv[1];
        return '<div class="kv"><div class="k">' + escapeHtml(k) + '</div><div class="v">' + escapeHtml(v) + '</div></div>';
      }).join('');

      // edit form
      const ef = document.getElementById('editForm');
      ef.action = '/admin/edit/' + d.id;
      document.getElementById('eNote').value = d.note || '';
      document.getElementById('eExp').value = d.expires_at || '';
      document.getElementById('eLimit').value = String(d.hwid_limit || 1);

      // footer actions
      let foot = '';

      if(d.archived){
        foot += '<form method="post" action="/admin/unarchive/' + d.id + '"><button class="btn act gray" type="submit">Повернути з архіву</button></form>';
      } else {
        foot += '<form method="post" action="/admin/archive/' + d.id + '"><button class="btn act gray" type="submit">В архів</button></form>';
      }

      if(d.status === 'banned' || d.status_ui === 'забанено'){
        foot += '<form method="post" action="/admin/unban/' + d.id + '"><button class="btn act unban" type="submit">Розбан</button></form>';
      } else {
        foot += '<button class="btn act ban" type="button" onclick="banPrompt(' + d.id + ')">Бан</button>';
      }

      if(d.frozen){
        foot += '<form method="post" action="/admin/unfreeze/' + d.id + '"><button class="btn act blue" type="submit">Розмороз</button></form>';
      } else {
        foot += '<button class="btn act blue" type="button" onclick="freezePrompt(' + d.id + ')">Мороз</button>';
      }

      foot += '<form method="post" action="/admin/clear_hwid/' + d.id + '"><button class="btn" type="submit">Очистити HWID</button></form>';
      foot += '<button class="btn danger" type="button" onclick="postDelete(' + d.id + ')">Видалити ключ</button>';

      document.getElementById('mFoot').innerHTML = foot;
    })
    .catch(_ => {
      document.getElementById('mSub').textContent = 'Помилка завантаження';
    });
}
function getSelectedIds(){
  const cks = document.querySelectorAll('.ck:checked');
  return Array.from(cks).map(x => x.value);
}
function massBan(){
  const ids = getSelectedIds();
  if(ids.length === 0) { alert('Спочатку вибери ключі (checkbox).'); return; }
  document.getElementById('massBanIds').value = ids.join(',');
  document.getElementById('massBanForm').submit();
}
function massUnban(){
  const ids = getSelectedIds();
  if(ids.length === 0) { alert('Спочатку вибери ключі (checkbox).'); return; }
  document.getElementById('massUnbanIds').value = ids.join(',');
  document.getElementById('massUnbanForm').submit();
}
function massClearHwid(){
  const ids = getSelectedIds();
  if(ids.length === 0) { alert('Спочатку вибери ключі (checkbox).'); return; }
  document.getElementById('massClearIds').value = ids.join(',');
  document.getElementById('massClearForm').submit();
}
function massDelete(){
  const ids = getSelectedIds();
  if(ids.length === 0) { alert('Спочатку вибери ключі (checkbox).'); return; }
  if(!confirm('Точно масово видалити вибрані ключі?')) return;
  document.getElementById('massDeleteIds').value = ids.join(',');
  document.getElementById('massDeleteForm').submit();
}
</script>
"""

    return f"""
<div class="topbar">
  <div class="brand"><div class="dot">◻</div>{html_escape(APP_TITLE)}</div>
  <div class="links">
    <a href="/admin">/admin</a>
    <a href="/banned">/banned</a>
    <a href="/frozen">/frozen</a>
    <a href="/archive">/archive</a>
    <a href="/logs">/logs</a>
    <a href="/logout">/logout</a>
  </div>
</div>

<div class="wrap">
  <div class="stats">
    <div class="stat"><div class="bar g-blue"><div class="label">Всього (не архів)</div><div class="num">{total}</div></div></div>
    <div class="stat"><div class="bar g-green"><div class="label">Активні</div><div class="num">{active}</div></div></div>
    <div class="stat"><div class="bar g-red"><div class="label">Забанені</div><div class="num">{banned}</div></div></div>
    <div class="stat"><div class="bar g-gray"><div class="label">Заморожені</div><div class="num">{frozen}</div></div></div>
    <div class="stat"><div class="bar g-amber"><div class="label">Логи (24 год)</div><div class="num">{logs_24h}</div></div></div>
  </div>

  <div class="toolbar">
    <form method="post" action="/admin/generate" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
      <button class="btn primary" type="submit">Згенерувати ключ</button>
      <input class="inp" name="days" placeholder="Днів (30)" style="width:140px;">
      <select class="inp" name="hwid_limit" style="width:170px;">
        <option value="1">HWID ліміт: 1</option>
        <option value="2">HWID ліміт: 2</option>
      </select>
      <input class="inp" name="note" placeholder="Примітка (необов'язково)" style="width:280px;">
    </form>

    <form method="get" action="{base_path}" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
      <input class="inp search" name="q" placeholder="Пошук..." value="{html_escape(q)}">
      <button class="btn" type="submit">Фільтр</button>
    </form>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">{html_escape(title)} <span style="color:var(--muted);font-weight:900;font-size:12px;">(архів: {archived})</span></div>
      <div class="panel-actions">
        <button class="mini" type="button" onclick="massBan()">Масовий бан</button>
        <button class="mini" type="button" onclick="massUnban()">Масовий розбан</button>
        <button class="mini" type="button" onclick="massClearHwid()">Масова очистка HWID</button>
        <button class="mini" type="button" onclick="massDelete()">Масове видалення</button>
        <form method="post" action="/admin/maintenance" style="display:inline;">
          <button class="mini" type="submit">Обслуговування</button>
        </form>
      </div>
    </div>

    <div class="tablewrap">
      <table>
        <thead>
          <tr>
            <th style="min-width:240px;">Ключ</th>
            <th style="min-width:160px;">Статус</th>
            <th style="min-width:120px;">Діє до</th>
            <th style="min-width:120px;">Останнє</th>
            <th style="min-width:240px;">Дії</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>

    <div class="pager">
      {''.join(pager)}
    </div>
  </div>
</div>

<!-- Modal -->
<div class="backdrop" id="backdrop" onclick="closeModal()">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modalhead">
      <div>Деталі ключа</div>
      <button class="mini" onclick="closeModal()">Закрити</button>
    </div>
    <div class="modalbody">
      <div style="color:var(--muted);font-weight:1000;" id="mSub">Завантаження...</div>
      <div class="grid" id="mGrid"></div>

      <div class="editbox">
        <div style="font-weight:1000;">Редагування</div>
        <form id="editForm" method="post" style="margin-top:10px;">
          <div class="editrow">
            <input class="inp" name="note" id="eNote" placeholder="Примітка">
            <input class="inp" name="expires_at" id="eExp" placeholder="Діє до (YYYY-MM-DD або ISO)">
            <select class="inp" name="hwid_limit" id="eLimit">
              <option value="1">HWID ліміт: 1</option>
              <option value="2">HWID ліміт: 2</option>
            </select>
          </div>
          <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:10px;">
            <button class="btn" type="button" onclick="closeModal()">Закрити</button>
            <button class="btn primary" type="submit">Зберегти</button>
          </div>
        </form>
      </div>
    </div>

    <div class="modalfoot" id="mFoot"></div>
  </div>
</div>

<form id="massBanForm" method="post" action="/admin/mass_ban" style="display:none;">
  <input type="hidden" name="ids" id="massBanIds">
</form>
<form id="massUnbanForm" method="post" action="/admin/mass_unban" style="display:none;">
  <input type="hidden" name="ids" id="massUnbanIds">
</form>
<form id="massClearForm" method="post" action="/admin/mass_clear_hwid" style="display:none;">
  <input type="hidden" name="ids" id="massClearIds">
</form>
<form id="massDeleteForm" method="post" action="/admin/mass_delete" style="display:none;">
  <input type="hidden" name="ids" id="massDeleteIds">
</form>

<form id="deleteForm" method="post" style="display:none;"></form>

{js}
"""


def logs_html(rows, q: str, page: int, total_pages: int) -> str:
    trs = []
    for r in rows:
        trs.append(f"""
        <tr>
          <td>{html_escape(r["created_at"])}</td>
          <td style="font-weight:1000;">{html_escape(r["level"])}</td>
          <td style="font-weight:1000;">{html_escape(r["action"])}</td>
          <td class="mono">{html_escape(r["license_key"] or "-")}</td>
          <td>{html_escape(r["ip"] or "-")}</td>
          <td style="white-space:normal;max-width:650px;">{html_escape((r["message"] or "")[:420])}</td>
        </tr>
        """)

    rows_html = "\n".join(trs) if trs else '<tr><td colspan="6" style="padding:14px;color:var(--muted);font-weight:1000;">Логів немає</td></tr>'

    prev_p = max(1, page - 1)
    next_p = min(total_pages, page + 1)

    def href(p: int) -> str:
        return f"/logs?q={html_escape(q)}&page={p}"

    return f"""
<div class="topbar">
  <div class="brand"><div class="dot">◻</div>{html_escape(APP_TITLE)}</div>
  <div class="links">
    <a href="/admin">/admin</a>
    <a href="/banned">/banned</a>
    <a href="/frozen">/frozen</a>
    <a href="/archive">/archive</a>
    <a href="/logs">/logs</a>
    <a href="/logout">/logout</a>
  </div>
</div>

<div class="wrap">
  <div class="toolbar">
    <div style="font-weight:1000;font-size:18px;">Логи</div>
    <form method="get" action="/logs" style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;flex:1;">
      <input class="inp search" name="q" placeholder="Пошук..." value="{html_escape(q)}">
      <button class="btn" type="submit">Фільтр</button>
    </form>
    <form method="post" action="/admin/clear_logs">
      <button class="btn danger" type="submit" onclick="return confirm('Точно очистити всі логи?');">Очистити логи</button>
    </form>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">Системні логи</div>
      <div class="panel-actions">
        <a class="mini" href="/admin">Повернутись</a>
      </div>
    </div>

    <div class="tablewrap">
      <table>
        <thead>
          <tr>
            <th style="min-width:190px;">Час</th>
            <th style="min-width:80px;">Рівень</th>
            <th style="min-width:180px;">Дія</th>
            <th style="min-width:230px;">Ключ</th>
            <th style="min-width:140px;">IP</th>
            <th>Повідомлення</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>

    <div class="pager">
      <a class="pbtn" href="{href(prev_p)}">‹ Попередня</a>
      <a class="pbtn active" href="{href(page)}">{page}</a>
      <a class="pbtn" href="{href(next_p)}">Наступна ›</a>
    </div>
  </div>
</div>
"""


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    init_db()
    print(f"Відкрий: http://127.0.0.1:{PORT}/login  (потім /admin)")
    app.run(host="0.0.0.0", port=PORT, debug=False)
