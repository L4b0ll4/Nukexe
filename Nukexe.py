"""
Nukexe.py — REST Gateway → Windows Executables
==================================================
Features:
  • Dynamic APIs: /{TOOL}/{FUNCTION} → Windows executables
  • External UI dashboard (dashboard.html) at /admin/ui
  • Template-based parameter system: {$value} or {$nested_value}
  • Bearer authentication, rate limiting, Fail2ban, webhooks
  • HTTPS, IP filtering, call deduplication
  • SMTP notifications, tray icon, startup popup

PyInstaller build (dashboard.html and nukexe.png alongside the script):
    pyinstaller --noconsole --onedir --name Nukexe ^
        --add-data “dashboard.html;.” ^
        --add-data “nukexe.png;.” ^
        --collect-submodules uvicorn ^
        Nukexe.py

Notes:
  • WRITABLE files (Nukexe.db, Nukexe.log, certs/) are created next to
    the executable — NOT in the CWD and NOT in the _MEIPASS temp directory.
  • GW_DOCS=1 enables /docs (default: off). GW_WORKERS=N overrides the number of workers.
  • If the server starts without a GUI, the initial admin token is written to the log.
"""
import logging.handlers
import hmac
import argparse
import asyncio
import base64
import collections
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import smtplib
import socket
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from contextlib import asynccontextmanager, closing
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Optional

import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field

# --- Optional GUI/desktop: server must start even without them ---
try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_TK = True
except Exception:
    HAS_TK = False

try:
    import pystray
    from PIL import Image
    HAS_TRAY = True
except Exception:
    HAS_TRAY = False

# ============================================================
# PATCH PYINSTALLER --noconsole & EVENT LOOP WINDOWS
# ============================================================
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

DB_PATH = str(BASE_DIR / "Nukexe.db")
LOG_PATH = str(BASE_DIR / "Nukexe.log")
CERTS_DIR = BASE_DIR / "certs"


class DummyStream:
    def write(self, *args, **kwargs): pass
    def flush(self, *args, **kwargs): pass
    def isatty(self): return False


class FileWriter:
    def __init__(self, path: str, mode: str = "a"):
        self.file = open(path, mode, encoding="utf-8")
    def write(self, msg):
        self.file.write(msg)
        self.file.flush()
    def flush(self):
        self.file.flush()
    def isatty(self):
        return False


# With --noconsole, stdout/stderr are None: redirect them to files next to the exe
if sys.stdout is None or sys.stderr is None:
    _console_path = BASE_DIR / "Nukexe_console.log"
    try:
        # If > 5MB, restart (it only contains print/tracebacks)
        _mode = "w" if _console_path.exists() and _console_path.stat().st_size > 5 * 1024 * 1024 else "a"
        _fw: Any = FileWriter(str(_console_path), mode=_mode)
    except OSError:
        _fw = DummyStream()
    if sys.stdout is None: sys.stdout = _fw
    if sys.stderr is None: sys.stderr = _fw


def _configure_logging():
    fmt, dfmt = "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    if getattr(sys, "frozen", False):
        try:
            h = logging.handlers.TimedRotatingFileHandler(
                LOG_PATH, when="midnight", backupCount=30, encoding="utf-8")
            logging.basicConfig(level=logging.INFO, format=fmt, datefmt=dfmt, handlers=[h])
            return
        except OSError:
            pass
        try:  # Fallback to temp if exec folder is not writable
            h = logging.handlers.TimedRotatingFileHandler(
                os.path.join(tempfile.gettempdir(), "Nukexe.log"),
                when="midnight", backupCount=30, encoding="utf-8")
            logging.basicConfig(level=logging.INFO, format=fmt, datefmt=dfmt, handlers=[h])
            return
        except OSError:
            pass
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt=dfmt)


_configure_logging()
logger = logging.getLogger("Nukexe")

# ============================================================
# CONSTANTS
# ============================================================
NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
RESERVED_PREFIXES = {"admin", "jobs", "health", "docs", "redoc", "openapi.json"}

DEFAULT_SETTINGS: dict[str, str] = {
    "server_host":            "0.0.0.0",
    "server_port":            "8000",
    "ssl_mode":               "0",   # 0=HTTP, 1=Self-Signed, 2=Custom Cert
    "ssl_certfile":           "",
    "ssl_keyfile":            "",
    "ip_mode":                "allow_all",
    "ip_whitelist":           "",
    "ip_blacklist":           "",
    "trust_proxy":            "0",
    "forwarded_allow_ips":    "127.0.0.1",
    "max_body_bytes":         "1048576",
    "allow_private_callbacks": "0",
    "rate_global_per_min":    "120",
    "rate_route_per_min":     "30",
    "dedup_window_s":         "30",
    "ban_failures":           "10",
    "ban_window_s":           "60",
    "ban_minutes":            "15",
    "ban_exempt_ips":         "",
    "smtp_enabled":           "0",
    "smtp_host":              "",
    "smtp_port":              "587",
    "smtp_user":              "",
    "smtp_pass_enc":          "",
    "smtp_from":              "",
    "smtp_to":                "",
    "smtp_tls":               "1",
    "notify_cooldown_min":    "10",
    "notify_failures_per_min": "30",
    "notify_calls_per_min":   "200",
    "notify_on_ban":          "1",
    "jobs_retention_h":       "24",
    "async_workers":          "4",
    "audit_retention_days":   "30",
    "jobs_max_rows":          "50000",
    "webhook_enabled":     "0",
    "webhook_url":         "",        # comma-separated list
    "webhook_secret":      "",        # header X-Nukexe-Signature (HMAC-SHA256)
    "webhook_events":      "*",       # "*" = all, or list, or "*, -volume" to exclude
    "webhook_timeout":     "10",
    "webhook_max_per_min": "60",      # Anti-flood threshold
    "notify_mail_events":  "ip.banned,failures,volume,route.unauthorized,route.forbidden,"
    "rate.limited,route.invalid,admin.action",
    "audit_max_rows":        "100000",   
}

PROTECTED_SETTINGS = {"secret_key", "smtp_pass_enc"}

# ============================================================
# LIFESPAN & FASTAPI SETUP
# ============================================================
EXECUTOR: Optional[concurrent.futures.ThreadPoolExecutor] = None
JOB_SLOTS: Optional[threading.BoundedSemaphore] = None
_DB_READY = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global EXECUTOR, JOB_SLOTS, _DB_READY
    if not _DB_READY:
        init_db()
    load_bans()
    workers = max(1, min(sint(os.environ.get("GW_WORKERS") or get_setting("async_workers"), 4), 64))
    EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="exe")
    # Backpressure: max jobs in queue+execution = workers * 8
    JOB_SLOTS = threading.BoundedSemaphore(workers * 8)

    # Reconcile orphaned jobs from previous crashes
    try:
        with closing(get_db()) as conn:
            conn.execute("UPDATE jobs SET status='failed', "
                         "stderr=COALESCE(NULLIF(stderr,''),'Server restarted: job interrupted') "
                         "WHERE status IN ('queued','running')")
            conn.commit()
    except sqlite3.Error:
        logger.exception("Job reconciliation failed")

    threading.Thread(target=maintenance_loop, daemon=True, name="maintenance").start()
    logger.info(f"Nukexe started with {workers} async workers.")

    yield

    logger.info("Shutting down... closing ThreadPool.")
    try:
        EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except TypeError:  # Python < 3.9
        EXECUTOR.shutdown(wait=False)


app = FastAPI(
    title="Nukexe", version="1.1", redoc_url=None, lifespan=lifespan,
    docs_url="/docs" if os.environ.get("GW_DOCS") == "1" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Dedup", "Retry-After"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ============================================================
# DATABASE
# ============================================================
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> Optional[str]:
    """Create/Update schema. Returns admin token only on first run."""
    global _DB_READY
    new_token: Optional[str] = None
    conn = get_db()
    try:
        c = conn.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE NOT NULL,
            prefix TEXT NOT NULL, description TEXT DEFAULT '', is_admin INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), last_used TEXT
        );
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT UNIQUE NOT NULL,
            exe_path TEXT NOT NULL, exe_args_template TEXT DEFAULT '',
            mode TEXT DEFAULT 'whitelist' CHECK(mode IN ('whitelist','dangerous')),
            exec_mode TEXT DEFAULT 'sync' CHECK(exec_mode IN ('sync','async')),
            timeout INTEGER DEFAULT 30, requires_auth INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1, rate_limit_per_min INTEGER DEFAULT 0,
            dedup_seconds INTEGER DEFAULT -1, allowed_ips TEXT DEFAULT '[]',
            blocked_ips TEXT DEFAULT '[]', description TEXT DEFAULT '',
            allowed_token_ids TEXT DEFAULT '[]', notify_webhook INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, route_path TEXT, client_ip TEXT, token_id INTEGER,
            params TEXT, exit_code INTEGER, stdout TEXT, stderr TEXT, duration_ms REAL,
            method TEXT, status INTEGER, reason TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, route_path TEXT, token_id INTEGER, params TEXT,
            status TEXT DEFAULT 'queued', exit_code INTEGER, stdout TEXT, stderr TEXT,
            created_at TEXT DEFAULT (datetime('now')), finished_at TEXT, callback_url TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS bans (
            ip TEXT PRIMARY KEY, reason TEXT, banned_at TEXT DEFAULT (datetime('now')), expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS admin_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER, ip TEXT, method TEXT, path TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
        CREATE INDEX IF NOT EXISTS idx_adminlog_created ON admin_log(created_at);
        """)

        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        if not c.execute("SELECT value FROM settings WHERE key='secret_key'").fetchone():
            c.execute("INSERT INTO settings (key, value) VALUES ('secret_key', ?)",
                      (Fernet.generate_key().decode(),))
        if c.execute("SELECT COUNT(*) FROM api_tokens WHERE is_admin=1 AND enabled=1").fetchone()[0] == 0:
            tok = "adm_" + secrets.token_urlsafe(32)
            c.execute("INSERT INTO api_tokens (token_hash, prefix, description, is_admin) VALUES (?,?,?,1)",
                      (hashlib.sha256(tok.encode()).hexdigest(), tok[:10], "Default Admin"))
            new_token = tok
        conn.commit()
        _DB_READY = True
    finally:
        conn.close()
    return new_token


# --- Settings Cache with TTL ---
class SettingsCache:
    def __init__(self, ttl: float = 5.0):
        self._ttl = ttl
        self._data: Optional[dict] = None
        self._ts = 0.0
        self._lock = threading.Lock()

    def get(self) -> dict:
        with self._lock:
            now = time.time()
            if self._data is None or now - self._ts > self._ttl:
                try:
                    with closing(get_db()) as conn:
                        rows = conn.execute("SELECT key, value FROM settings").fetchall()
                    d = dict(DEFAULT_SETTINGS)
                    d.update({r["key"]: r["value"] for r in rows})
                    self._data, self._ts = d, now
                except sqlite3.Error as e:
                    logger.error(f"[SETTINGS] Read failed: {e}")
                    if self._data is None:
                        self._data = dict(DEFAULT_SETTINGS)
            return dict(self._data)

    def invalidate(self):
        with self._lock:
            self._data = None


SETTINGS = SettingsCache(ttl=5.0)


def get_setting(key: str, default: str = "") -> str:
    return SETTINGS.get().get(key, default)


def get_settings_obj() -> dict:
    return SETTINGS.get()


def set_setting(key: str, value: str):
    with closing(get_db()) as conn:
        conn.execute("INSERT INTO settings (key, value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        conn.commit()
    SETTINGS.invalidate()


def sint(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_csv(s: str) -> list:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def parse_json_list(s: str) -> list:
    try:
        v = json.loads(s or "[]")
        return v if isinstance(v, list) else []
    except Exception:
        return []

# ============================================================
# CRYPTO AND AUTH
# ============================================================
def _fernet() -> Fernet:
    return Fernet(get_setting("secret_key").encode())


def enc_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def dec_secret(cipher: str) -> str:
    return _fernet().decrypt(cipher.encode()).decode()


_LAST_USED_UPDATE: dict = {}  # token_id -> timestamp


def check_token(request: Request) -> Optional[sqlite3.Row]:
    auth = request.headers.get("Authorization", "")
    token_plain = ""

    if auth.startswith("Bearer "):
        token_plain = auth[7:].strip()
    elif auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
            parts = decoded.split(":", 1)
            user, pwd = parts[0], parts[1] if len(parts) > 1 else ""
            token_plain = user if (user.startswith("adm_") or user.startswith("exe_")) else pwd
        except Exception:
            pass

    if not token_plain:
        token_plain = request.query_params.get("_token", "")

    if not token_plain:
        return None

    h = hashlib.sha256(token_plain.encode()).hexdigest()
    try:
        with closing(get_db()) as conn:
            row = conn.execute("SELECT * FROM api_tokens WHERE token_hash=? AND enabled=1", (h,)).fetchone()
            if row:
                now = time.time()
                if now - _LAST_USED_UPDATE.get(row["id"], 0.0) > 60.0:  # 1 update/min per token
                    _LAST_USED_UPDATE[row["id"]] = now
                    conn.execute("UPDATE api_tokens SET last_used=datetime('now') WHERE id=?", (row["id"],))
                    conn.commit()
        return row
    except sqlite3.Error as e:
        logger.error(f"[AUTH] DB error: {e}")
        return None


def _admin_log_db(admin_row, ip: str, method: str, path: str):
    try:
        with closing(get_db()) as conn:
            conn.execute("INSERT INTO admin_log (token_id, ip, method, path) VALUES (?,?,?,?)",
                         (admin_row["id"], ip, method, path))
            conn.commit()
    except Exception:
        logger.exception("[ADMIN] admin_log write failed")
    emit_event("admin.action", ip=ip, token_row=admin_row, method=method,
               action=f"{method} {path}", detail=path)


async def require_admin(request: Request) -> sqlite3.Row:
    row = await run_in_threadpool(check_token, request)
    ip = getattr(request.state, "ip", None) or get_client_ip(request)
    if not row:
        emit_event("route.unauthorized", ip=ip, route=request.url.path,
                   method=request.method, status=401,
                   reason="missing or invalid token on admin endpoint")
        raise HTTPException(401, "Invalid or missing token")
    if not row["is_admin"]:
        emit_event("route.forbidden", ip=ip, token_row=row, route=request.url.path,
                   method=request.method, status=403, reason="non-admin token on admin endpoint")
        raise HTTPException(403, "Admin permissions required")
    logger.info(f"[ADMIN] {request.method} {request.url.path} | token #{row['id']} | ip={ip}")
    if (request.method not in ("GET", "HEAD", "OPTIONS")
            or request.url.path in ("/admin/fs/list", "/admin/config/export")):
        await run_in_threadpool(_admin_log_db, row, ip, request.method, request.url.path)
    return row

# ============================================================
# RATE LIMITER & DEDUP CACHE
# ============================================================
class SlidingWindow:
    def __init__(self):
        self._d = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def hit(self, key, limit: int, window: float) -> bool:
        if limit <= 0:
            return True
        with self._lock:
            dq = self._d[key]
            now = time.time()
            while dq and now - dq[0] > window:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

    def cleanup(self, max_age: float = 300.0):
        with self._lock:
            now = time.time()
            for k in list(self._d):
                dq = self._d[k]
                while dq and now - dq[0] > max_age:
                    dq.popleft()
                if not dq:
                    del self._d[k]


RL = SlidingWindow()


class DedupCache:
    def __init__(self, max_items: int = 1000):
        self._d = collections.OrderedDict()
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str):
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            exp, status, payload = item
            if time.time() > exp:
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return status, payload

    def put(self, key: str, window: int, status: int, payload: dict):
        with self._lock:
            self._d[key] = (time.time() + window, status, payload)
            while len(self._d) > self._max:
                self._d.popitem(last=False)

    def sweep(self):
        with self._lock:
            now = time.time()
            for k in [k for k, (exp, *_r) in self._d.items() if now > exp]:
                del self._d[k]


DEDUP = DedupCache()

# ============================================================
# FAIL2BAN & MAIL
# ============================================================
BANS: dict = {}
FAILS = collections.defaultdict(collections.deque)
LAST_NOTIFY: dict = {}
NC_REQ, NC_FAIL = collections.deque(), collections.deque()


def load_bans():
    try:
        with closing(get_db()) as conn:
            rows = conn.execute("SELECT ip, expires_at FROM bans WHERE expires_at > datetime('now')").fetchall()
        for r in rows:
            try:
                BANS[r["ip"]] = dt.datetime.fromisoformat(r["expires_at"]).replace(
                    tzinfo=dt.timezone.utc).timestamp()
            except ValueError:
                pass
    except sqlite3.Error as e:
        logger.error(f"[BANS] Load failed: {e}")


def is_banned(ip: str) -> bool:
    exp = BANS.get(ip)
    if not exp:
        return False
    if time.time() > exp:
        BANS.pop(ip, None)
        return False
    return True


def ban_ip(ip: str, reason: str):
    minutes = max(1, sint(get_setting("ban_minutes"), 15))
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
    expires_str = expiry.replace(tzinfo=None).isoformat(sep=" ")
    try:
        with closing(get_db()) as conn:
            conn.execute(
                "INSERT INTO bans (ip, reason, expires_at) VALUES (?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, "
                "banned_at=datetime('now'), expires_at=excluded.expires_at",
                (ip, reason, expires_str))
            conn.commit()
    except sqlite3.Error:
        logger.exception(f"[FAIL2BAN] Ban write failed for {ip}")
    BANS[ip] = expiry.timestamp()
    logger.warning(f"[FAIL2BAN] Banning {ip} for {minutes}m — {reason}")
    if get_setting("notify_on_ban") in ("1", "true"):
        emit_event("ip.banned", ip=ip, reason=reason, detail=f"Ban duration: {minutes} mins")


def unban_ip(ip: str):
    BANS.pop(ip, None)
    with closing(get_db()) as conn:
        conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
        conn.commit()


def record_failure(ip: str):
    if not ip or ip == "unknown":
        return
    if ip in parse_csv(get_setting("ban_exempt_ips")):
        return
    dq = FAILS[ip]
    now, window = time.time(), sint(get_setting("ban_window_s"), 60)
    threshold = sint(get_setting("ban_failures"), 10)
    while dq and now - dq[0] > window:
        dq.popleft()
    dq.append(now)
    if threshold > 0 and len(dq) >= threshold:
        dq.clear()
        threading.Thread(target=ban_ip, args=(ip, f"{threshold} failures in {window}s"),
                         daemon=True).start()


def mail_send(subject: str, body: str) -> tuple:
    s = get_settings_obj()
    if s.get("smtp_enabled") not in ("1", "true"):
        return False, "SMTP disabled"
    try:
        password = dec_secret(s["smtp_pass_enc"]) if s.get("smtp_pass_enc") else None
    except InvalidToken:
        return False, "Invalid encrypted password (key mismatch?)"
    if s.get("smtp_user") and not password:
        return False, "SMTP user set but password missing"

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"], msg["From"], msg["To"] = subject, s["smtp_from"], s["smtp_to"]
        port = sint(s["smtp_port"], 587)
        if port == 465:   # Implicit SSL
            srv = smtplib.SMTP_SSL(s["smtp_host"], 465, timeout=15,
                                   context=ssl.create_default_context())
        else:             # STARTTLS
            srv = smtplib.SMTP(s["smtp_host"], port, timeout=15)
        try:
            if port != 465 and s.get("smtp_tls") in ("1", "true"):
                srv.starttls(context=ssl.create_default_context())
            if s.get("smtp_user") and password:
                srv.login(s["smtp_user"], password)
            srv.sendmail(s["smtp_from"], parse_csv(s["smtp_to"]), msg.as_string())
        finally:
            try:
                srv.quit()
            except Exception:
                pass
        return True, "Sent"
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        return False, str(e)


# ============================================================
# NOTIFICATIONS: EVENTS → MAIL + WEBHOOK
# ============================================================
EVENT_KINDS = {
    "route.exec", "route.invalid", "route.unauthorized", "route.forbidden",
    "rate.limited", "ip.banned", "failures", "volume", "admin.action",
}
NOTIFY_SUPP: dict = {}
_SECRET_KEY_RE = re.compile(r"(pass|pwd|secret|token|key|auth)", re.I)


def _events_filter(spec: str) -> set:
    out: set = set()
    for t in [t.strip().lower() for t in (spec or "").split(",") if t.strip()]:
        if t == "*":
            out |= set(EVENT_KINDS)
        elif t.startswith("-"):
            out.discard(t[1:])
        else:
            out.add(t)
    return out


def _tok_info(tok) -> Optional[dict]:
    if tok is None:
        return None
    try:
        return {"id": tok["id"], "prefix": tok["prefix"], "admin": bool(tok["is_admin"])}
    except Exception:
        return None


def _safe_params(params) -> str:
    """Mask sensitive fields and truncate."""
    try:
        if isinstance(params, dict):
            clean = {k: ("***" if _SECRET_KEY_RE.search(str(k)) else v) for k, v in params.items()}
            s = json.dumps(clean, ensure_ascii=False)
        else:
            s = json.dumps(params, ensure_ascii=False)
        return s[:400] + ("…" if len(s) > 400 else "")
    except Exception:
        return "<non-serializable>"


def _event_payload(kind: str, ctx: dict) -> dict:
    p: dict = {"event": kind, "time": dt.datetime.now().isoformat(sep=" ", timespec="seconds")}
    p["ip"] = ctx.get("ip", "unknown")
    if "token_row" in ctx:
        p["token"] = _tok_info(ctx.get("token_row"))
    elif "token_info" in ctx:
        p["token"] = ctx.get("token_info")
    for key in ("route", "method", "status", "exit_code", "duration_ms",
                "reason", "detail", "action", "scope", "count"):
        if ctx.get(key) is not None:
            p[key] = ctx.get(key)
    if ctx.get("params") is not None:
        p["params"] = _safe_params(ctx["params"])
    return p


def _event_body(p: dict, suppressed: int) -> str:
    tok = p.get("token")
    lines = [
        f"Event:      {p.get('event')}",
        f"Time:       {p.get('time')}",
        f"IP:         {p.get('ip')}",
        "Token:      " + (f"#{tok['id']} ({tok['prefix']}…) admin={tok['admin']}" if tok
                           else "none / invalid"),
    ]
    if p.get("route"):      lines.append(f"Route:      {p['route']}")
    if p.get("method"):     lines.append(f"Method:     {p['method']}")
    if p.get("status") is not None:     lines.append(f"HTTP:       {p['status']}")
    if p.get("exit_code") is not None:  lines.append(f"Exit code:  {p['exit_code']}")
    if p.get("duration_ms") is not None: lines.append(f"Duration:   {p['duration_ms']} ms")
    if p.get("reason"):     lines.append(f"Reason:     {p['reason']}")
    if p.get("detail"):     lines.append(f"Detail:     {p['detail']}")
    if p.get("count") is not None:      lines.append(f"Count:      {p['count']}")
    if p.get("params"):     lines.append(f"Params:     {p['params']}")
    if suppressed:
        lines.append(f"\n(+{suppressed} events suppressed by cooldown)")
    return "\n".join(lines)


def webhook_send(kind: str, payload: dict, force: bool = False) -> tuple:
    s = get_settings_obj()
    if s.get("webhook_enabled") not in ("1", "true"):
        return False, "webhook disabled"
    urls = parse_csv(s.get("webhook_url", ""))
    if not urls:
        return False, "webhook_url not set"
    if not force and kind not in _events_filter(s.get("webhook_events", "*")):
        return False, f"event '{kind}' excluded from webhooks"
    if not RL.hit(("hook",), sint(s.get("webhook_max_per_min"), 60), 60):
        return False, "internal webhook rate limit reached"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Nukexe-Event": kind}
    secret = s.get("webhook_secret", "")
    if secret:
        headers["X-Nukexe-Signature"] = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256).hexdigest()
    errs = []
    for url in urls:
        try:
            req = urllib.request.Request(url, data=body, headers=headers)
            urllib.request.urlopen(req, timeout=sint(s.get("webhook_timeout"), 10))
        except Exception as e:
            errs.append(f"{url}: {e}")
    if errs:
        logger.error(f"[WEBHOOK] {kind} → {'; '.join(errs)}")
        return False, "; ".join(errs)
    return True, "sent"


def _mail_notify(kind: str, payload: dict, s: dict):
    if s.get("smtp_enabled") not in ("1", "true"):
        return
    if kind not in _events_filter(s.get("notify_mail_events", "")):
        return
    now, cd = time.time(), sint(s.get("notify_cooldown_min"), 10) * 60
    if now - LAST_NOTIFY.get(kind, 0) < cd:
        NOTIFY_SUPP[kind] = NOTIFY_SUPP.get(kind, 0) + 1
        return
    LAST_NOTIFY[kind] = now
    supp = NOTIFY_SUPP.pop(kind, 0)
    threading.Thread(target=mail_send,
                     args=(f"[Nukexe] {kind}", _event_body(payload, supp)),
                     daemon=True, name=f"mail-{kind}").start()


def emit_event(kind: str, **ctx):
    try:
        payload = _event_payload(kind, ctx)
        s = get_settings_obj()
        if (s.get("webhook_enabled") in ("1", "true") and parse_csv(s.get("webhook_url", ""))
                and kind in _events_filter(s.get("webhook_events", "*"))):
            threading.Thread(target=webhook_send, args=(kind, payload), daemon=True).start()
        _mail_notify(kind, payload, s)
    except Exception:
        logger.exception(f"[EVENT] emission of '{kind}' failed")


def notify_check():
    now = time.time()
    for dq in (NC_REQ, NC_FAIL):
        while dq and now - dq[0] > 60:
            dq.popleft()
    f_thr, c_thr = sint(get_setting("notify_failures_per_min"), 30), sint(get_setting("notify_calls_per_min"), 200)
    if f_thr > 0 and len(NC_FAIL) >= f_thr:
        emit_event("failures", ip="-", count=len(NC_FAIL), reason="high error rate",
                   detail=f"{len(NC_FAIL)} responses >=400 in last 60s")
    if c_thr > 0 and len(NC_REQ) >= c_thr:
        emit_event("volume", ip="-", count=len(NC_REQ), reason="high volume",
                   detail=f"{len(NC_REQ)} requests in last 60s")

# ============================================================
# MIDDLEWARE
# ============================================================
def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _drain_body(request: Request, cap: int = 16 * 1024 * 1024, timeout: float = 10.0):
    async def _read_all():
        n = 0
        async for chunk in request.stream():
            n += len(chunk)
            if n >= cap:
                return
    try:
        await asyncio.wait_for(_read_all(), timeout=timeout)
    except Exception:
        pass


async def _maybe_drain(request: Request):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("content-length") or request.headers.get("transfer-encoding"):
            await _drain_body(request)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)

    ip = get_client_ip(request)
    request.state.ip = ip
    s = get_settings_obj()

    if is_banned(ip):
        await _maybe_drain(request)
        return JSONResponse({"detail": f"IP {ip} banned"}, status_code=403)

    if s["ip_mode"] == "whitelist" and ip not in parse_csv(s["ip_whitelist"]):
        record_failure(ip)
        await _maybe_drain(request)
        return JSONResponse({"detail": "IP not in whitelist"}, status_code=403)
    if s["ip_mode"] == "blacklist" and ip in parse_csv(s["ip_blacklist"]):
        await _maybe_drain(request)
        return JSONResponse({"detail": "IP in blacklist"}, status_code=403)

    max_body = sint(s.get("max_body_bytes"), 1048576)
    if max_body > 0:
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > max_body:
            await _maybe_drain(request)
            return JSONResponse({"detail": "Body too large"}, status_code=413)

    g = sint(s["rate_global_per_min"], 120)
    if g > 0 and not RL.hit(("g", ip), g, 60):
        record_failure(ip)
        emit_event("rate.limited", ip=ip, scope="global", status=429,
                   reason="global rate limit exceeded", detail=f"limit {g}/min")
        await _maybe_drain(request)
        return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429,
                            headers={"Retry-After": "60"})

    response = await call_next(request)

    if not request.url.path.startswith("/admin"):
        NC_REQ.append(time.time())
    if response.status_code in (400, 401, 403, 413, 429):
        NC_FAIL.append(time.time())
        record_failure(ip)
    notify_check()
    return response

# ============================================================
# COMMAND EXECUTION AND TEMPLATE PARSING
# ============================================================
def build_command(route: dict, params: dict) -> list:
    params = dict(params or {})

    if route["mode"] == "dangerous":
        exe = str(params.pop("_exe", "") or route["exe_path"]).strip()
        if not exe:
            raise HTTPException(400, "'_exe' parameter missing (dangerous mode)")
        return [exe]

    template = route.get("exe_args_template", "")
    if not template.strip():
        return [route["exe_path"]]

    try:
        raw_args = shlex.split(template)
    except ValueError as e:
        raise HTTPException(400, f"Template syntax error: {e}")

    def replacer(match):
        var_path = match.group(1)
        keys = var_path.split('.')
        val = params
        try:
            for k in keys:
                val = val[k]
            return str(val)
        except (KeyError, TypeError):
            raise HTTPException(400, f"Missing required API parameter: {var_path}")

    final_args = [re.sub(r'\{\$([a-zA-Z0-9_.]+)\}', replacer, arg) for arg in raw_args]
    return [route["exe_path"]] + final_args


def execute_command(cmd: list, timeout: int) -> dict:
    start = time.time()
    timeout = max(1, sint(timeout, 30))
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
        return {"exit_code": r.returncode, "stdout": r.stdout[:20000], "stderr": r.stderr[:20000],
                "duration_ms": round((time.time() - start) * 1000, 2), "command": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timed out after {timeout}s",
                "duration_ms": round((time.time() - start) * 1000, 2), "command": " ".join(cmd)}
    except FileNotFoundError:
        return {"exit_code": -1, "stdout": "", "stderr": f"File not found: {cmd[0]}",
                "duration_ms": 0, "command": " ".join(cmd)}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e),
                "duration_ms": 0, "command": " ".join(cmd)}


def audit(route_path: str, ip: str, token_id: Optional[int], params: dict, result: dict,
          method: Optional[str] = None, status: Optional[int] = None):
    logger.info(f"API CALLED: /{route_path} | IP: {ip} | Exit: {result['exit_code']} | {result['duration_ms']}ms")
    params_json = json.dumps(params, ensure_ascii=False)[:4000]
    reason = result["stderr"].strip()[:200] if result["exit_code"] != 0 else ""
    with closing(get_db()) as conn:
        conn.execute(
            "INSERT INTO audit_log (route_path, client_ip, token_id, params, exit_code, stdout, stderr, "
            "duration_ms, method, status, reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (route_path, ip, token_id, params_json, result["exit_code"],
             result["stdout"][:4000], result["stderr"][:4000], result["duration_ms"],
             method, status, reason))
        conn.commit()    

def _audit_reject(route_path: str, ip: str, token_id: Optional[int], params: dict,
                  method: str, status: int, reason):
    try:
        params_json = json.dumps(params, ensure_ascii=False)[:4000]
        with closing(get_db()) as conn:
            conn.execute(
                "INSERT INTO audit_log (route_path, client_ip, token_id, params, exit_code, stdout, stderr, "
                "duration_ms, method, status, reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (route_path, ip, token_id, params_json, None, "", "", None,
                 method, status, str(reason)[:500]))
            conn.commit()
    except Exception:
        logger.exception("Audit rejection failed") 


def _callback_url_ok(url: str, allow_private: bool) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    if allow_private:
        return True
    host = u.hostname.strip().lower().strip("[]")
    if host in ("localhost", "::1", "0.0.0.0"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return False
    except ValueError:
        pass
    return True


def forward_callback(url: str, status: int, payload: dict):
    try:
        data = json.dumps(payload, ensure_ascii=False).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json",
                                              "X-Exit-Code": str(status)})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        logger.error(f"[CALLBACK] Error to {url}: {e}")


def _update_job(job_id: str, sql: str):
    try:
        with closing(get_db()) as conn:
            conn.execute(sql, (job_id,))
            conn.commit()
    except Exception:
        logger.exception(f"[JOB {job_id}] State update failed")


def run_job(job_id: str, cmd: list, timeout: int, route_path: str, params: dict,
            ip: str, token_id: Optional[int], callback_url: str,
            dkey: Optional[str], dwin: int, notify_exec: bool = False,
            token_info: Optional[dict] = None):
    _update_job(job_id, "UPDATE jobs SET status='running' WHERE id=?")
    try:
        result = execute_command(cmd, timeout)
    except Exception as e:
        logger.exception(f"[JOB {job_id}] Execution error")
        result = {"exit_code": -1, "stdout": "", "stderr": f"Internal error: {e}",
                  "duration_ms": 0, "command": " ".join(cmd)}
    finally:
        if JOB_SLOTS is not None:
            try:
                JOB_SLOTS.release()
            except Exception:
                pass

    status = 200 if result["exit_code"] == 0 else 500
    final = "done" if result["exit_code"] == 0 else "failed"
    try:
        with closing(get_db()) as conn:
            conn.execute("UPDATE jobs SET status=?, exit_code=?, stdout=?, stderr=?, "
                         "finished_at=datetime('now') WHERE id=?",
                         (final, result["exit_code"], result["stdout"][:20000],
                          result["stderr"][:20000], job_id))
            conn.commit()
    except Exception:
        logger.exception(f"[JOB {job_id}] Final update failed")
    try:
        audit(route_path, ip, token_id, params, result)
    except Exception:
        logger.exception(f"[JOB {job_id}] Audit failed")
    if dkey:
        DEDUP.put(dkey, dwin, status, result)
    if notify_exec:
        emit_event("route.exec", ip=ip, token_info=token_info, route=route_path,
                   status=status, exit_code=result["exit_code"],
                   duration_ms=result["duration_ms"], params=params,
                   detail=f"job {job_id} ({final})")
    if callback_url:
        threading.Thread(target=forward_callback,
                         args=(callback_url, status, {**result, "job_id": job_id}),
                         daemon=True).start()

# ============================================================
# DASHBOARD
# ============================================================
def resource_path(relative_path: str) -> str:
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


_LOGO_B64: Optional[str] = None


def _set_appusermodelid():
    """Register process as a standalone app in Windows Taskbar."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Nukexe")
        except Exception:
            pass


def set_window_icon(root) -> None:
    ico = resource_path("nukexe.ico")
    if os.path.exists(ico):
        try:
            root.iconbitmap(ico)
            return
        except Exception:
            pass
    png = resource_path("nukexe.png")
    if os.path.exists(png):
        try:
            root._nukexe_icon = tk.PhotoImage(file=png)
            root.iconphoto(True, root._nukexe_icon)
        except Exception:
            pass


def get_logo_b64() -> str:
    global _LOGO_B64
    if _LOGO_B64 is None:
        logo_path = resource_path("nukexe.png")
        try:
            if os.path.exists(logo_path):
                with open(logo_path, "rb") as image_file:
                    _LOGO_B64 = "data:image/png;base64," + \
                                base64.b64encode(image_file.read()).decode("utf-8")
            else:
                _LOGO_B64 = ""
        except Exception as e:
            logger.warning(f"Logo not readable: {e}")
            _LOGO_B64 = ""
    return _LOGO_B64


_DASH_HTML_CACHE: Optional[str] = None


def get_dashboard_html() -> str:
    global _DASH_HTML_CACHE
    if _DASH_HTML_CACHE is None:
        try:
            html_content = Path(resource_path("dashboard.html")).read_text(encoding="utf-8")
            _DASH_HTML_CACHE = html_content.replace("{{APP_LOGO}}", get_logo_b64())
        except Exception as e:
            return (f"<h1>Interface load error:</h1><p>{e}</p>"
                    f"<p>Ensure dashboard.html is in the build.</p>")
    return _DASH_HTML_CACHE

# ============================================================
# API MODELS
# ============================================================
class RouteIn(BaseModel):
    path: str
    exe_path: str
    exe_args_template: str = ""
    mode: str = "whitelist"
    exec_mode: str = "sync"
    timeout: int = Field(30, ge=1, le=3600)
    requires_auth: bool = True
    rate_limit_per_min: int = Field(0, ge=0)
    dedup_seconds: int = Field(-1, ge=-1)
    allowed_ips: list = []
    blocked_ips: list = []
    description: str = ""
    allowed_token_ids: list = []


ROUTE_FIELDS = {"exe_path", "exe_args_template", "mode", "exec_mode",
                "timeout", "requires_auth", "rate_limit_per_min", "dedup_seconds",
                "allowed_ips", "blocked_ips", "enabled", "description", "allowed_token_ids"}

class TokenIn(BaseModel):
    description: str = ""
    is_admin: bool = False


def validate_path(path: str) -> str:
    path = path.strip().strip("/")
    parts = path.split("/")
    if len(parts) != 2 or not all(SEGMENT_RE.match(p) for p in parts):
        raise HTTPException(400, "Path format: TOOL/FUNCTION")
    if parts[0].lower() in RESERVED_PREFIXES:
        raise HTTPException(400, f"Prefix '{parts[0]}' is reserved")
    return path


def _parse_token_ids(raw) -> list:
    values = parse_json_list(raw) if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
    ids = []
    for x in values:
        try:
            ids.append(int(x))
        except (TypeError, ValueError):
            pass
    return ids

# ============================================================
# API ROUTES
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/admin/shutdown")
async def shutdown_api(_=Depends(require_admin)):
    def seppuku():
        time.sleep(1)
        try:
            logging.shutdown()
        except Exception:
            pass
        os._exit(0)
    threading.Thread(target=seppuku, daemon=True).start()
    return {"status": "shutting down"}


@app.get("/")
async def root():
    return {"service": "Nukexe", "admin_ui": "/admin/ui"}


@app.get("/admin/ui", response_class=HTMLResponse, include_in_schema=False)
async def admin_ui(request: Request):
    logger.info(f"[ADMIN] access /admin/ui | ip={get_client_ip(request)}")
    return get_dashboard_html()

@app.get("/admin/adminlog")
def adminlog_api(limit: int = 100, offset: int = 0, _=Depends(require_admin)):
    limit, offset = max(1, min(limit, 500)), max(0, offset)
    with closing(get_db()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM admin_log").fetchone()[0]
        rows = conn.execute("SELECT * FROM admin_log ORDER BY id DESC LIMIT ? OFFSET ?",
                            (limit, offset)).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


@app.get("/admin/routes")
def list_routes(_=Depends(require_admin)):
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM routes ORDER BY path").fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/routes")
def create_route(data: RouteIn, _=Depends(require_admin)):
    path = validate_path(data.path)
    if data.mode not in ("whitelist", "dangerous") or data.exec_mode not in ("sync", "async"):
        raise HTTPException(400, "Invalid enum")
    if data.mode == "dangerous" and not data.requires_auth:
        raise HTTPException(400, "'dangerous' routes MUST require authentication")
    if data.mode != "dangerous" and not Path(data.exe_path).exists():
        raise HTTPException(400, f"File not found: {data.exe_path}")
    try:
        with closing(get_db()) as conn:
            if conn.execute("SELECT 1 FROM routes WHERE path=? COLLATE NOCASE", (path,)).fetchone():
                raise HTTPException(409, "Route already exists")
            conn.execute(
                """INSERT INTO routes (path, exe_path, exe_args_template, mode, exec_mode, timeout,
                   requires_auth, rate_limit_per_min, dedup_seconds, allowed_ips, blocked_ips,
                   description, allowed_token_ids)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (path, data.exe_path, data.exe_args_template, data.mode, data.exec_mode,
                 data.timeout, int(data.requires_auth), data.rate_limit_per_min, data.dedup_seconds,
                 json.dumps(data.allowed_ips), json.dumps(data.blocked_ips),
                 data.description, json.dumps(data.allowed_token_ids)))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Route already exists")
    return {"status": "created", "path": path}


@app.put("/admin/routes/{route_id}")
def update_route(route_id: int, payload: dict, _=Depends(require_admin)):
    updates = {k: v for k, v in (payload or {}).items() if k in ROUTE_FIELDS}
    if not updates:
        raise HTTPException(400, "No valid fields")

    for k in ("allowed_ips", "blocked_ips", "allowed_token_ids"):
        if k in updates:
            v = updates[k]
            if isinstance(v, str):
                v = parse_json_list(v)
            updates[k] = json.dumps(v if isinstance(v, list) else [])
    if "requires_auth" in updates:
        updates["requires_auth"] = int(bool(updates["requires_auth"]))
    if "enabled" in updates:
        updates["enabled"] = int(bool(updates["enabled"]))
    if "timeout" in updates:
        t = sint(updates["timeout"], 0)
        if t < 1:
            raise HTTPException(400, "Timeout must be >= 1")
        updates["timeout"] = min(t, 3600)
    if "rate_limit_per_min" in updates:
        updates["rate_limit_per_min"] = max(0, sint(updates["rate_limit_per_min"], 0))
    if "dedup_seconds" in updates:
        updates["dedup_seconds"] = sint(updates["dedup_seconds"], -1)

    with closing(get_db()) as conn:
        row = conn.execute("SELECT mode, requires_auth FROM routes WHERE id=?", (route_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Route not found")
        if "mode" in updates and updates["mode"] not in ("whitelist", "dangerous"):
            raise HTTPException(400, "Invalid mode")
        if "exec_mode" in updates and updates["exec_mode"] not in ("sync", "async"):
            raise HTTPException(400, "Invalid exec_mode")
        new_mode = updates.get("mode", row["mode"])
        new_auth = bool(updates.get("requires_auth", row["requires_auth"]))
        if new_mode == "dangerous" and not new_auth:
            raise HTTPException(400, "'dangerous' routes MUST require authentication")

        sql = f"UPDATE routes SET {', '.join(k + '=?' for k in updates)} WHERE id=?"
        conn.execute(sql, (*updates.values(), route_id))
        conn.commit()
    return {"status": "updated"}


@app.delete("/admin/routes/{route_id}")
def delete_route(route_id: int, _=Depends(require_admin)):
    with closing(get_db()) as conn:
        conn.execute("DELETE FROM routes WHERE id=?", (route_id,))
        conn.commit()
    return {"status": "deleted"}


@app.get("/admin/fs/list")
def list_filesystem(path: str = "", _=Depends(require_admin)):
    if not path:
        if sys.platform == "win32":
            import string
            drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            return {"path": "", "items": [{"name": d, "is_dir": True, "path": d} for d in drives]}
        path = "/"

    p = Path(path)
    if not p.exists() or not p.is_dir():
        raise HTTPException(400, "Folder not found")

    items = []
    try:
        if str(p.parent) != str(p) and str(p.parent) != ".":
            items.append({"name": ".. (Parent)", "is_dir": True, "path": str(p.parent)})
        for entry in os.scandir(p):
            if entry.name.startswith('.'):
                continue
            try:
                is_d = entry.is_dir()
            except OSError:
                continue
            if is_d or entry.name.lower().endswith(('.exe', '.bat', '.ps1', '.cmd', '.sh')):
                items.append({"name": entry.name, "is_dir": is_d, "path": entry.path})
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return {"path": str(p), "items": items}
    except PermissionError:
        raise HTTPException(403, f"Insufficient permissions on {p}")
    except Exception as e:
        raise HTTPException(500, f"Read error: {e}")


@app.get("/admin/tokens")
def list_tokens(_=Depends(require_admin)):
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, prefix, description, is_admin, enabled, "
                            "created_at, last_used FROM api_tokens ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/tokens")
def create_token(data: TokenIn, _=Depends(require_admin)):
    tok = ("adm_" if data.is_admin else "exe_") + secrets.token_urlsafe(32)
    with closing(get_db()) as conn:
        conn.execute("INSERT INTO api_tokens (token_hash, prefix, description, is_admin) VALUES (?,?,?,?)",
                     (hashlib.sha256(tok.encode()).hexdigest(), tok[:10],
                      data.description, int(data.is_admin)))
        conn.commit()
    return {"token": tok}


@app.delete("/admin/tokens/{token_id}")
def delete_token(token_id: int, _=Depends(require_admin)):
    with closing(get_db()) as conn:
        conn.execute("DELETE FROM api_tokens WHERE id=?", (token_id,))
        conn.commit()
    return {"status": "revoked"}


@app.get("/admin/settings")
async def get_settings_api(_=Depends(require_admin)):
    s = get_settings_obj()
    for k in PROTECTED_SETTINGS:
        s.pop(k, None)
    s["smtp_pass_set"] = bool(get_setting("smtp_pass_enc"))
    return s


@app.post("/admin/settings")
def save_settings_api(payload: dict, _=Depends(require_admin)):
    changed = 0
    for k, v in (payload or {}).items():
        if k == "smtp_pass":
            if v:
                set_setting("smtp_pass_enc", enc_secret(str(v)))
                changed += 1
            continue
        if k in PROTECTED_SETTINGS or k not in DEFAULT_SETTINGS:
            continue
        if isinstance(v, bool):
            v = "1" if v else "0"
        set_setting(k, str(v))
        changed += 1
    return {"status": "saved", "updated": changed}


@app.post("/admin/settings/smtp/test")
def smtp_test(_=Depends(require_admin)):
    ok, msg = mail_send("[Nukexe] SMTP Test", f"Test sent at {dt.datetime.now()}")
    if not ok:
        raise HTTPException(400, msg)
    return {"status": "sent"}

@app.post("/admin/settings/webhook/test")
def webhook_test(_=Depends(require_admin)):
    payload = {"event": "webhook.test",
               "time": dt.datetime.now().isoformat(sep=" ", timespec="seconds"),
               "detail": "Test webhook from /admin/settings/webhook/test"}
    ok, msg = webhook_send("webhook.test", payload, force=True)
    if not ok:
        raise HTTPException(400, msg)
    return {"status": "sent"}


@app.get("/admin/bans")
def list_bans_api(_=Depends(require_admin)):
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM bans ORDER BY banned_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.delete("/admin/bans/{ip}")
def remove_ban_api(ip: str, _=Depends(require_admin)):
    unban_ip(ip)
    return {"status": "unbanned"}


@app.get("/admin/audit")
def audit_list_api(limit: int = 50, offset: int = 0, status: Optional[int] = None,
                   route: str = "", only_failures: bool = False, _=Depends(require_admin)):
    limit, offset = max(1, min(limit, 500)), max(0, offset)
    where, args = [], []
    if status is not None:
        where.append("status = ?"); args.append(status)
    if route:
        where.append("route_path LIKE ?"); args.append(f"%{route}%")
    if only_failures:
        where.append("(COALESCE(status, 0) >= 400 OR COALESCE(exit_code, 0) <> 0)")
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    with closing(get_db()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log" + wsql, args).fetchone()[0]
        rows = conn.execute("SELECT * FROM audit_log" + wsql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                            (*args, limit, offset)).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


@app.get("/admin/jobs")
def jobs_list_api(limit: int = 50, _=Depends(require_admin)):
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                            (max(1, min(limit, 200)),)).fetchall()
    return [dict(r) for r in rows]


@app.get("/jobs/{job_id}")
def job_status(job_id: str, request: Request):
    tok = check_token(request)
    if not tok:
        raise HTTPException(401, "Invalid or missing token")
    with closing(get_db()) as conn:
        job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        raise HTTPException(404, "Job not found")
    if not tok["is_admin"] and tok["id"] != job["token_id"]:
        raise HTTPException(403, "Access denied")
    return dict(job)


@app.get("/admin/config/export")
def config_export(_=Depends(require_admin)):
    with closing(get_db()) as conn:
        routes = [dict(r) for r in conn.execute("SELECT * FROM routes").fetchall()]
        tokens = [dict(r) for r in conn.execute(
            "SELECT token_hash, prefix, description, is_admin, enabled FROM api_tokens").fetchall()]
    s = get_settings_obj()
    for k in PROTECTED_SETTINGS:
        s.pop(k, None)
    return {"version": 1, "exported_at": dt.datetime.now().isoformat(),
            "routes": routes, "tokens": tokens, "settings": s}


ROUTE_IMPORT_DEFAULTS = {
    "exe_args_template": "", "mode": "whitelist", "exec_mode": "sync",
    "timeout": 30, "requires_auth": 1, "enabled": 1,
    "rate_limit_per_min": 0, "dedup_seconds": -1, "description": "",
    "allowed_ips": "[]", "blocked_ips": "[]", "allowed_token_ids": "[]",
    "notify_webhook": 0,
}


@app.post("/admin/config/import")
def config_import(payload: dict, _=Depends(require_admin)):
    c = {"routes": 0, "tokens": 0, "settings": 0}
    errors: list = []
    conn = get_db()
    try:
        for r in payload.get("routes", []):
            if not isinstance(r, dict) or not r.get("path") or not r.get("exe_path"):
                continue
            try:
                norm = dict(ROUTE_IMPORT_DEFAULTS)
                for k in ("path", "exe_path", "exe_args_template", "mode", "exec_mode",
                          "timeout", "requires_auth", "enabled", "rate_limit_per_min",
                          "dedup_seconds", "description", "notify_webhook"):
                    if k in r:
                        norm[k] = r[k]
                for k in ("allowed_ips", "blocked_ips", "allowed_token_ids"):
                    v = r.get(k, "[]")
                    if isinstance(v, list):
                        norm[k] = json.dumps(v)
                    elif isinstance(v, str):
                        norm[k] = json.dumps(parse_json_list(v))
                    else:
                        norm[k] = "[]"
                conn.execute(
                    """INSERT INTO routes (path, exe_path, exe_args_template, mode, exec_mode, timeout,
                       requires_auth, enabled, rate_limit_per_min, dedup_seconds, allowed_ips,
                       blocked_ips, description, allowed_token_ids, notify_webhook)
                       VALUES (:path,:exe_path,:exe_args_template,:mode,:exec_mode,:timeout,
                       :requires_auth,:enabled,:rate_limit_per_min,:dedup_seconds,:allowed_ips,
                       :blocked_ips,:description,:allowed_token_ids,:notify_webhook)
                       ON CONFLICT(path) DO UPDATE SET
                       exe_path=excluded.exe_path, exe_args_template=excluded.exe_args_template,
                       mode=excluded.mode, exec_mode=excluded.exec_mode, timeout=excluded.timeout,
                       requires_auth=excluded.requires_auth, enabled=excluded.enabled,
                       rate_limit_per_min=excluded.rate_limit_per_min, dedup_seconds=excluded.dedup_seconds,
                       allowed_ips=excluded.allowed_ips, blocked_ips=excluded.blocked_ips,
                       description=excluded.description, allowed_token_ids=excluded.allowed_token_ids,
                       notify_webhook=excluded.notify_webhook""",
                    norm)
                c["routes"] += 1
            except Exception as e:
                errors.append(f"route '{r.get('path')}': {e}")
        for t in payload.get("tokens", []):
            if not isinstance(t, dict) or not t.get("token_hash"):
                continue
            try:
                norm = {"prefix": "", "description": "", "is_admin": 0, "enabled": 1}
                norm.update({k: t[k] for k in ("token_hash", "prefix", "description",
                                               "is_admin", "enabled") if k in t})
                conn.execute(
                    "INSERT INTO api_tokens (token_hash, prefix, description, is_admin, enabled) "
                    "VALUES (:token_hash,:prefix,:description,:is_admin,:enabled) "
                    "ON CONFLICT(token_hash) DO UPDATE SET description=excluded.description, "
                    "is_admin=excluded.is_admin, enabled=excluded.enabled", norm)
                c["tokens"] += 1
            except Exception as e:
                errors.append(f"token: {e}")
        conn.commit()
    finally:
        conn.close()
    for k, v in (payload.get("settings") or {}).items():
        if k in PROTECTED_SETTINGS or k not in DEFAULT_SETTINGS or isinstance(v, (dict, list)):
            continue
        set_setting(k, str(v))
        c["settings"] += 1
    return {"status": "imported", **c, "errors": errors[:20]}


@app.api_route("/{tool}/{function}", methods=["GET", "POST"], include_in_schema=False)
async def dynamic_route(tool: str, function: str, request: Request):
    path = f"{tool}/{function}"
    ip = getattr(request.state, "ip", None) or get_client_ip(request)
    s = get_settings_obj()
    params: dict = {}
    token_id: Optional[int] = None

    try:
        # ---------- Body first ----------
        callback_url = None
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:
                raise HTTPException(400, "Invalid JSON")
            if not isinstance(body, dict):
                raise HTTPException(400, "Body must be a dict")
            params, callback_url = body.get("params", {}), body.get("callback_url")
            if not isinstance(params, dict):
                raise HTTPException(400, "'params' must be dict")
            if callback_url is not None:
                callback_url = str(callback_url)
                if not _callback_url_ok(callback_url, get_setting("allow_private_callbacks") in ("1", "true")):
                    raise HTTPException(400, "Invalid callback_url")
        else:
            params = dict(request.query_params)
        params.pop("_token", None)

        # ---------- Route ----------
        route_row = await run_in_threadpool(_get_enabled_route, path)
        if route_row is None:
            tok_ctx = await run_in_threadpool(check_token, request)
            if tok_ctx:
                token_id = tok_ctx["id"]
            emit_event("route.invalid", ip=ip, token_row=tok_ctx, route=path,
                       method=request.method, status=404,
                       reason="route not found or disabled")
            raise HTTPException(404, "Route not found or disabled")
        route = dict(route_row)

        # ---------- Auth ----------
        token_row = await run_in_threadpool(check_token, request) if route["requires_auth"] else None
        if route["requires_auth"] and not token_row:
            emit_event("route.unauthorized", ip=ip, route=path, method=request.method,
                       status=401, reason="missing or invalid token")
            raise HTTPException(401, "Invalid or missing token")
        if token_row:
            token_id = token_row["id"]

        if token_row and not token_row["is_admin"]:
            allowed_tids = _parse_token_ids(route.get("allowed_token_ids"))
            if allowed_tids and token_row["id"] not in allowed_tids:
                emit_event("route.forbidden", ip=ip, token_row=token_row, route=path,
                           method=request.method, status=403,
                           reason="token not authorized for this route")
                raise HTTPException(403, "Token not authorized")

        # ---------- IP Check ----------
        blocked, allowed = parse_json_list(route["blocked_ips"]), parse_json_list(route["allowed_ips"])
        if blocked and ip in blocked:
            emit_event("route.forbidden", ip=ip, token_row=token_row, route=path,
                       method=request.method, status=403, reason="IP in blocked_ips")
            raise HTTPException(403, "IP not authorized")
        if allowed and ip not in allowed:
            emit_event("route.forbidden", ip=ip, token_row=token_row, route=path,
                       method=request.method, status=403, reason="IP not in allowed_ips")
            raise HTTPException(403, "IP not authorized")

        # ---------- Rate limit ----------
        lim = route["rate_limit_per_min"] or sint(s["rate_route_per_min"], 30)
        if lim > 0 and not RL.hit(("r", ip, path), lim, 60):
            emit_event("rate.limited", ip=ip, token_row=token_row, route=path,
                       method=request.method, status=429, scope="route",
                       reason="route rate limit exceeded", detail=f"limit {lim}/min")
            raise HTTPException(429, "Route rate limit exceeded")

        # ---------- Dedup ----------
        dwin = route["dedup_seconds"] if sint(route["dedup_seconds"], -1) >= 0 else sint(s["dedup_window_s"], 30)
        dkey = None
        if dwin > 0:
            dkey = hashlib.sha256(json.dumps(
                {"ip": ip, "tok": token_id or 0, "p": path, "params": params},
                sort_keys=True).encode()).hexdigest()
            cached = DEDUP.get(dkey)
            if cached:
                status, payload = cached
                return JSONResponse({**payload, "deduplicated": True},
                                    status_code=status, headers={"X-Dedup": "hit"})

        try:
            cmd = build_command(route, params)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(400, f"Command build error: {e}")
        timeout = max(1, sint(route["timeout"], 30))
        notify_exec = bool(route.get("notify_webhook"))
        token_info = _tok_info(token_row)

        if route["exec_mode"] == "async":
            if EXECUTOR is None or JOB_SLOTS is None:
                raise HTTPException(503, "Server not ready")
            if not JOB_SLOTS.acquire(blocking=False):
                emit_event("rate.limited", ip=ip, token_row=token_row, route=path,
                           method=request.method, status=503, scope="queue", reason="job queue saturated")
                raise HTTPException(503, "Job queue full")
            job_id = uuid.uuid4().hex

            def _insert_job():
                with closing(get_db()) as conn:
                    conn.execute("INSERT INTO jobs (id, route_path, token_id, params, status, callback_url) "
                                 "VALUES (?,?,?,?,'queued',?)",
                                 (job_id, path, token_id, json.dumps(params, ensure_ascii=False),
                                  callback_url or ""))
                    conn.commit()
            try:
                await run_in_threadpool(_insert_job)
            except Exception:
                JOB_SLOTS.release()
                logger.exception("Job insertion failed")
                raise HTTPException(500, "Internal error during job creation")

            if dkey:
                DEDUP.put(dkey, dwin, 202,
                          {"job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"})

            try:
                EXECUTOR.submit(run_job, job_id, cmd, timeout, path, params, ip,
                                token_id, callback_url or "", dkey, dwin, notify_exec, token_info)
            except RuntimeError:
                JOB_SLOTS.release()
                raise HTTPException(503, "Server shutting down")
            return JSONResponse({"job_id": job_id, "status": "queued",
                                 "status_url": f"/jobs/{job_id}"}, status_code=202)

        result = await run_in_threadpool(execute_command, cmd, timeout)
        status = 200 if result["exit_code"] == 0 else 500
        await run_in_threadpool(audit, path, ip, token_id, params, result,
                                method=request.method, status=status)
        if dkey:
            DEDUP.put(dkey, dwin, status, result)
        if notify_exec:
            emit_event("route.exec", ip=ip, token_row=token_row, route=path,
                       method=request.method, status=status,
                       exit_code=result["exit_code"], duration_ms=result["duration_ms"],
                       params=params)
        if callback_url:
            threading.Thread(target=forward_callback, args=(callback_url, status, result),
                             daemon=True).start()
        return JSONResponse(result, status_code=status)

    except HTTPException as e:
        await run_in_threadpool(_audit_reject, path, ip, token_id, params,
                                request.method, e.status_code, e.detail)
        raise
    except Exception as e:
        await run_in_threadpool(_audit_reject, path, ip, token_id, params,
                                request.method, 500, f"internal error: {e}")
        raise

def _get_enabled_route(path: str) -> Optional[sqlite3.Row]:
    with closing(get_db()) as conn:
        return conn.execute("SELECT * FROM routes WHERE path=? COLLATE NOCASE AND enabled=1",
                            (path,)).fetchone()

# ============================================================
# MAINTENANCE
# ============================================================
def _prune_memory():
    now = time.time()
    for k in [k for k, v in BANS.items() if v < now]:
        BANS.pop(k, None)
    for k in [k for k, dq in FAILS.items() if not dq or now - dq[-1] > 3600]:
        FAILS.pop(k, None)
    for k in [k for k, t in _LAST_USED_UPDATE.items() if now - t > 3600]:
        _LAST_USED_UPDATE.pop(k, None)


def maintenance_loop():
    while True:
        time.sleep(1800)
        try:
            RL.cleanup()
            DEDUP.sweep()
            _prune_memory()
            with closing(get_db()) as conn:
                retention = sint(get_setting("jobs_retention_h"), 24)
                conn.execute("DELETE FROM jobs WHERE created_at < datetime('now', ?)",
                             (f"-{retention} hours",))
                max_rows = sint(get_setting("jobs_max_rows"), 50000)
                if max_rows > 0:
                    conn.execute("DELETE FROM jobs WHERE id IN "
                                 "(SELECT id FROM jobs ORDER BY created_at DESC LIMIT -1 OFFSET ?)",
                                 (max_rows,))
                days = max(1, sint(get_setting("audit_retention_days"), 30))
                conn.execute("DELETE FROM audit_log WHERE created_at < datetime('now', ?)",
                             (f"-{days} days",))
                audit_max = sint(get_setting("audit_max_rows"), 100000)
                if audit_max > 0:
                    conn.execute("DELETE FROM audit_log WHERE id IN "
                                 "(SELECT id FROM audit_log ORDER BY id DESC LIMIT -1 OFFSET ?)",
                                 (audit_max,))
                conn.execute("DELETE FROM bans WHERE expires_at <= datetime('now')")
                conn.execute("DELETE FROM admin_log WHERE created_at < datetime('now', ?)", (f"-{days} days",))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            _maybe_vacuum()
        except Exception as e:
            logger.error(f"[MAINTENANCE] Error: {e}")


def _maybe_vacuum():
    now = time.time()
    if sint(get_setting("last_vacuum_ts"), 0) and now - sint(get_setting("last_vacuum_ts"), 0) < 86400:
        return
    try:
        with closing(get_db()) as conn:
            conn.execute("VACUUM")
        set_setting("last_vacuum_ts", str(int(now)))
        logger.info("[MAINTENANCE] VACUUM complete.")
    except sqlite3.Error as e:
        logger.warning(f"[MAINTENANCE] VACUUM skipped: {e}")

# ============================================================
# SERVER, POPUP & TRAY
# ============================================================
class UvicornServer(uvicorn.Server):
    def install_signal_handlers(self):
        pass


def _fatal_popup(title: str, message: str):
    logger.error(f"{title}: {message}")
    if HAS_TK:
        try:
            root = tk.Tk()
            root.withdraw()
            set_window_icon(root)                              
            messagebox.showerror(title, message, parent=root)
            root.destroy()
        except Exception:
            pass


def show_startup_popup(host: str, port: int, scheme: str, new_token: Optional[str] = None):
    url = f"{scheme}://localhost:{port}/admin/ui"
    if not HAS_TK:
        logger.info(f"Dashboard: {url}")
        if new_token:
            logger.warning("NEW ADMIN TOKEN: " + new_token)
        return
    try:
        root = tk.Tk()
    except Exception:
        logger.exception("Startup window failed.")
        if new_token:
            logger.warning("ADMIN TOKEN: " + new_token)
        return

    try:
        set_window_icon(root) 
        root.title("Nukexe")
        root.minsize(450, 220)
        frame = tk.Frame(root, padx=20, pady=20)
        frame.pack(expand=True, fill="both")

        tk.Label(frame, text="Nukexe is running in the background.\n\nWeb dashboard available at:",
                 justify="center", font=("Arial", 10)).pack(pady=(0, 5))

        url_entry = tk.Entry(frame, width=40, justify="center",
                             font=("Arial", 10, "bold"), fg="#3b82f6", relief="flat")
        url_entry.insert(0, url)
        url_entry.config(state="readonly")
        url_entry.pack(pady=5)

        def open_dashboard():
            try:
                webbrowser.open(url)
            except Exception:
                logger.exception("webbrowser.open failed")

        tk.Button(frame, text="Dashboard", command=open_dashboard,
                  cursor="hand2", width=18).pack(pady=(10, 0))

        if new_token:
            tk.Label(frame, text="ADMIN TOKEN (Save it now!):",
                     fg="red", font=("Arial", 10, "bold")).pack(pady=(15, 5))
            tok_entry = tk.Entry(frame, width=45, justify="center", font=("Consolas", 11))
            tok_entry.insert(0, new_token)
            tok_entry.config(state="readonly")
            tok_entry.pack(pady=5)

            def copy_tok():
                root.clipboard_clear()
                root.clipboard_append(new_token)
                btn_copy.config(text="✓ Copied!", fg="green")

            btn_copy = tk.Button(frame, text="Copy Token", command=copy_tok, cursor="hand2")
            btn_copy.pack(pady=5)

        tk.Button(frame, text="Close Window", command=root.destroy, width=15).pack(pady=(15, 0))

        root.update_idletasks()
        root.eval("tk::PlaceWindow . center")
        root.mainloop()
    except Exception:
        logger.exception("Startup popup error")
        if new_token:
            logger.warning("ADMIN TOKEN: " + new_token)


def generate_selfsigned(certfile: str, keyfile: str, hostname: str = "localhost"):
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(hostname), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    Path(keyfile).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    Path(certfile).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _server_started(server) -> bool:
    if getattr(server, "started", False):
        return True
    state = getattr(server, "server_state", None)
    return bool(getattr(state, "started", False))


def _wait_server_up(server, thread, host: str, port: int, timeout: float = 15.0) -> tuple:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _server_started(server):
            return True, ""
        if not thread.is_alive():
            break
        time.sleep(0.1)
    probe_host = host if host not in ("", "0.0.0.0", "::") else "127.0.0.1"
    try:
        with socket.create_connection((probe_host, port), timeout=1.0):
            return True, ""
    except OSError:
        pass
    return False, "Port busy or bind failed."


def _build_tray(server, scheme: str, port: int, stop_event: threading.Event):
    logo_path = resource_path("nukexe.png")
    try:
        tray_image = Image.open(logo_path) if os.path.exists(logo_path) \
            else Image.new("RGB", (64, 64), (59, 130, 246))
    except Exception:
        tray_image = Image.new("RGB", (64, 64), (59, 130, 246))

    def on_open_ui(icon, item):
        webbrowser.open(f"{scheme}://localhost:{port}/admin/ui")

    def on_exit(icon, item):
        stop_event.set()

    menu = pystray.Menu(
        pystray.MenuItem(f"Open Web UI ({scheme.upper()})", on_open_ui, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Turn off Nukexe", on_exit),
    )
    return pystray.Icon("Nukexe", tray_image, f"Nukexe (Port {port})", menu)


def main() -> int:
    _set_appusermodelid()
    ap = argparse.ArgumentParser(description="Nukexe")
    ap.add_argument("--host", default=None, help="Emergency: override DB host")
    ap.add_argument("--port", type=int, default=None, help="Emergency: override DB port")
    args, _ = ap.parse_known_args()

    try:
        new_token = init_db()
    except Exception as e:
        _fatal_popup("Nukexe — Startup Error",
                     f"Database initialization failed:\n{DB_PATH}\n\n{e}\n\n"
                     "If in 'Program Files', move to a writable folder.")
        return 1

    db_host = get_setting("server_host", "0.0.0.0")
    db_port = sint(get_setting("server_port", "8000"), 8000)
    ssl_mode = get_setting("ssl_mode", "0")

    final_host = args.host if args.host else db_host
    final_port = args.port if args.port else db_port

    trust_proxy = get_setting("trust_proxy") in ("1", "true")
    fwd_allow = (get_setting("forwarded_allow_ips", "127.0.0.1").strip() or "127.0.0.1")

    ssl_kwargs = {}
    if ssl_mode == "2":
        c_cert, c_key = get_setting("ssl_certfile", ""), get_setting("ssl_keyfile", "")
        if c_cert and c_key and os.path.exists(c_cert) and os.path.exists(c_key):
            ssl_kwargs = {"ssl_certfile": c_cert, "ssl_keyfile": c_key}
        else:
            logger.error("Custom certificates not found, fallback to HTTP.")
    elif ssl_mode == "1":
        try:
            CERTS_DIR.mkdir(parents=True, exist_ok=True)
            cf, kf = str(CERTS_DIR / "cert.pem"), str(CERTS_DIR / "key.pem")
            generate_selfsigned(cf, kf)
            ssl_kwargs = {"ssl_certfile": cf, "ssl_keyfile": kf}
        except Exception as e:
            logger.error(f"Self-signed cert generation failed ({e}): fallback to HTTP.")

    scheme = "https" if ssl_kwargs else "http"

    config = uvicorn.Config(
        app,
        host=final_host,
        port=final_port,
        log_level="warning",
        log_config=None,
        proxy_headers=trust_proxy,
        forwarded_allow_ips=fwd_allow,
        **ssl_kwargs,
    )
    server = UvicornServer(config)

    def _run_server():
        try:
            server.run()
        except SystemExit:
            pass
        except BaseException:
            logger.exception("Uvicorn: fatal error")

    server_thread = threading.Thread(target=_run_server, name="uvicorn", daemon=True)
    server_thread.start()

    ok, err_msg = _wait_server_up(server, server_thread, final_host, final_port, timeout=15.0)
    if not ok:
        _fatal_popup("Nukexe — Startup Error",
                     f"Cannot start server on {final_host}:{final_port}.\n"
                     f"{err_msg}\nCheck Nukexe.log.")
        return 1

    show_startup_popup(final_host, final_port, scheme, new_token)

    stop_event = threading.Event()
    icon = None
    if HAS_TRAY:
        try:
            icon = _build_tray(server, scheme, final_port, stop_event)
            icon.run_detached()
        except Exception:
            logger.exception("Tray icon unavailable.")
            icon = None
    else:
        logger.warning("pystray/PIL unavailable: shutdown via /admin/shutdown.")

    logger.info(f"Nukexe active on {scheme}://{final_host}:{final_port}")

    while not stop_event.wait(timeout=5.0):
        if not server_thread.is_alive():
            logger.error("Server thread died unexpectedly.")
            break

    server.should_exit = True
    if icon is not None:
        try:
            icon.stop()
        except Exception:
            pass
    server_thread.join(timeout=10)
    logger.info("Shutdown complete.")
    logging.shutdown()
    os._exit(0)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        logger.exception("Fatal error at startup")
        _fatal_popup("Nukexe — Startup Error",
                     "Unexpected error at startup.\nCheck Nukexe.log.")
        sys.exit(1)