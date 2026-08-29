import os
import sys
import math
import time
import datetime
import sqlite3
import subprocess
import shutil
import re
import json
import threading
import signal
import fcntl
import secrets
import string
import io
import tempfile
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, stream_with_context, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", "/etc/strongswan-panel/panel.db")
SECRETS_PATH = os.environ.get("SECRETS_PATH", "/etc/ipsec.secrets")
SECRET_KEY_PATH = os.environ.get("SECRET_KEY_PATH", "/etc/strongswan-panel/secret.key")
SERVER_DOMAIN = os.environ.get("SERVER_DOMAIN", "vpn.example.com")
PANEL_PORT = int(os.environ.get("PANEL_PORT", 8000))

def generate_random_pwd(length=8):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_persistent_secret_key():
    candidates = [
        SECRET_KEY_PATH,
        os.path.join(BASE_DIR, ".secret.key")
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    key = f.read()
                    if len(key) >= 16:
                        return key
            except Exception:
                pass

    new_key = os.urandom(32)
    for path in candidates:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "wb") as f:
                f.write(new_key)
            os.chmod(path, 0o600)
            return new_key
        except Exception:
            continue
    return new_key

APP_VERSION = "1.7.5"

SUB_SESSION_LIFETIME = 3 * 24 * 3600  # 3 days in seconds (259200s)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1
)

app.secret_key = get_persistent_secret_key()
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=4320)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

@app.errorhandler(429)
@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.accept_mimetypes.best == "application/json"
    is_sub = request.path.startswith("/sub")
    msg = "Too many requests. Please slow down and try again later."
    if is_ajax:
        return jsonify({"success": False, "error": msg}), 429
    flash(msg, "danger")
    if is_sub:
        username_arg = (request.args.get("u") or request.args.get("username") or request.args.get("user") or "").strip()
        return render_template("sub.html",
                               is_logged_in=False,
                               prefilled_username=username_arg,
                               server_domain=get_system_config("server_domain", SERVER_DOMAIN),
                               error=msg), 429
    return render_template("login.html"), 429

@app.before_request
def sync_session_lifetime():
    try:
        timeout_mins = int(get_system_config("admin_session_timeout", "4320"))
        timeout_mins = max(1, min(43200, timeout_mins))
    except (ValueError, TypeError):
        timeout_mins = 4320
    app.permanent_session_lifetime = datetime.timedelta(minutes=timeout_mins)

shutdown_event = threading.Event()

def signal_handler(signum, frame):
    shutdown_event.set()

try:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
except Exception:
    pass

@app.context_processor
def inject_globals():
    try:
        session_timeout = int(get_system_config("admin_session_timeout", "4320"))
        session_timeout = max(1, min(43200, session_timeout))
    except (ValueError, TypeError):
        session_timeout = 4320
    return dict(
        app_version=APP_VERSION,
        current_admin=session.get("admin_user", ""),
        vpn_enabled=(get_system_config("vpn_enabled", "1") == "1"),
        base_path=request.script_root,
        panel_path=get_system_config("panel_path", ""),
        session_timeout=session_timeout,
        session_timeout_formatted=format_duration_minutes(session_timeout)
    )

prev_cpu_times = None
prev_net_bytes = None
prev_net_time = None

def get_cpu_raw():
    try:
        with open('/proc/stat') as f:
            line = f.readline()
            vals = [float(x) for x in line.split()[1:8]]
            idle = vals[3] + vals[4]
            total = sum(vals)
            return idle, total
    except Exception:
        return 0, 0

def get_net_raw():
    rx, tx = 0, 0
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if ':' in line:
                    iface, data = line.split(':', 1)
                    if iface.strip() != 'lo':
                        fields = data.split()
                        rx += int(fields[0])
                        tx += int(fields[8])
    except Exception:
        pass
    return rx, tx

def format_speed(bps):
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps / (1024 * 1024):.2f} MB/s"

def get_system_metrics():
    global prev_cpu_times, prev_net_bytes, prev_net_time
    now = time.time()

    try:
        total, used, free = shutil.disk_usage('/')
        disk_pct = round((used / total) * 100, 1)
        disk_used_gb = round(used / (1024**3), 1)
        disk_total_gb = round(total / (1024**3), 1)
    except Exception:
        disk_pct, disk_used_gb, disk_total_gb = 0, 0, 0

    try:
        mem = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].split()[0])
        mem_total = mem.get('MemTotal', 1)
        mem_avail = mem.get('MemAvailable', mem.get('MemFree', 0))
        mem_used = mem_total - mem_avail
        ram_pct = round((mem_used / mem_total) * 100, 1)
        ram_used_gb = round(mem_used / 1024 / 1024, 2)
        ram_total_gb = round(mem_total / 1024 / 1024, 2)
    except Exception:
        ram_pct, ram_used_gb, ram_total_gb = 0, 0, 0

    curr_idle, curr_total = get_cpu_raw()
    cpu_pct = 0.0
    if prev_cpu_times:
        p_idle, p_total = prev_cpu_times
        d_idle = curr_idle - p_idle
        d_total = curr_total - p_total
        if d_total > 0:
            cpu_pct = round(max(0.0, min(100.0, (1.0 - (d_idle / d_total)) * 100)), 1)
    prev_cpu_times = (curr_idle, curr_total)

    curr_rx, curr_tx = get_net_raw()
    rx_spd, tx_spd = "0 B/s", "0 B/s"
    if prev_net_bytes and prev_net_time:
        dt = now - prev_net_time
        if dt > 0:
            p_rx, p_tx = prev_net_bytes
            rx_spd = format_speed(max(0, curr_rx - p_rx) / dt)
            tx_spd = format_speed(max(0, curr_tx - p_tx) / dt)
    prev_net_bytes = (curr_rx, curr_tx)
    prev_net_time = now

    cpu_cores = os.cpu_count() or 1

    return {
        "cpu_percent": cpu_pct,
        "cpu_cores": cpu_cores,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "ram_percent": ram_pct,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "disk_percent": disk_pct,
        "net_rx": rx_spd,
        "net_tx": tx_spd
    }

get_system_metrics()

def get_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def get_db_usernames():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        usernames = {row["username"] for row in cursor.fetchall()}
        conn.close()
        return usernames
    except Exception:
        return set()

def get_system_config(key, default="1"):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_config WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        if row and row["value"] is not None:
            return row["value"]
        return default
    except Exception:
        return default

def set_system_config(key, value):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO system_config (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (key, str(value)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error setting config {key}: {e}", file=sys.stderr)

def format_duration_minutes(minutes):
    try:
        mins = int(minutes)
    except (ValueError, TypeError):
        return f"{minutes} mins"
    if mins <= 0:
        return "0 mins"
    if mins < 60:
        return f"{mins} min" if mins == 1 else f"{mins} mins"
    if mins % 1440 == 0:
        days = mins // 1440
        return f"{days} day" if days == 1 else f"{days} days"
    if mins < 1440 and mins % 60 == 0:
        hours = mins // 60
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    days = mins // 1440
    rem = mins % 1440
    hours = rem // 60
    m = rem % 60
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if m > 0:
        parts.append(f"{m}m")
    return " ".join(parts)

def init_db():
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT
        )
        """)

        try:
            cursor.execute("ALTER TABLE admin ADD COLUMN created_at TEXT")
        except Exception:
            pass

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            max_traffic_gb REAL DEFAULT 0,
            used_traffic_bytes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expire_date TEXT,
            is_active INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            last_online_at TEXT,
            max_devices INTEGER DEFAULT 10
        )
        """)

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_online_at TEXT")
        except Exception:
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN max_devices INTEGER DEFAULT 10")
        except Exception:
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_ip TEXT")
        except Exception:
            pass

        cursor.execute("UPDATE users SET max_devices = 10 WHERE max_devices IS NULL OR max_devices <= 0 OR max_devices > 10")

        cursor.execute("SELECT COUNT(*) as cnt FROM admin")
        if cursor.fetchone()["cnt"] == 0:
            rand_admin_user = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
            rand_admin_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            default_hash = generate_password_hash(rand_admin_pass)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO admin (username, password_hash, created_at) VALUES (?, ?, ?)", (rand_admin_user, default_hash, now))

        cursor.execute("SELECT COUNT(*) as cnt FROM users")
        if cursor.fetchone()["cnt"] == 0:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            default_user_pass = generate_random_pwd(8)
            cursor.execute("""
                INSERT INTO users (username, password, max_traffic_gb, used_traffic_bytes, created_at, expire_date, is_active, note, last_online_at, max_devices)
                VALUES ('user1', ?, 0, 0, ?, NULL, 1, 'Default VPN User', NULL, 10)
            """, (default_user_pass, now))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error in init_db: {e}", file=sys.stderr)

sync_lock = threading.Lock()

def disconnect_all_sas():
    """Disconnect all active StrongSwan SAs when VPN is killed."""
    try:
        subprocess.run(["ipsec", "down", "ikev2-vpn"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        online = fetch_online_users_raw()
        for u, data in online.items():
            for sa_id in data.get("sa_ids", []):
                if sa_id:
                    subprocess.run(["ipsec", "down", f"ikev2-vpn[{sa_id}]"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["ipsec", "down", str(sa_id)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        invalidate_online_cache()
    except Exception as e:
        print(f"[!] Error disconnecting all SAs: {e}", file=sys.stderr)

def disconnect_user_sas(username, online_dict=None):
    """Safely disconnect all active StrongSwan SAs for a specific username."""
    if not username:
        return
    try:
        if online_dict is None:
            online_dict = fetch_online_users_raw()
        user_info = online_dict.get(username)
        if user_info:
            for sa_id in user_info.get("sa_ids", []):
                if sa_id:
                    subprocess.run(["ipsec", "down", f"ikev2-vpn[{sa_id}]"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["ipsec", "down", str(sa_id)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            invalidate_online_cache()
    except Exception as e:
        print(f"[!] Error disconnecting SAs for {username}: {e}", file=sys.stderr)

def disconnect_excess_sas(username, max_devices, online_dict=None):
    """Disconnect oldest excess SAs if a user has more connections than max_devices."""
    if not username:
        return
    try:
        max_dev = max(1, min(10, int(max_devices or 10)))
        if online_dict is None:
            online_dict = fetch_online_users_raw()
        user_info = online_dict.get(username)
        if user_info:
            sa_ids = user_info.get("sa_ids", [])
            if len(sa_ids) > max_dev:
                try:
                    sorted_sas = sorted(sa_ids, key=lambda x: int(x) if str(x).isdigit() else str(x))
                except Exception:
                    sorted_sas = list(sa_ids)
                excess_count = len(sorted_sas) - max_dev
                excess_sas = sorted_sas[:excess_count]
                for sa_id in excess_sas:
                    if sa_id:
                        subprocess.run(["ipsec", "down", f"ikev2-vpn[{sa_id}]"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(["ipsec", "down", str(sa_id)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                invalidate_online_cache()
    except Exception as e:
        print(f"[!] Error disconnecting excess SAs for {username}: {e}", file=sys.stderr)

def sync_ipsec_secrets():
    with sync_lock:
        try:
            vpn_enabled = (get_system_config("vpn_enabled", "1") == "1")
            if not vpn_enabled:
                os.makedirs(os.path.dirname(os.path.abspath(SECRETS_PATH)), exist_ok=True)
                temp_secrets = f"{SECRETS_PATH}.tmp"
                with open(temp_secrets, "w") as f:
                    f.write(": RSA privkey.pem\n")
                os.chmod(temp_secrets, 0o600)
                os.replace(temp_secrets, SECRETS_PATH)
                subprocess.run(["ipsec", "rereadsecrets"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT username, password, max_traffic_gb, used_traffic_bytes, expire_date, is_active FROM users")
            users = cursor.fetchall()
            conn.close()

            now = datetime.datetime.now()
            active_lines = [": RSA privkey.pem"]

            for u in users:
                is_active = u["is_active"] if u["is_active"] is not None else 1
                if u["expire_date"]:
                    try:
                        exp_dt = datetime.datetime.strptime(u["expire_date"], "%Y-%m-%d %H:%M:%S")
                        if now > exp_dt:
                            is_active = 0
                    except Exception:
                        pass
                if u["max_traffic_gb"] and u["max_traffic_gb"] > 0:
                    max_bytes = u["max_traffic_gb"] * 1024 * 1024 * 1024
                    if (u["used_traffic_bytes"] or 0) >= max_bytes:
                        is_active = 0

                if is_active == 1:
                    pwd = str(u["password"]).replace('\\', '\\\\').replace('"', '\\"')
                    uname = str(u["username"]).replace('\\', '\\\\').replace('"', '\\"')
                    active_lines.append(f'{uname} : EAP "{pwd}"')

            os.makedirs(os.path.dirname(os.path.abspath(SECRETS_PATH)), exist_ok=True)
            temp_secrets = f"{SECRETS_PATH}.tmp"
            with open(temp_secrets, "w") as f:
                f.write("\n".join(active_lines) + "\n")
            os.chmod(temp_secrets, 0o600)
            os.replace(temp_secrets, SECRETS_PATH)

            subprocess.run(["ipsec", "rereadsecrets"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error syncing ipsec.secrets: {e}", file=sys.stderr)

user_live_speeds = {}
user_speed_lock = threading.Lock()
sa_live_speeds = {}
sa_speed_lock = threading.Lock()

def update_sa_live_speed(sa_id, total_in, total_out):
    now_t = time.time()
    with sa_speed_lock:
        prev = sa_live_speeds.get(sa_id)
        if prev:
            dt = now_t - prev['last_time']
            if dt < 0.8:
                return
            delta_in = max(0, total_in - prev['last_in'])
            delta_out = max(0, total_out - prev['last_out'])
            up_rate = delta_in / dt
            down_rate = delta_out / dt
            sa_live_speeds[sa_id] = {
                'speed_down': format_speed(down_rate),
                'speed_up': format_speed(up_rate),
                'down_rate': down_rate,
                'up_rate': up_rate,
                'last_in': total_in,
                'last_out': total_out,
                'last_time': now_t
            }
        else:
            sa_live_speeds[sa_id] = {
                'speed_down': '0 B/s',
                'speed_up': '0 B/s',
                'down_rate': 0,
                'up_rate': 0,
                'last_in': total_in,
                'last_out': total_out,
                'last_time': now_t
            }

def update_user_live_speed(username, total_in, total_out):
    now_t = time.time()
    with user_speed_lock:
        prev = user_live_speeds.get(username)
        if prev:
            dt = now_t - prev['last_time']
            if dt < 0.8:
                return
            delta_in = max(0, total_in - prev['last_in'])
            delta_out = max(0, total_out - prev['last_out'])
            up_rate = delta_in / dt
            down_rate = delta_out / dt
            user_live_speeds[username] = {
                'net_rx': format_speed(down_rate),
                'net_tx': format_speed(up_rate),
                'speed_down': format_speed(down_rate),
                'speed_up': format_speed(up_rate),
                'down_rate': down_rate,
                'up_rate': up_rate,
                'last_in': total_in,
                'last_out': total_out,
                'last_time': now_t
            }
        else:
            user_live_speeds[username] = {
                'net_rx': '0 B/s',
                'net_tx': '0 B/s',
                'speed_down': '0 B/s',
                'speed_up': '0 B/s',
                'down_rate': 0,
                'up_rate': 0,
                'last_in': total_in,
                'last_out': total_out,
                'last_time': now_t
            }

cached_online_users = {}
cached_online_time = 0
online_cache_lock = threading.Lock()

def invalidate_online_cache():
    global cached_online_time, cached_online_users
    with online_cache_lock:
        cached_online_time = 0
        cached_online_users = {}

def fetch_online_users_raw():
    online = {}
    try:
        db_users = get_db_usernames()
        if not db_users:
            return online

        db_users_set = set(db_users)
        db_users_lower = {u.lower(): u for u in db_users}

        res = subprocess.run(["ipsec", "statusall"], capture_output=True, text=True, check=False)
        output = res.stdout or ""

        lines = output.splitlines()
        sa_blocks = {}
        current_sa_id = None

        for line in lines:

            ike_match = re.search(r'(?:^|\s)[\w.-]*\[(\d+)\]:\s*(.*)$', line)
            if ike_match:
                sa_id = ike_match.group(1)
                current_sa_id = sa_id
                if current_sa_id not in sa_blocks:
                    sa_blocks[current_sa_id] = []
                sa_blocks[current_sa_id].append(line)
                continue

            child_match = re.search(r'(?:^|\s)[\w.-]*\{(\d+)\}:\s*(.*)$', line)
            if child_match:
                if current_sa_id is not None:
                    sa_blocks[current_sa_id].append(line)
                continue

            if current_sa_id is not None and (line.startswith(' ') or line.startswith('\t')):
                sa_blocks[current_sa_id].append(line)
            else:
                if line.strip() and not line.startswith(' '):
                    current_sa_id = None

        for sa_id, block_lines in sa_blocks.items():
            block_text = "\n".join(block_lines)

            if not re.search(r'ESTABLISHED', block_text, re.IGNORECASE):
                continue

            candidates = []

            eap_matches = re.findall(r'(?:Remote\s+)?EAP\s+identity(?:\s*\'%any\'\s*->)?\s*[:\s]\s*[\'\"]?([^\'\s\n\r,\]]+)', block_text, re.IGNORECASE)
            for m in eap_matches:
                candidates.append(m.strip("'\" \t"))

            rem_matches = re.findall(r'Remote\s+identity\s*[:\s]\s*[\'\"]?([^\'\s\n\r,\]]+)', block_text, re.IGNORECASE)
            for m in rem_matches:
                candidates.append(m.strip("'\" \t"))

            client_ip = None
            established_str = ""
            for bline in block_lines:
                if 'ESTABLISHED' in bline:
                    est_m = re.search(r'ESTABLISHED\s+([^,]+)', bline, re.IGNORECASE)
                    if est_m:
                        established_str = est_m.group(1).strip()
                    est_rem = re.search(r'\.\.\.[^\[\n\r]*\[([^\]]+)\]', bline)
                    if est_rem:
                        raw_id = est_rem.group(1).strip()
                        if ':' in raw_id and not raw_id.startswith('::'):
                            parts = raw_id.split(':')
                            candidates.append(parts[0].strip("'\" \t"))
                        candidates.append(raw_id.strip("'\" \t"))
                    ip_m = re.search(r'\.\.\.([0-9a-fA-F:.]+?)(?::\d+)?(?:\s*\[|\s*$)', bline)
                    if ip_m:
                        raw_ip = ip_m.group(1).strip()
                        if not raw_ip.startswith('%') and raw_ip != '0.0.0.0':
                            client_ip = raw_ip

            matched_user = None
            for cand in candidates:
                cand_clean = cand
                if '\\' in cand_clean:
                    cand_clean = cand_clean.split('\\')[-1]
                if '/' in cand_clean:
                    cand_clean = cand_clean.split('/')[-1]
                if '@' in cand_clean and cand_clean not in db_users_set:
                    cand_clean = cand_clean.split('@')[0]

                if cand in db_users_set:
                    matched_user = cand
                    break
                elif cand_clean in db_users_set:
                    matched_user = cand_clean
                    break
                elif cand.lower() in db_users_lower:
                    matched_user = db_users_lower[cand.lower()]
                    break
                elif cand_clean.lower() in db_users_lower:
                    matched_user = db_users_lower[cand_clean.lower()]
                    break

            if not matched_user:
                continue

            # Parse individual CHILD_SAs within this IKE_SA block to uniquely track traffic by SPI
            child_blocks = {}
            current_child_id = None
            for bline in block_lines:
                ch_m = re.search(r'(?:^|\s)[\w.-]*\{(\d+)\}:\s*(.*)$', bline)
                if ch_m:
                    current_child_id = ch_m.group(1)
                    if current_child_id not in child_blocks:
                        child_blocks[current_child_id] = []
                    child_blocks[current_child_id].append(bline)
                elif current_child_id is not None and (bline.startswith(' ') or bline.startswith('\t')):
                    child_blocks[current_child_id].append(bline)

            child_sas = {}
            bytes_in = 0
            bytes_out = 0

            if child_blocks:
                for ch_id, ch_lines in child_blocks.items():
                    ch_text = "\n".join(ch_lines)
                    c_in = 0
                    c_out = 0
                    for cline in ch_lines:
                        bm = re.search(r'(\d+)\s+bytes_i.*?(\d+)\s+bytes_o', cline)
                        if bm:
                            c_in += int(bm.group(1))
                            c_out += int(bm.group(2))

                    # Extract SPIs if present: e.g. "ESP in UDP SPIs: c3d4e5f6_i c7d8e9f0_o"
                    esp_spis = re.findall(r'\b([0-9a-fA-F]{4,16}_[io])\b', ch_text)
                    if len(esp_spis) >= 2:
                        c_key = f"spi_{esp_spis[0]}--{esp_spis[1]}"
                    elif len(esp_spis) == 1:
                        c_key = f"spi_{esp_spis[0]}"
                    else:
                        spi_generic = re.search(r'SPIs:\s*([0-9a-fA-F_]+)\s+([0-9a-fA-F_]+)', ch_text)
                        if spi_generic:
                            c_key = f"spi_{spi_generic.group(1)}--{spi_generic.group(2)}"
                        else:
                            c_key = f"sa_{sa_id}_ch_{ch_id}"

                    child_sas[c_key] = {
                        "child_key": c_key,
                        "child_id": ch_id,
                        "bytes_in": c_in,
                        "bytes_out": c_out,
                        "bytes_total": c_in + c_out
                    }
                    bytes_in += c_in
                    bytes_out += c_out
            else:
                # Fallback if no child lines found but bytes exist in block_lines
                for bline in block_lines:
                    bm = re.search(r'(\d+)\s+bytes_i.*?(\d+)\s+bytes_o', bline)
                    if bm:
                        bytes_in += int(bm.group(1))
                        bytes_out += int(bm.group(2))
                c_key = f"sa_{sa_id}_raw"
                child_sas[c_key] = {
                    "child_key": c_key,
                    "child_id": "0",
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "bytes_total": bytes_in + bytes_out
                }

            vip = None
            for bline in block_lines:
                vip_m = re.search(r'===\s*(10\.\d+\.\d+\.\d+|(?:\d{1,3}\.){3}\d{1,3})', bline)
                if vip_m:
                    vip = vip_m.group(1)
                    break
                vip_fallback = re.search(r'(?!0\.0\.0\.0)(\b10\.\d+\.\d+\.\d+\b)', bline)
                if vip_fallback:
                    vip = vip_fallback.group(1)
                    break

            if matched_user not in online:
                online[matched_user] = {
                    "username": matched_user,
                    "sa_ids": [sa_id],
                    "vips": [vip] if vip else [],
                    "client_ip": client_ip or "",
                    "established": established_str,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "bytes_total": bytes_in + bytes_out,
                    "device_count": 1,
                    "sas": {
                        sa_id: {
                            "sa_id": sa_id,
                            "bytes_in": bytes_in,
                            "bytes_out": bytes_out,
                            "bytes_total": bytes_in + bytes_out,
                            "vip": vip,
                            "client_ip": client_ip or "",
                            "established": established_str,
                            "child_sas": child_sas
                        }
                    }
                }
            else:
                if sa_id not in online[matched_user]["sa_ids"]:
                    online[matched_user]["sa_ids"].append(sa_id)
                if vip and vip not in online[matched_user]["vips"]:
                    online[matched_user]["vips"].append(vip)
                if client_ip and not online[matched_user]["client_ip"]:
                    online[matched_user]["client_ip"] = client_ip
                online[matched_user]["bytes_in"] += bytes_in
                online[matched_user]["bytes_out"] += bytes_out
                online[matched_user]["bytes_total"] += (bytes_in + bytes_out)
                online[matched_user]["sas"][sa_id] = {
                    "sa_id": sa_id,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "bytes_total": bytes_in + bytes_out,
                    "vip": vip,
                    "client_ip": client_ip or "",
                    "established": established_str,
                    "child_sas": child_sas
                }
                online[matched_user]["device_count"] = len(online[matched_user]["sa_ids"])

        for uname, udata in online.items():
            update_user_live_speed(uname, udata.get("bytes_in", 0), udata.get("bytes_out", 0))
            for sa_id, s_info in udata.get("sas", {}).items():
                update_sa_live_speed(sa_id, s_info.get("bytes_in", 0), s_info.get("bytes_out", 0))

    except Exception as e:
        print(f"[!] Error parsing ipsec statusall: {e}", file=sys.stderr)

    return online

def get_online_users(ttl=1.5):
    global cached_online_users, cached_online_time
    now = time.time()
    with online_cache_lock:
        if (now - cached_online_time) < ttl and cached_online_users:
            return cached_online_users

    fresh_online = fetch_online_users_raw()
    with online_cache_lock:
        cached_online_users = fresh_online
        cached_online_time = now
    return fresh_online

last_seen_child_bytes = {}
daemon_warmup_done = False

def accounting_daemon():
    global last_seen_child_bytes, daemon_warmup_done
    while not shutdown_event.is_set():
        try:
            vpn_enabled = (get_system_config("vpn_enabled", "1") == "1")
            online = fetch_online_users_raw()
            if not vpn_enabled and online:
                disconnect_all_sas()
                online = {}

            now = datetime.datetime.now()
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")

            conn = get_db()
            cursor = conn.cursor()

            active_child_keys = set()
            user_deltas = {}

            if not daemon_warmup_done:
                # Baseline warmup: Initialize existing active child SAs without charging delta
                for username, data in online.items():
                    for sa_id, sa_data in data.get("sas", {}).items():
                        for child_key, c_data in sa_data.get("child_sas", {}).items():
                            active_child_keys.add(child_key)
                            last_seen_child_bytes[child_key] = c_data.get("bytes_total", 0)
                daemon_warmup_done = True
            else:
                for username, data in online.items():
                    for sa_id, sa_data in data.get("sas", {}).items():
                        for child_key, c_data in sa_data.get("child_sas", {}).items():
                            active_child_keys.add(child_key)
                            curr_bytes = c_data.get("bytes_total", 0)
                            prev_bytes = last_seen_child_bytes.get(child_key, 0)

                            delta = 0
                            if curr_bytes >= prev_bytes:
                                delta = curr_bytes - prev_bytes
                            else:
                                delta = curr_bytes

                            last_seen_child_bytes[child_key] = curr_bytes
                            if delta > 0:
                                user_deltas[username] = user_deltas.get(username, 0) + delta

            for username, data in online.items():
                client_ip = data.get("client_ip") or ""
                if client_ip:
                    cursor.execute("""
                        UPDATE users
                        SET last_online_at = ?, last_ip = ?
                        WHERE username = ?
                    """, (now_str, client_ip, username))
                else:
                    cursor.execute("""
                        UPDATE users
                        SET last_online_at = ?
                        WHERE username = ?
                    """, (now_str, username))

            for username, delta in user_deltas.items():
                cursor.execute("""
                    UPDATE users
                    SET used_traffic_bytes = COALESCE(used_traffic_bytes, 0) + ?
                    WHERE username = ?
                """, (delta, username))

            if daemon_warmup_done:
                for child_key in list(last_seen_child_bytes.keys()):
                    if child_key not in active_child_keys:
                        del last_seen_child_bytes[child_key]

            conn.commit()

            cursor.execute("SELECT id, username, max_traffic_gb, used_traffic_bytes, expire_date, is_active, max_devices FROM users")
            users = cursor.fetchall()

            should_resync = False
            for u in users:
                is_active = u["is_active"] if u["is_active"] is not None else 1
                needs_disable = False

                if u["expire_date"]:
                    try:
                        exp_dt = datetime.datetime.strptime(u["expire_date"], "%Y-%m-%d %H:%M:%S")
                        if now > exp_dt:
                            needs_disable = True
                    except Exception:
                        pass

                if u["max_traffic_gb"] and u["max_traffic_gb"] > 0:
                    max_bytes = u["max_traffic_gb"] * 1024 * 1024 * 1024
                    if (u["used_traffic_bytes"] or 0) >= max_bytes:
                        needs_disable = True

                if needs_disable and is_active == 1:
                    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (u["id"],))
                    should_resync = True
                    disconnect_user_sas(u["username"], online)
                elif is_active == 1 and u["username"] in online:

                    user_max_dev = u["max_devices"] if u["max_devices"] is not None and u["max_devices"] > 0 else 10
                    try:
                        user_max_dev = max(1, min(10, int(user_max_dev)))
                    except (ValueError, TypeError):
                        user_max_dev = 10
                    disconnect_excess_sas(u["username"], user_max_dev, online)

            conn.commit()
            conn.close()

            if should_resync:
                sync_ipsec_secrets()

        except Exception as e:
            print(f"[!] Daemon exception: {e}", file=sys.stderr)

        if shutdown_event.wait(2):
            break

daemon_lock_handle = None

def start_accounting_daemon():
    global daemon_lock_handle
    lock_file = "/tmp/ike_accounting_daemon.lock"
    try:
        daemon_lock_handle = open(lock_file, "w")
        fcntl.flock(daemon_lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, BlockingIOError, PermissionError):

        return

    t = threading.Thread(target=accounting_daemon, daemon=True)
    t.start()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
        admin_id = session.get("admin_id")
        admin_user = session.get("admin_user")
        auth_hash = session.get("auth_hash")
        logged_in = session.get("logged_in")

        if not logged_in or not admin_user or not auth_hash:
            session.clear()
            if is_ajax:
                return jsonify({"success": False, "error": "Unauthorized or session expired", "redirect": url_for("login")}), 401
            return redirect(url_for("login"))

        try:
            timeout_mins = int(get_system_config("admin_session_timeout", "4320"))
            timeout_mins = max(1, min(43200, timeout_mins))
        except (ValueError, TypeError):
            timeout_mins = 4320

        now = int(time.time())
        last_active = session.get("last_active")
        if last_active and (now - int(last_active)) > (timeout_mins * 60):
            session.clear()
            if is_ajax:
                return jsonify({"success": False, "error": "Session expired due to inactivity", "redirect": url_for("login")}), 401
            flash("Your session has expired. Please sign in again.", "warning")
            return redirect(url_for("login"))

        try:
            conn = get_db()
            cursor = conn.cursor()
            if admin_id:
                cursor.execute("SELECT id, username, password_hash FROM admin WHERE id = ?", (admin_id,))
            else:
                cursor.execute("SELECT id, username, password_hash FROM admin WHERE username = ?", (admin_user,))
            admin = cursor.fetchone()
            conn.close()

            if not admin or admin["username"] != admin_user or admin["password_hash"] != auth_hash:
                session.clear()
                if is_ajax:
                    return jsonify({"success": False, "error": "Admin credentials were changed. Please log in again.", "redirect": url_for("login")}), 401
                flash("Admin credentials were changed. Please log in again.", "warning")
                return redirect(url_for("login"))
        except Exception:
            session.clear()
            if is_ajax:
                return jsonify({"success": False, "error": "Session validation error", "redirect": url_for("login")}), 401
            return redirect(url_for("login"))

        session["last_active"] = now
        return f(*args, **kwargs)
    return decorated_function

def clear_sub_session():
    session.pop("sub_logged_in", None)
    session.pop("sub_user_id", None)
    session.pop("sub_username", None)
    session.pop("sub_password", None)
    session.pop("sub_login_time", None)

def sub_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.accept_mimetypes.best == "application/json"
        sub_id = session.get("sub_user_id")
        sub_user = session.get("sub_username")
        sub_pass = session.get("sub_password")
        sub_logged = session.get("sub_logged_in")
        sub_login_time = session.get("sub_login_time")

        if not sub_logged or not sub_id or not sub_user or not sub_pass:
            clear_sub_session()
            if is_ajax:
                return jsonify({"success": False, "error": "Unauthorized or session expired", "redirect": url_for("sub_portal")}), 401
            return redirect(url_for("sub_portal"))

        now = int(time.time())
        if sub_login_time and (now - int(sub_login_time)) > SUB_SESSION_LIFETIME:
            clear_sub_session()
            if is_ajax:
                return jsonify({"success": False, "error": "Your session has expired (3-day limit). Please sign in again.", "redirect": url_for("sub_portal", u=sub_user)}), 401
            flash("Your session has expired (3-day limit). Please sign in again.", "warning")
            return redirect(url_for("sub_portal", u=sub_user))

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password FROM users WHERE id = ?", (sub_id,))
            user_db = cursor.fetchone()
            conn.close()

            if not user_db or user_db["username"] != sub_user or user_db["password"] != sub_pass:
                clear_sub_session()
                if is_ajax:
                    return jsonify({"success": False, "error": "Account credentials were changed. Please log in again.", "redirect": url_for("sub_portal", u=sub_user)}), 401
                flash("Account credentials were changed. Please log in again.", "warning")
                return redirect(url_for("sub_portal", u=sub_user))
        except Exception:
            clear_sub_session()
            if is_ajax:
                return jsonify({"success": False, "error": "Session validation error", "redirect": url_for("sub_portal")}), 401
            return redirect(url_for("sub_portal"))

        return f(*args, **kwargs)
    return decorated_function

def format_bytes_val(bytes_val):
    if bytes_val is None:
        return "0 B"
    try:
        b = float(bytes_val)
    except Exception:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024.0 or unit == 'TB':
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} GB"

def format_last_online_str(last_seen_str):
    if not last_seen_str:
        return None
    try:
        dt = datetime.datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        diff = (now - dt).total_seconds()
        if diff < 60:
            return "Just now"
        elif diff < 3600:
            mins = int(diff // 60)
            return f"{mins}m ago"
        elif diff < 86400:
            hours = int(diff // 3600)
            return f"{hours}h ago"
        else:
            days = int(diff // 86400)
            return f"{days}d ago"
    except Exception:
        return last_seen_str[:16]

def calc_remaining_days(expire_date_str):
    if not expire_date_str:
        return ""
    try:
        exp_dt = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d %H:%M:%S")
        diff = exp_dt - datetime.datetime.now()
        if diff.total_seconds() <= 0:
            return 0
        return max(0, diff.days + (1 if diff.seconds > 0 else 0))
    except Exception:
        return ""

@app.template_filter('format_bytes')
def format_bytes(bytes_val):
    return format_bytes_val(bytes_val)

@app.template_filter('traffic_percent')
def traffic_percent(used_bytes, max_gb):
    try:
        if not max_gb or float(max_gb) <= 0:
            return 0
        if not used_bytes or float(used_bytes) <= 0:
            return 0
        max_bytes = float(max_gb) * 1024 * 1024 * 1024
        pct = (float(used_bytes) / max_bytes) * 100
        return min(round(pct, 1), 100)
    except Exception:
        return 0

@app.template_filter('time_remaining')
def time_remaining(expire_date_str):
    if not expire_date_str:
        return "Unlimited"
    try:
        exp_dt = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        if now >= exp_dt:
            return "Expired"
        diff = exp_dt - now
        days = diff.days
        hours = diff.seconds // 3600
        if days > 0:
            return f"{days}d {hours}h left"
        return f"{hours}h left"
    except Exception:
        return "Unlimited"

@app.template_filter('format_last_seen')
def format_last_seen(last_seen_str):
    return format_last_online_str(last_seen_str)

@app.template_filter('get_remaining_days')
def get_remaining_days_filter(expire_date_str):
    return calc_remaining_days(expire_date_str)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("1/second; 10/minute")
def login():
    if session.get("logged_in") and session.get("admin_user"):
        admin_id = session.get("admin_id")
        admin_user = session.get("admin_user")
        auth_hash = session.get("auth_hash")

        valid = False
        if auth_hash:
            try:
                timeout_mins = int(get_system_config("admin_session_timeout", "4320"))
                timeout_mins = max(1, min(43200, timeout_mins))
            except (ValueError, TypeError):
                timeout_mins = 4320
            now = int(time.time())
            last_active = session.get("last_active")
            if not last_active or (now - int(last_active)) <= (timeout_mins * 60):
                try:
                    conn = get_db()
                    cursor = conn.cursor()
                    if admin_id:
                        cursor.execute("SELECT id, username, password_hash FROM admin WHERE id = ?", (admin_id,))
                    else:
                        cursor.execute("SELECT id, username, password_hash FROM admin WHERE username = ?", (admin_user,))
                    admin = cursor.fetchone()
                    conn.close()
                    if admin and admin["username"] == admin_user and admin["password_hash"] == auth_hash:
                        valid = True
                except Exception:
                    pass

        if valid:
            return redirect(url_for("dashboard"))
        else:
            session.clear()

    if request.method == "POST":
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.accept_mimetypes.best == "application/json"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admin WHERE username = ?", (username,))
            admin = cursor.fetchone()
            conn.close()

            if admin and check_password_hash(admin["password_hash"], password):
                session.permanent = True
                session["logged_in"] = True
                session["admin_id"] = admin["id"]
                session["admin_user"] = admin["username"]
                session["auth_hash"] = admin["password_hash"]
                session["last_active"] = int(time.time())
                session["login_time"] = int(time.time())
                if is_ajax:
                    return jsonify({"success": True, "redirect": url_for("dashboard")})
                return redirect(url_for("dashboard"))
            else:
                if is_ajax:
                    return jsonify({"success": False, "error": "Invalid username or password!"}), 401
                flash("Invalid username or password!", "danger")
        except Exception as e:
            if is_ajax:
                return jsonify({"success": False, "error": f"Login error: {e}"}), 500
            flash(f"Login error: {e}", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def format_user_payload(u, online):
    uname = u.get("username") if isinstance(u, dict) else u["username"]
    is_act = u.get("is_active") if isinstance(u, dict) else u["is_active"]
    is_act = 1 if is_act is None else int(is_act)

    raw_max_dev = u.get("max_devices") if isinstance(u, dict) else u["max_devices"]
    try:
        max_dev = int(raw_max_dev) if raw_max_dev is not None else 10
        max_dev = max(1, min(10, max_dev))
    except (ValueError, TypeError):
        max_dev = 10

    online_info = online.get(uname, {}) if is_act == 1 else {}
    is_on = (is_act == 1) and (uname in online)

    if is_on:
        raw_dev_cnt = online_info.get("device_count", 1)
        dev_cnt = max(1, min(raw_dev_cnt, max_dev))
    else:
        dev_cnt = 0

    last_seen_raw = u.get("last_online_at") if isinstance(u, dict) else u["last_online_at"]
    last_seen_formatted = format_last_online_str(last_seen_raw)
    created_at_raw = u.get("created_at") if isinstance(u, dict) else (u["created_at"] if "created_at" in u.keys() else "")
    used_bytes = (u.get("used_traffic_bytes") if isinstance(u, dict) else u["used_traffic_bytes"]) or 0
    max_gb = (u.get("max_traffic_gb") if isinstance(u, dict) else u["max_traffic_gb"]) or 0
    exp_date = (u.get("expire_date") if isinstance(u, dict) else u["expire_date"]) or ""
    note = (u.get("note") if isinstance(u, dict) else u["note"]) or ""
    u_id = u.get("id") if isinstance(u, dict) else u["id"]
    u_pwd = u.get("password") if isinstance(u, dict) else u["password"]

    saved_last_ip = u.get("last_ip") if isinstance(u, dict) else (u["last_ip"] if "last_ip" in u.keys() else "")
    last_ip_val = saved_last_ip or ""
    if is_on:
        live_client_ip = online_info.get("client_ip")
        if live_client_ip:
            last_ip_val = live_client_ip

    live_net = None
    if is_on:
        with user_speed_lock:
            spd = user_live_speeds.get(uname, {})
            down_spd = spd.get('speed_down', spd.get('net_rx', '0 B/s'))
            up_spd = spd.get('speed_up', spd.get('net_tx', '0 B/s'))

        bytes_in = online_info.get("bytes_in", 0)
        bytes_out = online_info.get("bytes_out", 0)

        devices = []
        sas_dict = online_info.get("sas", {})
        if sas_dict:
            for sa_id, sa_item in sas_dict.items():
                with sa_speed_lock:
                    s_spd = sa_live_speeds.get(sa_id, {})
                    d_down = s_spd.get('speed_down', '0 B/s')
                    d_up = s_spd.get('speed_up', '0 B/s')

                d_in = sa_item.get("bytes_in", 0)
                d_out = sa_item.get("bytes_out", 0)
                devices.append({
                    "sa_id": sa_id,
                    "client_ip": sa_item.get("client_ip", "") or online_info.get("client_ip", ""),
                    "vip": sa_item.get("vip", ""),
                    "established": sa_item.get("established", "") or "Active",
                    "speed_down": d_down,
                    "speed_up": d_up,
                    "bytes_down": format_bytes_val(d_out),
                    "bytes_up": format_bytes_val(d_in),
                    "bytes_total": format_bytes_val(d_in + d_out)
                })

        live_net = {
            "speed_down": down_spd,
            "speed_up": up_spd,
            "net_rx": down_spd,
            "net_tx": up_spd,
            "bytes_down": format_bytes_val(bytes_out),
            "bytes_up": format_bytes_val(bytes_in),
            "bytes_in": format_bytes_val(bytes_in),
            "bytes_out": format_bytes_val(bytes_out),
            "bytes_total": format_bytes_val(bytes_in + bytes_out),
            "vip": (online_info.get("vips") or [""])[0],
            "client_ip": online_info.get("client_ip", ""),
            "established": online_info.get("established", ""),
            "devices": devices
        }

    return {
        "id": u_id,
        "username": uname,
        "password": u_pwd,
        "is_online": is_on,
        "device_count": dev_cnt,
        "last_online_at": last_seen_raw or "",
        "last_seen_formatted": last_seen_formatted or "",
        "last_ip": last_ip_val,
        "created_at": created_at_raw or "",
        "used_traffic_bytes": used_bytes,
        "used_traffic_formatted": format_bytes_val(used_bytes),
        "max_traffic_gb": max_gb,
        "traffic_percent": traffic_percent(used_bytes, max_gb),
        "expire_date": exp_date,
        "remaining_days": calc_remaining_days(exp_date),
        "time_remaining": time_remaining(exp_date),
        "is_active": is_act,
        "max_devices": max_dev,
        "note": note,
        "live_net": live_net
    }

@app.route("/api/user/info/<int:user_id>", methods=["GET"])
@login_required
def get_user_info_api(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404

        online = get_online_users()
        user_data = format_user_payload(dict(row), online)
        return jsonify({"success": True, "user": user_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/sub", methods=["GET"])
@limiter.limit("1/second; 60/minute")
def sub_portal():
    if get_system_config("sub_portal_enabled", "1") != "1":
        abort(404)

    sub_id = session.get("sub_user_id")
    sub_user = session.get("sub_username")
    sub_pass = session.get("sub_password")
    sub_logged = session.get("sub_logged_in")
    sub_login_time = session.get("sub_login_time")
    now = int(time.time())

    is_valid = False
    user_data = None

    if sub_logged and sub_id and sub_user and sub_pass:
        if sub_login_time and (now - int(sub_login_time)) <= SUB_SESSION_LIFETIME:
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (sub_id,))
                row = cursor.fetchone()
                conn.close()
                if row and row["username"] == sub_user and row["password"] == sub_pass:
                    is_valid = True
                    online = get_online_users()
                    user_data = format_user_payload(dict(row), online)
            except Exception:
                is_valid = False

    if not is_valid:
        clear_sub_session()
        username_arg = (request.args.get("u") or request.args.get("username") or request.args.get("user") or "").strip()
        return render_template(
            "sub.html",
            is_logged_in=False,
            prefilled_username=username_arg,
            server_domain=get_system_config("server_domain", SERVER_DOMAIN)
        )

    return render_template(
        "sub.html",
        is_logged_in=True,
        user=user_data,
        server_domain=get_system_config("server_domain", SERVER_DOMAIN)
    )

@app.route("/sub/login", methods=["POST"])
@limiter.limit("1/second; 10/minute")
def sub_login():
    if get_system_config("sub_portal_enabled", "1") != "1":
        abort(404)

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.accept_mimetypes.best == "application/json"
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        msg = "Username and password are required!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("sub_portal", u=username))

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user["password"] == password:
            session["sub_logged_in"] = True
            session["sub_user_id"] = user["id"]
            session["sub_username"] = user["username"]
            session["sub_password"] = user["password"]
            session["sub_login_time"] = int(time.time())

            if is_ajax:
                return jsonify({"success": True, "redirect": url_for("sub_portal")})
            return redirect(url_for("sub_portal"))
        else:
            msg = "Invalid username or password!"
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 401
            flash(msg, "danger")
            return redirect(url_for("sub_portal", u=username))
    except Exception as e:
        msg = f"Login error: {e}"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 500
        flash(msg, "danger")
        return redirect(url_for("sub_portal", u=username))

@app.route("/sub/logout", methods=["GET", "POST"])
@limiter.limit("1/second")
def sub_logout():
    if get_system_config("sub_portal_enabled", "1") != "1":
        abort(404)

    username = session.get("sub_username", "")
    clear_sub_session()
    if username:
        return redirect(url_for("sub_portal", u=username))
    return redirect(url_for("sub_portal"))

@app.route("/sub/change-password", methods=["POST"])
@sub_login_required
@limiter.limit("1/second; 10/minute")
def sub_change_password():
    if get_system_config("sub_portal_enabled", "1") != "1":
        abort(404)

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or request.accept_mimetypes.best == "application/json"
    sub_id = session.get("sub_user_id")
    sub_user = session.get("sub_username")

    new_pass = request.form.get("new_password", "").strip()
    confirm_pass = request.form.get("confirm_password", "").strip()

    if not new_pass or not confirm_pass:
        msg = "New password and confirmation are required!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("sub_portal"))

    if new_pass != confirm_pass:
        msg = "New passwords do not match!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("sub_portal"))

    if len(new_pass) < 6:
        msg = "Password must be at least 6 characters!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("sub_portal"))

    if len(new_pass) > 24:
        msg = "Password length cannot exceed 24 characters!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("sub_portal"))

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_pass, sub_id))
        conn.commit()
        conn.close()

        sync_ipsec_secrets()
        disconnect_user_sas(sub_user)
        clear_sub_session()

        msg = "Password changed successfully! Please sign in with your new password."
        redirect_target = url_for("sub_portal", u=sub_user)

        if is_ajax:
            return jsonify({
                "success": True,
                "message": msg,
                "redirect": redirect_target
            })
        flash(msg, "success")
        return redirect(redirect_target)
    except Exception as e:
        msg = f"Error changing password: {e}"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 500
        flash(msg, "danger")
        return redirect(url_for("sub_portal"))

@app.route("/")
@login_required
def dashboard():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM users")
        total_row = cursor.fetchone()
        total_users = total_row["total"] if total_row else 0

        cursor.execute("SELECT COUNT(*) as active FROM users WHERE is_active = 1")
        active_row = cursor.fetchone()
        active_users = active_row["active"] if active_row else 0

        cursor.execute("SELECT COALESCE(SUM(used_traffic_bytes), 0) as total_traf FROM users")
        traf_row = cursor.fetchone()
        total_traffic_bytes = traf_row["total_traf"] if traf_row else 0

        cursor.execute("SELECT * FROM users ORDER BY id DESC LIMIT 10")
        initial_users = cursor.fetchall()
        conn.close()
    except Exception as e:
        total_users = 0
        active_users = 0
        total_traffic_bytes = 0
        initial_users = []
        print(f"[!] Error fetching dashboard data: {e}", file=sys.stderr)

    online = get_online_users()

    online_count = 0
    if online:
        try:
            conn2 = get_db()
            cur2 = conn2.cursor()
            placeholders = ",".join("?" for _ in online.keys())
            cur2.execute(f"SELECT COUNT(*) as cnt FROM users WHERE is_active = 1 AND username IN ({placeholders})", list(online.keys()))
            cnt_row = cur2.fetchone()
            online_count = cnt_row["cnt"] if cnt_row else 0
            conn2.close()
        except Exception:
            online_count = len(online)

    sys_metrics = get_system_metrics()
    users_formatted = [format_user_payload(dict(u), online) for u in initial_users]

    return render_template("dashboard.html",
                           users=initial_users,
                           users_json=json.dumps(users_formatted),
                           online=online,
                           total_users=total_users,
                           active_users=active_users,
                           online_count=online_count,
                           total_traffic_bytes=total_traffic_bytes,
                           sys=sys_metrics,
                           server_domain=SERVER_DOMAIN)

@app.route("/api/users", methods=["GET"])
@login_required
def get_users_api():
    try:
        try:
            page = int(request.args.get("page", 1))
            if page < 1:
                page = 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = int(request.args.get("per_page", 10))
            if per_page not in [10, 30, 50, 100]:
                per_page = min(max(1, per_page), 100)
        except (ValueError, TypeError):
            per_page = 10

        sort_col = request.args.get("sort", "").strip().lower()
        sort_dir = request.args.get("dir", "").strip().lower()
        if sort_dir not in ["asc", "desc"]:
            sort_dir = "desc" if sort_col in ["traffic", "account_status", "live_status"] else "asc"

        q = request.args.get("q", "").strip()

        conn = get_db()
        cursor = conn.cursor()

        where_clauses = []
        where_params = []

        if q:
            where_clauses.append("(LOWER(username) LIKE ? OR LOWER(COALESCE(note, '')) LIKE ?)")
            where_params.extend([f"%{q.lower()}%", f"%{q.lower()}%"])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        cursor.execute(f"SELECT COUNT(*) as total FROM users {where_sql}", where_params)
        count_row = cursor.fetchone()
        total_items = count_row["total"] if count_row else 0

        total_pages = max(1, math.ceil(total_items / per_page)) if total_items > 0 else 1
        if page > total_pages:
            page = total_pages

        online = get_online_users()

        order_sql = "id DESC"
        sort_params = []

        if sort_col == "username":
            order_sql = f"LOWER(username) {sort_dir.upper()}"
        elif sort_col == "traffic":
            order_sql = f"used_traffic_bytes {sort_dir.upper()}, id DESC"
        elif sort_col == "expiration":
            if sort_dir == "asc":
                order_sql = "CASE WHEN expire_date IS NULL OR expire_date = '' THEN 1 ELSE 0 END ASC, expire_date ASC, id DESC"
            else:
                order_sql = "CASE WHEN expire_date IS NULL OR expire_date = '' THEN 1 ELSE 0 END DESC, expire_date DESC, id DESC"
        elif sort_col == "account_status":
            order_sql = f"is_active {sort_dir.upper()}, id DESC"
        elif sort_col == "live_status":
            online_unames = list(online.keys())
            if online_unames:
                placeholders = ",".join("?" for _ in online_unames)
                if sort_dir == "asc":
                    order_sql = f"CASE WHEN is_active = 1 AND username IN ({placeholders}) THEN 1 ELSE 0 END ASC, CASE WHEN last_online_at IS NULL OR last_online_at = '' THEN 1 ELSE 0 END ASC, last_online_at ASC, id DESC"
                else:
                    order_sql = f"CASE WHEN is_active = 1 AND username IN ({placeholders}) THEN 1 ELSE 0 END DESC, CASE WHEN last_online_at IS NULL OR last_online_at = '' THEN 1 ELSE 0 END ASC, last_online_at DESC, id DESC"
                sort_params = list(online_unames)
            else:
                if sort_dir == "asc":
                    order_sql = "CASE WHEN last_online_at IS NULL OR last_online_at = '' THEN 1 ELSE 0 END ASC, last_online_at ASC, id DESC"
                else:
                    order_sql = "CASE WHEN last_online_at IS NULL OR last_online_at = '' THEN 1 ELSE 0 END ASC, last_online_at DESC, id DESC"

        offset = (page - 1) * per_page
        query_sql = f"SELECT * FROM users {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?"
        full_params = where_params + sort_params + [per_page, offset]

        cursor.execute(query_sql, full_params)
        rows = cursor.fetchall()
        conn.close()

        users_formatted = [format_user_payload(dict(u), online) for u in rows]
        start_index = (page - 1) * per_page if total_items > 0 else 0
        end_index = min(start_index + per_page, total_items)

        return jsonify({
            "success": True,
            "users": users_formatted,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_items": total_items,
                "total_pages": total_pages,
                "start_index": start_index,
                "end_index": end_index
            }
        })
    except Exception as e:
        print(f"[!] Error in get_users_api: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/stream")
@login_required
def sse_stream():
    stream_admin_id = session.get("admin_id")
    stream_admin_user = session.get("admin_user")
    stream_auth_hash = session.get("auth_hash")

    def event_generator():
        while not shutdown_event.is_set():
            try:
                conn = get_db()
                cursor = conn.cursor()
                if stream_admin_id:
                    cursor.execute("SELECT id, username, password_hash FROM admin WHERE id = ?", (stream_admin_id,))
                else:
                    cursor.execute("SELECT id, username, password_hash FROM admin WHERE username = ?", (stream_admin_user,))
                admin = cursor.fetchone()
                if not admin or admin["username"] != stream_admin_user or admin["password_hash"] != stream_auth_hash:
                    conn.close()
                    break

                online = get_online_users()

                cursor.execute("SELECT * FROM users ORDER BY id DESC")
                all_users = cursor.fetchall()
                conn.close()

                total_users = len(all_users)
                active_users = sum(1 for u in all_users if (u["is_active"] or 0) == 1)
                total_traffic_bytes = sum((u["used_traffic_bytes"] or 0) for u in all_users)
                online_count = sum(1 for u in all_users if (u["is_active"] or 0) == 1 and u["username"] in online) if online else 0

                users_live = {
                    u["id"]: format_user_payload(dict(u), online)
                    for u in all_users
                }

                sys_metrics = get_system_metrics()

                payload = {
                    "stats": {
                        "total_users": total_users,
                        "active_users": active_users,
                        "online_count": online_count,
                        "total_traffic": format_bytes_val(total_traffic_bytes)
                    },
                    "sys": sys_metrics,
                    "vpn_enabled": (get_system_config("vpn_enabled", "1") == "1"),
                    "users_live": users_live
                }

                yield f"data: {json.dumps(payload)}\n\n"
            except GeneratorExit:
                break
            except Exception as e:
                print(f"[!] Error in SSE generator: {e}", file=sys.stderr)

            if shutdown_event.wait(2):
                break

    response = Response(stream_with_context(event_generator()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response

@app.route("/user/add", methods=["POST"])
@login_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    raw_traffic = request.form.get("max_traffic_gb", "").strip()
    max_traffic_gb = float(raw_traffic) if raw_traffic else 0.0

    raw_days = request.form.get("duration_days", "").strip()
    duration_days = int(raw_days) if raw_days else 0

    raw_devices = request.form.get("max_devices", "10").strip()
    try:
        max_devices = int(raw_devices) if raw_devices else 10
        max_devices = max(1, min(10, max_devices))
    except ValueError:
        max_devices = 10

    note = request.form.get("note", "").strip()

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"

    if not username or not password:
        if is_ajax:
            return jsonify({"success": False, "error": "Username and password are required!"}), 400
        flash("Username and password are required!", "danger")
        return redirect(url_for("dashboard"))

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            conn.close()
            if is_ajax:
                return jsonify({"success": False, "error": f"User '{username}' already exists!"}), 400
            flash(f"User '{username}' already exists!", "danger")
            return redirect(url_for("dashboard"))
    except Exception as e:
        pass

    expire_date = None
    if duration_days > 0:
        expire_date = (datetime.datetime.now() + datetime.timedelta(days=duration_days)).strftime("%Y-%m-%d %H:%M:%S")

    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password, max_traffic_gb, used_traffic_bytes, created_at, expire_date, is_active, note, last_online_at, max_devices)
            VALUES (?, ?, ?, 0, ?, ?, 1, ?, NULL, ?)
        """, (username, password, max_traffic_gb, created_at, expire_date, note, max_devices))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        sync_ipsec_secrets()

        traffic_display = f"{max_traffic_gb} GB" if max_traffic_gb > 0 else "Unlimited"
        expire_display = f"{duration_days} Days" if duration_days > 0 else "∞ Lifetime"

        if is_ajax:
            return jsonify({
                "success": True,
                "user_id": user_id,
                "username": username,
                "password": password,
                "server": SERVER_DOMAIN,
                "max_traffic": traffic_display,
                "max_traffic_gb": max_traffic_gb,
                "expire": expire_display,
                "expire_date": expire_date or "",
                "remaining_days": duration_days if duration_days > 0 else "",
                "max_devices": max_devices,
                "note": note
            })

        flash(f"User '{username}' added successfully!", "success")
    except sqlite3.IntegrityError:
        if is_ajax:
            return jsonify({"success": False, "error": f"User '{username}' already exists!"}), 400
        flash(f"User '{username}' already exists!", "danger")
    except Exception as e:
        if is_ajax:
            return jsonify({"success": False, "error": f"Error adding user: {e}"}), 500
        flash(f"Error adding user: {e}", "danger")

    return redirect(url_for("dashboard"))

@app.route("/user/edit/<int:user_id>", methods=["POST"])
@login_required
def edit_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"

    if not user:
        conn.close()
        if is_ajax:
            return jsonify({"success": False, "error": "User not found!"}), 404
        flash("User not found!", "danger")
        return redirect(url_for("dashboard"))

    change_pwd = request.form.get("change_password") == "yes"
    raw_pwd = request.form.get("password", "").strip()

    if change_pwd and raw_pwd:
        new_password = raw_pwd
        pwd_was_changed = True
    else:
        new_password = user["password"]
        pwd_was_changed = False

    raw_traffic = request.form.get("max_traffic_gb", "").strip()
    if raw_traffic == "":
        max_traffic_gb = 0.0
        traffic_display = "Unlimited"
    else:
        try:
            val = float(raw_traffic)
            max_traffic_gb = 0.0001 if val == 0 else val
            traffic_display = f"{val} GB" if val > 0 else "0 GB (Disabled)"
        except ValueError:
            max_traffic_gb = user["max_traffic_gb"]
            traffic_display = f"{user['max_traffic_gb']} GB" if user['max_traffic_gb'] > 0 else "Unlimited"

    raw_days = request.form.get("duration_days", "").strip()
    if raw_days == "":
        new_expire = None
        expire_display = "∞ Lifetime"
        time_rem = "Unlimited"
        rem_days = ""
    else:
        try:
            days_val = int(raw_days)
            if days_val == 0:
                new_expire = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
                expire_display = "Expired"
                time_rem = "Expired"
                rem_days = 0
            else:
                new_expire = (datetime.datetime.now() + datetime.timedelta(days=days_val)).strftime("%Y-%m-%d %H:%M:%S")
                expire_display = f"{days_val} Days"
                time_rem = f"{days_val}d left"
                rem_days = days_val
        except ValueError:
            new_expire = user["expire_date"]
            expire_display = calc_remaining_days(user["expire_date"])
            time_rem = time_remaining(user["expire_date"])
            rem_days = calc_remaining_days(user["expire_date"])

    raw_devices = request.form.get("max_devices", "").strip()
    if raw_devices == "":
        existing_dev = user["max_devices"] if ("max_devices" in user.keys() and user["max_devices"] is not None) else 10
        try:
            max_devices = max(1, min(10, int(existing_dev)))
        except (ValueError, TypeError):
            max_devices = 10
    else:
        try:
            val_dev = int(raw_devices)
            max_devices = max(1, min(10, val_dev))
        except ValueError:
            existing_dev = user["max_devices"] if ("max_devices" in user.keys() and user["max_devices"] is not None) else 10
            max_devices = max(1, min(10, int(existing_dev or 10)))

    note = request.form.get("note", "").strip()

    query = """
        UPDATE users
        SET password = ?, max_traffic_gb = ?, expire_date = ?, note = ?, max_devices = ?
        WHERE id = ?
    """
    params = [new_password, max_traffic_gb, new_expire, note, max_devices, user_id]

    cursor.execute(query, params)
    conn.commit()
    conn.close()

    sync_ipsec_secrets()
    if pwd_was_changed:
        disconnect_user_sas(user["username"])
    else:
        disconnect_excess_sas(user["username"], max_devices)

    if is_ajax:
        return jsonify({
            "success": True,
            "user_id": user_id,
            "password_changed": pwd_was_changed,
            "username": user["username"],
            "password": new_password,
            "server": SERVER_DOMAIN,
            "max_traffic": traffic_display,
            "max_traffic_gb": max_traffic_gb,
            "expire": expire_display,
            "time_remaining": time_rem,
            "expire_date": new_expire or "",
            "remaining_days": rem_days,
            "max_devices": max_devices,
            "note": note
        })

    flash(f"User '{user['username']}' updated successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/user/toggle/<int:user_id>", methods=["GET", "POST"])
@login_required
def toggle_user(user_id):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        new_state = 0 if (user["is_active"] or 0) == 1 else 1
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))
        conn.commit()
        conn.close()
        sync_ipsec_secrets()

        if new_state == 0:
            disconnect_user_sas(user["username"])
        invalidate_online_cache()

        status_str = "Enabled" if new_state == 1 else "Disabled"
        if is_ajax:
            return jsonify({
                "success": True,
                "user_id": user_id,
                "is_active": new_state,
                "username": user["username"],
                "message": f"User '{user['username']}' is now {status_str}."
            })
        flash(f"User '{user['username']}' is now {status_str}.", "info")
    else:
        conn.close()
        if is_ajax:
            return jsonify({"success": False, "error": "User not found!"}), 404
        flash("User not found!", "danger")
    return redirect(url_for("dashboard"))

@app.route("/user/delete/<int:user_id>")
@login_required
def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        username = user["username"]
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        sync_ipsec_secrets()
        disconnect_user_sas(username)

        flash(f"User '{username}' deleted successfully!", "warning")
    else:
        conn.close()
    return redirect(url_for("dashboard"))

RESERVED_PANEL_PATHS = {
    "login", "logout", "settings", "user", "admin",
    "api", "backup", "restore", "static", "sub", "subscription"
}

def update_nginx_panel_path(new_path):
    try:
        domain = get_system_config("server_domain", SERVER_DOMAIN)
        port = get_system_config("panel_port", "443")

        conf_path = "/etc/nginx/sites-available/ike-ui"
        if os.path.exists(conf_path):
            try:
                with open(conf_path, "r") as f:
                    content = f.read()
                    m_dom = re.search(r'server_name\s+([^;]+);', content)
                    if m_dom:
                        domain = m_dom.group(1).strip()
                    m_port = re.search(r'listen\s+([0-9]+)\s+ssl', content)
                    if m_port:
                        port = m_port.group(1).strip()
            except Exception:
                pass

        clean_path = re.sub(r'^/+|/+$', '', str(new_path or "").strip())
        if clean_path.lower() in ("/", "root"):
            clean_path = ""
        else:
            clean_path = re.sub(r'[^a-zA-Z0-9_-]', '', clean_path)

        if clean_path and clean_path.lower() in RESERVED_PANEL_PATHS:
            return False, f"Path '/{clean_path}' is a reserved system path and cannot be used."

        redirect_port = f":{port}" if str(port) != "443" else ""

        nginx_conf = f"""server {{
    listen 80;
    server_name {domain};
    return 301 https://$host{redirect_port}$request_uri;
}}

server {{
    listen {port} ssl http2;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
"""
        if clean_path:
            nginx_conf += f"""
    location = /{clean_path} {{
        return 301 /{clean_path}/;
    }}

    location /{clean_path}/ {{
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Forwarded-Prefix /{clean_path};

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }}

    location /sub {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Forwarded-Prefix "";

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }}

    location /static {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Forwarded-Prefix "";
    }}

    location / {{
        return 404;
    }}
}}
"""
        else:
            nginx_conf += f"""
    location / {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Forwarded-Prefix "";

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }}
}}
"""
        if os.path.exists(os.path.dirname(conf_path)):
            backup_path = f"{conf_path}.bak"
            try:
                if os.path.exists(conf_path):
                    shutil.copy2(conf_path, backup_path)
                with open(conf_path, "w") as f:
                    f.write(nginx_conf)
                res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
                if res.returncode != 0:
                    if os.path.exists(backup_path):
                        shutil.copy2(backup_path, conf_path)
                    return False, f"Nginx test failed: {res.stderr}"
                subprocess.run(["systemctl", "reload", "nginx"], check=False)
            except Exception as ex:
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, conf_path)
                return False, str(ex)

        set_system_config("panel_path", clean_path)
        return True, clean_path
    except Exception as e:
        return False, str(e)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        return update_credentials()

    vpn_status = (get_system_config("vpn_enabled", "1") == "1")
    sub_portal_status = (get_system_config("sub_portal_enabled", "1") == "1")
    cur_path = get_system_config("panel_path", "")
    server_domain = get_system_config("server_domain", SERVER_DOMAIN)
    sub_portal_url = f"https://{server_domain}/sub"
    try:
        session_timeout = int(get_system_config("admin_session_timeout", "4320"))
        session_timeout = max(1, min(43200, session_timeout))
    except (ValueError, TypeError):
        session_timeout = 4320
    session_timeout_formatted = format_duration_minutes(session_timeout)

    return render_template(
        "settings.html",
        vpn_enabled=vpn_status,
        sub_portal_enabled=sub_portal_status,
        sub_portal_url=sub_portal_url,
        server_domain=server_domain,
        panel_path=cur_path,
        session_timeout=session_timeout,
        session_timeout_formatted=session_timeout_formatted
    )

@app.route("/settings/update-session-timeout", methods=["POST"])
@login_required
def update_session_timeout():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    raw_timeout = request.form.get("session_timeout", "").strip()

    try:
        timeout_mins = int(raw_timeout)
        if timeout_mins < 1 or timeout_mins > 43200:
            raise ValueError("Timeout out of range (1 to 43200 minutes)")
    except (ValueError, TypeError):
        msg = "Session expiration duration must be an integer between 1 minute and 43200 minutes (1 month)."
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("settings"))

    set_system_config("admin_session_timeout", str(timeout_mins))
    formatted_duration = format_duration_minutes(timeout_mins)
    msg = f"Admin session expiration duration updated to {timeout_mins} minutes ({formatted_duration})."

    if is_ajax:
        return jsonify({
            "success": True,
            "message": msg,
            "session_timeout": timeout_mins,
            "session_timeout_formatted": formatted_duration
        })
    flash(msg, "success")
    return redirect(url_for("settings"))

@app.route("/settings/update-credentials", methods=["POST"])
@login_required
def update_credentials():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    curr_user = session.get("admin_user", "")
    new_user = request.form.get("new_username", "").strip()
    curr_pass = request.form.get("current_password", "").strip()
    new_pass = request.form.get("new_password", "").strip()
    confirm_pass = request.form.get("confirm_password", "").strip()

    if not curr_pass:
        msg = "Current password is required to update credentials!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("settings"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE username = ?", (curr_user,))
    admin = cursor.fetchone()

    if not admin or not check_password_hash(admin["password_hash"], curr_pass):
        conn.close()
        msg = "Current password is incorrect!"
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("settings"))

    updates = []
    params = []

    if new_user and new_user != curr_user:
        new_user = re.sub(r'[^a-zA-Z0-9_@.-]', '', new_user)
        if len(new_user) < 3:
            conn.close()
            msg = "Username must be at least 3 characters long!"
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "danger")
            return redirect(url_for("settings"))

        cursor.execute("SELECT id FROM admin WHERE username = ? AND id != ?", (new_user, admin["id"]))
        if cursor.fetchone():
            conn.close()
            msg = f"Username '{new_user}' is already taken!"
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "danger")
            return redirect(url_for("settings"))

        updates.append("username = ?")
        params.append(new_user)

    if new_pass:
        if new_pass != confirm_pass:
            conn.close()
            msg = "New passwords do not match!"
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "danger")
            return redirect(url_for("settings"))

        if len(new_pass) < 4:
            conn.close()
            msg = "New password must be at least 4 characters long!"
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "danger")
            return redirect(url_for("settings"))

        updates.append("password_hash = ?")
        params.append(generate_password_hash(new_pass))

    if not updates:
        conn.close()
        msg = "No changes were submitted."
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "info")
        return redirect(url_for("settings"))

    params.append(admin["id"])
    cursor.execute(f"UPDATE admin SET {', '.join(updates)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()

    session.clear()

    msg = "Credentials updated successfully. Please log in with your new credentials."
    if is_ajax:
        return jsonify({
            "success": True,
            "message": msg,
            "require_login": True,
            "redirect_url": url_for("login")
        })
    flash(msg, "success")
    return redirect(url_for("login"))

@app.route("/settings/update-path", methods=["POST"])
@login_required
def update_path():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    new_path = request.form.get("new_path", "").strip()

    ok, result = update_nginx_panel_path(new_path)
    if not ok:
        if is_ajax:
            return jsonify({"success": False, "error": f"Failed to update panel path: {result}"}), 500
        flash(f"Failed to update panel path: {result}", "danger")
        return redirect(url_for("settings"))

    clean_path = result
    domain = get_system_config("server_domain", SERVER_DOMAIN)
    port = get_system_config("panel_port", "443")

    conf_path = "/etc/nginx/sites-available/ike-ui"
    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                content = f.read()
                m_dom = re.search(r'server_name\s+([^;]+);', content)
                if m_dom:
                    domain = m_dom.group(1).strip()
                m_port = re.search(r'listen\s+([0-9]+)\s+ssl', content)
                if m_port:
                    port = m_port.group(1).strip()
        except Exception:
            pass

    port_str = f":{port}" if str(port) != "443" else ""
    path_str = f"/{clean_path}" if clean_path else ""
    new_full_url = f"https://{domain}{port_str}{path_str}/"

    msg = "Panel secret path updated successfully! Redirecting to new path..."
    if is_ajax:
        return jsonify({
            "success": True,
            "message": msg,
            "new_path": clean_path,
            "redirect_url": new_full_url
        })
    flash(msg, "success")
    return redirect(new_full_url)

@app.route("/settings/toggle-vpn", methods=["POST"])
@login_required
def toggle_vpn_service():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    data = request.get_json(silent=True) or {}
    if "state" in data:
        new_status = bool(data["state"])
    else:
        current_status = (get_system_config("vpn_enabled", "1") == "1")
        new_status = not current_status

    set_system_config("vpn_enabled", "1" if new_status else "0")
    sync_ipsec_secrets()
    if not new_status:
        disconnect_all_sas()

    status_text = "enabled" if new_status else "disabled (Maintenance Mode)"
    msg = f"VPN Service is now {status_text}."
    if is_ajax:
        return jsonify({
            "success": True,
            "vpn_enabled": new_status,
            "message": msg
        })
    flash(msg, "success" if new_status else "warning")
    return redirect(url_for("settings"))

@app.route("/settings/toggle-sub-portal", methods=["POST"])
@login_required
def toggle_sub_portal():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"
    current_status = (get_system_config("sub_portal_enabled", "1") == "1")
    new_status = not current_status
    set_system_config("sub_portal_enabled", "1" if new_status else "0")

    status_text = "enabled" if new_status else "disabled"
    msg = f"User Account Portal (/sub) is now {status_text}."
    if is_ajax:
        return jsonify({
            "success": True,
            "sub_portal_enabled": new_status,
            "message": msg
        })
    flash(msg, "success" if new_status else "warning")
    return redirect(url_for("settings"))

@app.route("/admin/add", methods=["POST"])
@login_required
def add_admin():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm_password", "").strip()

    if not username or not password:
        flash("Username and password are required!", "danger")
        return redirect(url_for("settings"))

    if password != confirm:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("settings"))

    try:
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO admin (username, password_hash, created_at) VALUES (?, ?, ?)",
                       (username, generate_password_hash(password), now))
        conn.commit()
        conn.close()
        flash(f"Administrator '{username}' created successfully!", "success")
    except sqlite3.IntegrityError:
        flash(f"Administrator with username '{username}' already exists!", "danger")
    except Exception as e:
        flash(f"Error creating admin: {e}", "danger")

    return redirect(url_for("settings"))

@app.route("/admin/edit-password/<int:admin_id>", methods=["POST"])
@login_required
def edit_admin_password(admin_id):
    new_password = request.form.get("new_password", "").strip()
    confirm = request.form.get("confirm_password", "").strip()

    if not new_password or new_password != confirm:
        flash("Passwords are empty or do not match!", "danger")
        return redirect(url_for("settings"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE id = ?", (admin_id,))
    target_admin = cursor.fetchone()

    if not target_admin:
        conn.close()
        flash("Administrator not found!", "danger")
        return redirect(url_for("settings"))

    cursor.execute("UPDATE admin SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), admin_id))
    conn.commit()
    conn.close()

    flash(f"Password updated for administrator '{target_admin['username']}'!", "success")
    return redirect(url_for("settings"))

@app.route("/admin/delete/<int:admin_id>", methods=["POST"])
@login_required
def delete_admin(admin_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM admin")
    total_admins = cursor.fetchone()["cnt"]

    if total_admins <= 1:
        conn.close()
        flash("Cannot delete the only remaining administrator!", "danger")
        return redirect(url_for("settings"))

    cursor.execute("SELECT * FROM admin WHERE id = ?", (admin_id,))
    target_admin = cursor.fetchone()

    if not target_admin:
        conn.close()
        flash("Administrator not found!", "danger")
        return redirect(url_for("settings"))

    is_self = (target_admin["username"] == session.get("admin_user"))

    cursor.execute("DELETE FROM admin WHERE id = ?", (admin_id,))
    conn.commit()
    conn.close()

    if is_self:
        session.clear()
        flash("Your administrator account has been deleted.", "info")
        return redirect(url_for("login"))

    flash(f"Administrator '{target_admin['username']}' deleted successfully.", "warning")
    return redirect(url_for("settings"))

def validate_uploaded_sqlite_db(file_bytes):
    """
    Validates that the uploaded file is a valid, uncorrupted SQLite database
    and contains a compatible `users` table with valid account records.
    Returns: (is_valid: bool, error_message: str or None, parsed_users: list)
    """
    if not file_bytes:
        return False, "No file content received.", []

    if len(file_bytes) < 16 or not file_bytes.startswith(b"SQLite format 3\x00"):
        return False, "Invalid file signature. The uploaded file is not a valid SQLite 3 database.", []

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            tmp_file.write(file_bytes)
            tmp_path = tmp_file.name

        test_conn = sqlite3.connect(tmp_path, timeout=5.0)
        test_conn.row_factory = sqlite3.Row
        test_cur = test_conn.cursor()

        test_cur.execute("PRAGMA integrity_check;")
        check_row = test_cur.fetchone()
        if not check_row or str(check_row[0]).lower() != "ok":
            test_conn.close()
            return False, "The database file appears corrupted (integrity check failed).", []

        test_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if not test_cur.fetchone():
            test_conn.close()
            return False, "Incompatible database: Table 'users' was not found in the uploaded file.", []

        test_cur.execute("PRAGMA table_info(users);")
        col_rows = test_cur.fetchall()
        cols = {row["name"].lower() for row in col_rows}

        if "username" not in cols or "password" not in cols:
            test_conn.close()
            return False, "Incompatible table schema: Missing required 'username' or 'password' columns.", []

        test_cur.execute("SELECT * FROM users;")
        rows = test_cur.fetchall()
        test_conn.close()

        if not rows:
            return False, "The uploaded database contains 0 user records.", []

        parsed_users = []
        seen_usernames = set()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for r in rows:
            r_dict = dict(r)
            uname = str(r_dict.get("username", "")).strip()
            if not uname:
                continue

            uname_lower = uname.lower()
            if uname_lower in seen_usernames:
                continue
            seen_usernames.add(uname_lower)

            pwd = str(r_dict.get("password", "")).strip()
            if not pwd:
                pwd = generate_random_pwd(8)

            try:
                max_traffic = float(r_dict.get("max_traffic_gb") or 0.0)
            except (ValueError, TypeError):
                max_traffic = 0.0

            try:
                used_traffic = int(r_dict.get("used_traffic_bytes") or 0)
            except (ValueError, TypeError):
                used_traffic = 0

            created = str(r_dict.get("created_at") or now_str).strip()
            expire = r_dict.get("expire_date")
            expire = str(expire).strip() if expire else None

            try:
                is_active = int(r_dict.get("is_active") if r_dict.get("is_active") is not None else 1)
                is_active = 1 if is_active == 1 else 0
            except (ValueError, TypeError):
                is_active = 1

            note = str(r_dict.get("note") or "").strip()
            last_online = r_dict.get("last_online_at")
            last_online = str(last_online).strip() if last_online else None
            last_ip = r_dict.get("last_ip")
            last_ip = str(last_ip).strip() if last_ip else None

            try:
                max_dev = int(r_dict.get("max_devices") or 10)
                max_dev = max(1, min(10, max_dev))
            except (ValueError, TypeError):
                max_dev = 10

            parsed_users.append({
                "username": uname,
                "password": pwd,
                "max_traffic_gb": max_traffic,
                "used_traffic_bytes": used_traffic,
                "created_at": created,
                "expire_date": expire,
                "is_active": is_active,
                "note": note,
                "last_online_at": last_online,
                "last_ip": last_ip,
                "max_devices": max_dev
            })

        if not parsed_users:
            return False, "No valid user accounts found in the database.", []

        return True, None, parsed_users

    except Exception as e:
        return False, f"Failed to parse database file: {e}", []
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

@app.route("/backup/users", methods=["GET"])
@login_required
def backup_users():
    """Generates and downloads a dedicated SQLite database backup containing only the users table."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id ASC")
        users = [dict(u) for u in cursor.fetchall()]
        conn.close()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        export_conn = sqlite3.connect(tmp_path)
        export_cur = export_conn.cursor()

        export_cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            max_traffic_gb REAL DEFAULT 0,
            used_traffic_bytes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expire_date TEXT,
            is_active INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            last_online_at TEXT,
            last_ip TEXT,
            max_devices INTEGER DEFAULT 10
        )
        """)

        export_cur.execute("""
        CREATE TABLE _ike_backup_meta (
            backup_type TEXT,
            created_at TEXT,
            app_version TEXT,
            user_count INTEGER
        )
        """)

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        export_cur.execute(
            "INSERT INTO _ike_backup_meta (backup_type, created_at, app_version, user_count) VALUES ('users_backup', ?, ?, ?)",
            (now_str, APP_VERSION, len(users))
        )

        for u in users:
            export_cur.execute("""
                INSERT INTO users (username, password, max_traffic_gb, used_traffic_bytes, created_at, expire_date, is_active, note, last_online_at, last_ip, max_devices)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                u.get("username"),
                u.get("password"),
                u.get("max_traffic_gb", 0),
                u.get("used_traffic_bytes", 0),
                u.get("created_at", now_str),
                u.get("expire_date"),
                u.get("is_active", 1),
                u.get("note", ""),
                u.get("last_online_at"),
                u.get("last_ip"),
                u.get("max_devices", 10)
            ))

        export_conn.commit()
        export_conn.close()

        with open(tmp_path, "rb") as f:
            data = f.read()

        try:
            os.remove(tmp_path)
        except Exception:
            pass

        filename = f"ike_users_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename,
            mimetype="application/x-sqlite3"
        )
    except Exception as e:
        print(f"[!] Error creating users backup: {e}", file=sys.stderr)
        flash(f"Error creating users backup: {e}", "danger")
        return redirect(url_for("settings"))

@app.route("/backup/full", methods=["GET"])
@login_required
def backup_full():
    """Generates and downloads a complete snapshot of the entire panel database."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        src_conn = get_db()
        dest_conn = sqlite3.connect(tmp_path)
        with dest_conn:
            src_conn.backup(dest_conn)
        dest_conn.close()
        src_conn.close()

        with open(tmp_path, "rb") as f:
            data = f.read()

        try:
            os.remove(tmp_path)
        except Exception:
            pass

        filename = f"ike_panel_full_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename,
            mimetype="application/x-sqlite3"
        )
    except Exception as e:
        print(f"[!] Error creating full database backup: {e}", file=sys.stderr)
        flash(f"Error creating full backup: {e}", "danger")
        return redirect(url_for("settings"))

@app.route("/restore/users/validate", methods=["POST"])
@login_required
def restore_users_validate():
    """Validates an uploaded database file and returns user count."""
    if "backup_file" not in request.files:
        return jsonify({"success": False, "error": "No backup file uploaded."}), 400

    file = request.files["backup_file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "Please select a valid database file."}), 400

    file_bytes = file.read()
    if len(file_bytes) > 50 * 1024 * 1024:
        return jsonify({"success": False, "error": "Database file is too large (maximum allowed is 50MB)."}), 400

    is_valid, error_msg, users = validate_uploaded_sqlite_db(file_bytes)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    return jsonify({
        "success": True,
        "user_count": len(users)
    })

@app.route("/restore/users/execute", methods=["POST"])
@login_required
def restore_users_execute():
    """Restores users table from uploaded database file with confirmation enforcement."""
    confirm_text = request.form.get("confirmation", "").strip()
    if confirm_text.upper() != "RESTORE":
        return jsonify({
            "success": False,
            "error": "Confirmation keyword mismatch. Please type RESTORE to confirm."
        }), 400

    if "backup_file" not in request.files:
        return jsonify({"success": False, "error": "No backup file uploaded."}), 400

    file = request.files["backup_file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "Please select a valid database file."}), 400

    file_bytes = file.read()
    if len(file_bytes) > 50 * 1024 * 1024:
        return jsonify({"success": False, "error": "Database file exceeds maximum size of 50MB."}), 400

    is_valid, error_msg, users = validate_uploaded_sqlite_db(file_bytes)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users;")
        for u in users:
            cursor.execute("""
                INSERT INTO users (username, password, max_traffic_gb, used_traffic_bytes, created_at, expire_date, is_active, note, last_online_at, last_ip, max_devices)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                u["username"],
                u["password"],
                u["max_traffic_gb"],
                u["used_traffic_bytes"],
                u["created_at"],
                u["expire_date"],
                u["is_active"],
                u["note"],
                u.get("last_online_at"),
                u.get("last_ip"),
                u["max_devices"]
            ))

        conn.commit()
        conn.close()

        sync_ipsec_secrets()
        disconnect_all_sas()

        return jsonify({
            "success": True,
            "message": f"Successfully restored {len(users)} users!",
            "restored_count": len(users)
        })
    except Exception as e:
        print(f"[!] Error during users restore: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": f"Database restore failed: {e}"}), 500

init_db()
sync_ipsec_secrets()
start_accounting_daemon()

if __name__ == "__main__":
    print(f"[*] Starting IKE-UI Panel on 0.0.0.0:{PANEL_PORT}...")
    app.run(host="0.0.0.0", port=PANEL_PORT, debug=False)
