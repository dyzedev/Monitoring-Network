import hmac
import sqlite3
import hashlib
import ipaddress
import html
import os
import sys
import threading
import time
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, jsonify, request,
                   redirect, url_for, session, flash, send_file)
from groq import Groq
from dotenv import load_dotenv
import incident_engine

# Load environment variables from .env (absolute path for PythonAnywhere)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_env_path)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "netguard-dev-secret-change-in-prod")
# Use absolute path so PythonAnywhere WSGI finds the database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETGUARD_DB_PATH", os.path.join(BASE_DIR, "network_monitor.db"))

# Get Groq configuration from environment
groq_api_key = os.environ.get("GROQ_API_KEY")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
client       = Groq(api_key=groq_api_key) if groq_api_key else None


# ---------------------------------------------
#  DB helpers
# ---------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """SHA-256 hash. Swap for bcrypt in production."""
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")

    # users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT    NOT NULL,
            last_name  TEXT    NOT NULL,
            username   TEXT    NOT NULL UNIQUE,
            email      TEXT    NOT NULL UNIQUE,
            role       TEXT    NOT NULL DEFAULT 'analyst',
            password   TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    """)

    # network_logs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            device     TEXT    NOT NULL,
            ip         TEXT    NOT NULL,
            status     TEXT    NOT NULL CHECK(status IN ('Online','Offline')),
            latency_ms REAL    NOT NULL,
            timestamp  TEXT    NOT NULL
        )
    """)

    # devices table (v2 schema with category, criticality,
    # maintenance mode, and per-device latency thresholds)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            name                        TEXT    NOT NULL,
            ip_address                  TEXT    NOT NULL UNIQUE,
            category                    TEXT    NOT NULL DEFAULT 'General',
            criticality                 TEXT    NOT NULL DEFAULT 'Medium',
            is_maintenance              INTEGER NOT NULL DEFAULT 0,
            maintenance_reason          TEXT    DEFAULT NULL,
            latency_threshold_ms        REAL    NOT NULL DEFAULT 150.0,
            critical_latency_threshold_ms REAL  NOT NULL DEFAULT 300.0
        )
    """)

    # Create ai_responses table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_responses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            user_query  TEXT    NOT NULL,
            ai_response TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Create incidents table (tracks outages, high latency, etc.)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id         INTEGER NOT NULL,
            incident_type     TEXT    NOT NULL,
            severity          TEXT    NOT NULL DEFAULT 'Medium',
            status            TEXT    NOT NULL DEFAULT 'Open',
            summary           TEXT    NOT NULL,
            started_at        TEXT    NOT NULL,
            acknowledged_at   TEXT    DEFAULT NULL,
            resolved_at       TEXT    DEFAULT NULL,
            acknowledged_by   INTEGER DEFAULT NULL,
            resolved_by       INTEGER DEFAULT NULL,
            resolution_notes  TEXT    DEFAULT NULL,
            created_at        TEXT    NOT NULL,
            FOREIGN KEY(device_id)       REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY(acknowledged_by) REFERENCES users(id),
            FOREIGN KEY(resolved_by)     REFERENCES users(id)
        )
    """)

    # Create incident_timeline table (audit trail & comments)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            user_id     INTEGER DEFAULT NULL,
            source      TEXT    NOT NULL DEFAULT 'system',
            message     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id)     REFERENCES users(id)
        )
    """)

    # Seed default devices if empty
    cur.execute("SELECT COUNT(*) FROM devices")
    if cur.fetchone()[0] == 0:
        cur.executemany("""
            INSERT INTO devices (name, ip_address)
            VALUES (?, ?)
        """, [
            ("Google DNS", "8.8.8.8"),
            ("Laptop", "10.82.199.40"),
            ("My Phone", "10.82.199.254")
        ])

    conn.commit()
    conn.close()


def get_current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ─────────────────────────────────────────────
#  Auth decorator
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or get_current_user() is None:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            flash("Please log in to access the dashboard.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or get_current_user() is None:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))

        user = get_current_user()
        if not user or user.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "Forbidden: Administrator role required."}), 403
            flash("Access denied. Administrator privileges required.", "error")
            return redirect(url_for("index"))

        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
#  Auth routes (login, register, logout)
# ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please fill in all fields.", "error")
            return render_template("login.html")

        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username, username)
        )
        user = cur.fetchone()
        conn.close()

        if user and user["password"] == hash_password(password):
            session["user_id"]    = user["id"]
            session["username"]   = user["username"]
            session["role"]       = user["role"]
            session["first_name"] = user["first_name"]
            session["last_name"]  = user["last_name"]
            flash(f"Welcome back, {user['first_name']}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials. Access denied.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name  = request.form.get("last_name",  "").strip()
        username   = request.form.get("username",   "").strip()
        email      = request.form.get("email",      "").strip()
        role       = request.form.get("role",       "analyst")
        password   = request.form.get("password",   "")
        confirm    = request.form.get("confirm_password", "")
        terms      = request.form.get("terms")

        if not all([first_name, last_name, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        if not terms:
            flash("You must agree to the security policy.", "warning")
            return render_template("register.html")

        conn = get_db()
        cur  = conn.cursor()
        try:
            # Safe bootstrap check: First user registered is Admin, all subsequent users are Analyst
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            assigned_role = "admin" if user_count == 0 else "analyst"

            cur.execute("""
                INSERT INTO users
                  (first_name, last_name, username, email, role, password, created_at)
                VALUES (?,?,?,?,?,?,?)
            """, (
                first_name, last_name, username, email,
                assigned_role, hash_password(password),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
            if assigned_role == "admin":
                flash("Initial Administrator account created! You can now log in.", "success")
            else:
                flash("Analyst account created! You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/logout")
def logout():
    name = session.get("first_name", "Operator")
    session.clear()
    flash(f"Session terminated. Goodbye, {name}.", "success")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
#  Dashboard (protected)
# ─────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    user = get_current_user()
    return render_template("index.html", user=user)


# ─────────────────────────────────────────────
#  API routes (all protected)
# ─────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT AVG(latency_ms) AS avg_latency,
               SUM(CASE WHEN status='Online'  THEN 1 ELSE 0 END) AS online_count,
               SUM(CASE WHEN status='Offline' THEN 1 ELSE 0 END) AS offline_count
        FROM network_logs
        WHERE id IN (
            SELECT MAX(id) FROM network_logs GROUP BY device
        )
        AND EXISTS (
            SELECT 1 FROM devices 
            WHERE devices.name = network_logs.device 
              AND devices.ip_address = network_logs.ip
        )
    """)
    row     = cur.fetchone()
    online  = row["online_count"]  or 0
    offline = row["offline_count"] or 0
    status  = ("Operational" if offline == 0
               else "Degraded" if online >= offline
               else "Critical")

    # Get dynamic device count from devices table
    cur.execute("SELECT COUNT(*) FROM devices")
    device_count = cur.fetchone()[0] or 0

    conn.close()
    return jsonify({
        "avg_latency":    round(row["avg_latency"] or 0, 2),
        "device_count":   device_count,
        "current_status": status,
        "online_count":   online,
        "offline_count":  offline,
    })


@app.route("/api/logs")
@login_required
def api_logs():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT device, ip, status, latency_ms, timestamp
        FROM network_logs
        WHERE EXISTS (
            SELECT 1 FROM devices 
            WHERE devices.name = network_logs.device 
              AND devices.ip_address = network_logs.ip
        )
        ORDER BY id DESC
        LIMIT 10
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/devices")
@login_required
def api_devices():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, name, ip_address, category, criticality, 
               is_maintenance, maintenance_reason, 
               latency_threshold_ms, critical_latency_threshold_ms 
        FROM devices 
        ORDER BY name ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/latency_history")
@login_required
def api_latency_history():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT device, latency_ms, timestamp
        FROM network_logs
        WHERE EXISTS (
            SELECT 1 FROM devices 
            WHERE devices.name = network_logs.device 
              AND devices.ip_address = network_logs.ip
        )
        ORDER BY id DESC
        LIMIT 100
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    rows.reverse()
    return jsonify(rows)


@app.route("/api/chat/history")
@login_required
def api_chat_history():
    user = get_current_user()
    if not user:
        return jsonify([])
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT user_query, ai_response, timestamp
        FROM ai_responses
        WHERE user_id = ?
        ORDER BY id ASC
    """, (user["id"],))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

# ---------------------------------------------
#  Device Management Routes
# ---------------------------------------------

VALID_CATEGORIES = [
    "Gateway/Router",
    "Core Switch",
    "Access Point",
    "Server/NAS",
    "Workstation/Laptop",
    "IP Camera/CCTV",
    "IoT Device",
    "General Host",
    "General"
]

VALID_CRITICALITIES = ["Low", "Medium", "High", "Critical"]


def parse_and_validate_device_payload(data: dict, is_update=False):
    """
    Validates device input fields and returns (cleaned_dict, error_message).
    Uses Python's ipaddress module and enforces strict threshold checks.
    """
    cleaned = {}

    # Validate device name
    name = data.get("name")
    if name is not None or not is_update:
        if not name or not str(name).strip():
            return None, "Device Name is required."
        cleaned["name"] = str(name).strip()

    # Validate IP address using Python's ipaddress module
    ip_raw = data.get("ip_address")
    if ip_raw is not None or not is_update:
        if not ip_raw or not str(ip_raw).strip():
            return None, "IP Address is required."
        ip_str = str(ip_raw).strip()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            cleaned["ip_address"] = str(ip_obj)
        except ValueError:
            return None, f"Invalid IP address format: '{ip_str}'. Must be a valid IPv4 or IPv6 address."

    # Validate category
    if "category" in data or not is_update:
        category = str(data.get("category", "General")).strip()
        cleaned["category"] = category if category in VALID_CATEGORIES else "General"

    # Validate criticality
    if "criticality" in data or not is_update:
        criticality = str(data.get("criticality", "Medium")).strip().capitalize()
        cleaned["criticality"] = criticality if criticality in VALID_CRITICALITIES else "Medium"

    # Validate maintenance mode
    if "is_maintenance" in data or not is_update:
        val = data.get("is_maintenance", 0)
        cleaned["is_maintenance"] = 1 if val in (1, "1", True, "true", "True") else 0

    # Validate maintenance reason
    if "maintenance_reason" in data or not is_update:
        reason = data.get("maintenance_reason")
        cleaned["maintenance_reason"] = str(reason).strip() if (reason and str(reason).strip()) else None

    # Validate latency thresholds
    lat_warn_raw = data.get("latency_threshold_ms", 150.0)
    lat_crit_raw = data.get("critical_latency_threshold_ms", 300.0)

    if lat_warn_raw is not None:
        try:
            lat_warn = float(lat_warn_raw)
            if lat_warn <= 0:
                return None, "Warning latency threshold must be greater than 0 ms."
            cleaned["latency_threshold_ms"] = round(lat_warn, 2)
        except (ValueError, TypeError):
            return None, "Warning latency threshold must be a valid number."

    if lat_crit_raw is not None:
        try:
            lat_crit = float(lat_crit_raw)
            if lat_crit <= 0:
                return None, "Critical latency threshold must be greater than 0 ms."
            cleaned["critical_latency_threshold_ms"] = round(lat_crit, 2)
        except (ValueError, TypeError):
            return None, "Critical latency threshold must be a valid number."

    # Enforce threshold constraint: critical threshold must exceed warning threshold
    warn_val = cleaned.get("latency_threshold_ms", 150.0)
    crit_val = cleaned.get("critical_latency_threshold_ms", 300.0)
    if crit_val <= warn_val:
        return None, (
            f"Critical latency threshold ({crit_val} ms) must be strictly greater "
            f"than warning latency threshold ({warn_val} ms)."
        )

    return cleaned, None


@app.route("/api/devices", methods=["POST"])
@admin_required
def add_device():
    data = request.get_json(force=True) if (request.is_json or request.data) else {}
    cleaned, error = parse_and_validate_device_payload(data, is_update=False)
    if error:
        return jsonify({"error": error}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO devices (
                name, ip_address, category, criticality,
                is_maintenance, maintenance_reason,
                latency_threshold_ms, critical_latency_threshold_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cleaned["name"],
            cleaned["ip_address"],
            cleaned["category"],
            cleaned["criticality"],
            cleaned["is_maintenance"],
            cleaned["maintenance_reason"],
            cleaned["latency_threshold_ms"],
            cleaned["critical_latency_threshold_ms"]
        ))
        conn.commit()
        new_id = cur.lastrowid
        conn.close()
        return jsonify({
            "success": True,
            "message": f"Device '{cleaned['name']}' added successfully!",
            "id": new_id
        }), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": f"A device with this IP Address ('{cleaned['ip_address']}') already exists."}), 400


@app.route("/api/devices/<int:device_id>", methods=["PUT"])
@admin_required
def edit_device(device_id):
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": f"Device with ID {device_id} not found."}), 404

    data = request.get_json(force=True) if (request.is_json or request.data) else {}

    # Merge with existing database values for partial updates
    merged = dict(existing)
    merged.update(data)

    cleaned, error = parse_and_validate_device_payload(merged, is_update=True)
    if error:
        conn.close()
        return jsonify({"error": error}), 400

    try:
        cur.execute("""
            UPDATE devices 
            SET name = ?, ip_address = ?, category = ?, criticality = ?,
                is_maintenance = ?, maintenance_reason = ?,
                latency_threshold_ms = ?, critical_latency_threshold_ms = ?
            WHERE id = ?
        """, (
            cleaned["name"],
            cleaned["ip_address"],
            cleaned["category"],
            cleaned["criticality"],
            cleaned["is_maintenance"],
            cleaned["maintenance_reason"],
            cleaned["latency_threshold_ms"],
            cleaned["critical_latency_threshold_ms"],
            device_id
        ))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Device '{cleaned['name']}' updated successfully!"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": f"A device with this IP Address ('{cleaned['ip_address']}') already exists."}), 400


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
@admin_required
def delete_device(device_id):
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT id, name FROM devices WHERE id = ?", (device_id,))
    dev = cur.fetchone()
    if not dev:
        conn.close()
        return jsonify({"error": f"Device with ID {device_id} not found."}), 404

    # Requirement 1: Protect existing incident history when deleting devices
    cur.execute("SELECT COUNT(*) FROM incidents WHERE device_id = ?", (device_id,))
    incident_count = cur.fetchone()[0]
    if incident_count > 0:
        conn.close()
        return jsonify({
            "error": (
                f"Cannot delete device '{dev['name']}': {incident_count} incident record(s) "
                "are associated with this device. To protect incident history, resolve or archive "
                "its incidents first, or place the device in Maintenance Mode instead."
            )
        }), 400

    cur.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Device '{dev['name']}' deleted successfully!"})


# ─────────────────────────────────────────────
#  Incident Management Routes (Phase 4)
# ─────────────────────────────────────────────

@app.route("/api/incidents", methods=["GET"])
@login_required
def api_incidents():
    """
    List incidents with device metadata and resolution information.
    Supports filtering by status and severity.
    """
    status_filter = request.args.get("status", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    device_id_filter = request.args.get("device_id", "").strip()

    conn = get_db()
    cur  = conn.cursor()

    query = """
        SELECT i.id, i.device_id, i.incident_type, i.severity, i.status, i.summary,
               i.started_at, i.acknowledged_at, i.resolved_at,
               i.acknowledged_by, i.resolved_by, i.resolution_notes, i.created_at,
               d.name AS device_name, d.ip_address AS device_ip,
               d.category AS device_category, d.criticality AS device_criticality,
               u_ack.username AS acknowledged_by_username,
               (u_ack.first_name || ' ' || u_ack.last_name) AS acknowledged_by_name,
               u_res.username AS resolved_by_username,
               (u_res.first_name || ' ' || u_res.last_name) AS resolved_by_name
        FROM incidents i
        LEFT JOIN devices d ON d.id = i.device_id
        LEFT JOIN users u_ack ON u_ack.id = i.acknowledged_by
        LEFT JOIN users u_res ON u_res.id = i.resolved_by
        WHERE 1=1
    """
    params = []

    if status_filter:
        query += " AND i.status = ?"
        params.append(status_filter)

    if severity_filter:
        query += " AND i.severity = ?"
        params.append(severity_filter)

    if device_id_filter:
        try:
            params.append(int(device_id_filter))
            query += " AND i.device_id = ?"
        except ValueError:
            pass

    query += """
        ORDER BY 
          CASE i.status 
            WHEN 'Open' THEN 1 
            WHEN 'Acknowledged' THEN 2 
            WHEN 'Resolved' THEN 3 
            ELSE 4 
          END ASC,
          i.id DESC
    """

    cur.execute(query, tuple(params))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/incidents/<int:incident_id>/timeline", methods=["GET"])
@login_required
def api_incident_timeline(incident_id):
    """
    Return the audit timeline for an incident in chronological order.
    """
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"error": f"Incident with ID {incident_id} not found."}), 404

    cur.execute("""
        SELECT t.id, t.incident_id, t.user_id, t.source, t.message, t.created_at,
               u.username, u.first_name, u.last_name, u.role,
               CASE 
                 WHEN u.id IS NOT NULL THEN (u.first_name || ' ' || u.last_name)
                 ELSE 'System' 
               END AS author_name
        FROM incident_timeline t
        LEFT JOIN users u ON u.id = t.user_id
        WHERE t.incident_id = ?
        ORDER BY t.id ASC
    """, (incident_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/incidents/<int:incident_id>/acknowledge", methods=["POST"])
@login_required
def api_acknowledge_incident(incident_id):
    """
    Allow authenticated Administrators and Analysts to acknowledge an active incident.
    """
    user = get_current_user()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    inc = cur.fetchone()
    if not inc:
        conn.close()
        return jsonify({"error": f"Incident with ID {incident_id} not found."}), 404

    inc = dict(inc)
    if inc["status"] == "Resolved":
        conn.close()
        return jsonify({"error": "Cannot acknowledge an incident that has already been resolved."}), 400

    if inc["status"] == "Acknowledged":
        conn.close()
        return jsonify({
            "success": True,
            "message": "Incident is already acknowledged.",
            "status": "Acknowledged"
        })

    # Update incident to Acknowledged
    cur.execute("""
        UPDATE incidents
        SET status = 'Acknowledged', acknowledged_at = ?, acknowledged_by = ?
        WHERE id = ?
    """, (now_str, user["id"], incident_id))

    # Audit timeline entry
    author_name = f"{user['first_name']} {user['last_name']}"
    cur.execute("""
        INSERT INTO incident_timeline (incident_id, user_id, source, message, created_at)
        VALUES (?, ?, 'user', ?, ?)
    """, (
        incident_id,
        user["id"],
        f"Incident acknowledged by {author_name} (Role: {user['role']}).",
        now_str
    ))

    conn.commit()
    conn.close()
    return jsonify({
        "success": True,
        "message": f"Incident #{incident_id} acknowledged successfully.",
        "status": "Acknowledged"
    })


@app.route("/api/incidents/<int:incident_id>/resolve", methods=["POST"])
@admin_required
def api_resolve_incident(incident_id):
    """
    Allow Administrator to resolve an incident with mandatory resolution notes.
    """
    user = get_current_user()
    data = request.get_json(force=True) if (request.is_json or request.data) else {}
    notes = str(data.get("resolution_notes", "")).strip()

    if not notes:
        return jsonify({"error": "Resolution notes are required to resolve an incident."}), 400

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    inc = cur.fetchone()
    if not inc:
        conn.close()
        return jsonify({"error": f"Incident with ID {incident_id} not found."}), 404

    inc = dict(inc)
    if inc["status"] == "Resolved":
        conn.close()
        return jsonify({"error": "Incident has already been resolved."}), 400

    safe_notes = html.escape(notes)

    cur.execute("""
        UPDATE incidents
        SET status = 'Resolved', resolved_at = ?, resolved_by = ?, resolution_notes = ?
        WHERE id = ?
    """, (now_str, user["id"], safe_notes, incident_id))

    author_name = f"{user['first_name']} {user['last_name']}"
    cur.execute("""
        INSERT INTO incident_timeline (incident_id, user_id, source, message, created_at)
        VALUES (?, ?, 'user', ?, ?)
    """, (
        incident_id,
        user["id"],
        f"Incident resolved by Administrator {author_name}: {safe_notes}",
        now_str
    ))

    conn.commit()
    conn.close()
    return jsonify({
        "success": True,
        "message": f"Incident #{incident_id} resolved successfully.",
        "status": "Resolved"
    })


@app.route("/api/incidents/<int:incident_id>/timeline", methods=["POST"])
@login_required
def api_add_incident_note(incident_id):
    """
    Allow authenticated Administrators and Analysts to append investigation notes to an incident.
    """
    user = get_current_user()
    data = request.get_json(force=True) if (request.is_json or request.data) else {}
    note = str(data.get("message", "")).strip()

    if not note:
        return jsonify({"error": "Investigation note message is required."}), 400
    if len(note) > 1000:
        return jsonify({"error": "Investigation note cannot exceed 1000 characters."}), 400

    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"error": f"Incident with ID {incident_id} not found."}), 404

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_note = html.escape(note)

    cur.execute("""
        INSERT INTO incident_timeline (incident_id, user_id, source, message, created_at)
        VALUES (?, ?, 'user', ?, ?)
    """, (incident_id, user["id"], safe_note, now_str))

    new_timeline_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Investigation note recorded.",
        "id": new_timeline_id
    }), 201


# ─────────────────────────────────────────────
#  User Management Routes (Phase 4 - Admin Only)
# ─────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@admin_required
def api_users():
    """
    List registered users without exposing password hashes or secrets.
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, first_name, last_name, username, email, role, created_at
        FROM users
        ORDER BY id ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/users/<int:target_user_id>/role", methods=["PUT"])
@admin_required
def api_update_user_role(target_user_id):
    """
    Update a user's role between 'admin' and 'analyst'.
    Prevents demoting the last remaining Administrator.
    """
    data = request.get_json(force=True) if (request.is_json or request.data) else {}
    new_role = str(data.get("role", "")).strip().lower()

    if new_role not in ("admin", "analyst"):
        return jsonify({"error": "Invalid role. Role must be 'admin' or 'analyst'."}), 400

    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT id, username, role FROM users WHERE id = ?", (target_user_id,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return jsonify({"error": f"User with ID {target_user_id} not found."}), 404

    target = dict(target)
    if target["role"] == new_role:
        conn.close()
        return jsonify({"success": True, "message": f"User '{target['username']}' already has role '{new_role}'."})

    # Protect last remaining Administrator from demotion
    if target["role"] == "admin" and new_role != "admin":
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cur.fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return jsonify({
                "error": "Cannot demote the last remaining Administrator. At least one Administrator account must exist."
            }), 400

    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_user_id))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"User '{target['username']}' role updated to '{new_role}'."
    })


@app.route("/api/users/<int:target_user_id>", methods=["DELETE"])
@admin_required
def api_delete_user(target_user_id):
    """
    Delete a user account.
    Prevents:
      1. Self-deletion of currently logged-in Administrator account.
      2. Deletion of the last remaining Administrator.
      3. Deleting users with historical audit references (incidents, timeline, AI history).
    """
    current_user = get_current_user()

    # Rule 1: Prevent self-deletion
    if current_user["id"] == target_user_id:
        return jsonify({
            "error": "Security policy violation: You cannot delete your own active Administrator account."
        }), 400

    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT id, username, role FROM users WHERE id = ?", (target_user_id,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return jsonify({"error": f"User with ID {target_user_id} not found."}), 404

    target = dict(target)

    # Rule 2: Prevent deletion of last Administrator
    if target["role"] == "admin":
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cur.fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return jsonify({
                "error": "Cannot delete the last remaining Administrator. At least one Administrator account must exist."
            }), 400

    # Rule 3: Check dependent historical records to protect audit integrity
    cur.execute("SELECT COUNT(*) FROM incidents WHERE acknowledged_by = ? OR resolved_by = ?", (target_user_id, target_user_id))
    inc_history = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incident_timeline WHERE user_id = ?", (target_user_id,))
    timeline_history = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM ai_responses WHERE user_id = ?", (target_user_id,))
    ai_history = cur.fetchone()[0]

    total_history = inc_history + timeline_history + ai_history
    if total_history > 0:
        conn.close()
        return jsonify({
            "error": (
                f"Cannot delete user '{target['username']}': Account has {total_history} associated "
                "historical record(s) (incident resolutions, timeline audit entries, or AI chat logs). "
                "To preserve compliance and audit integrity, user history cannot be deleted."
            )
        }), 400

    cur.execute("DELETE FROM users WHERE id = ?", (target_user_id,))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"User '{target['username']}' deleted successfully."
    })


# ─────────────────────────────────────────────
#  AI Routes
# ─────────────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data       = request.get_json(force=True)
    user_query = data.get("message", "")
    user       = get_current_user()
    operator   = (f"{user['first_name']} {user['last_name']} (Role: {user['role']})"
                  if user else "Unknown Operator")

    # Fetch last 30 network events
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT timestamp, device, ip, status, latency_ms
        FROM network_logs
        WHERE EXISTS (
            SELECT 1 FROM devices 
            WHERE devices.name = network_logs.device 
              AND devices.ip_address = network_logs.ip
        )
        ORDER BY id DESC
        LIMIT 30
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    network_context = "Recent Network History (Last 30 events):\n"
    for r in rows:
        network_context += (
            f"- [{r['timestamp']}] {r['device']} ({r['ip']}): "
            f"{r['status']}, {r['latency_ms']}ms\n"
        )

    try:
        if not client:
            raise ValueError("GROQ_API_KEY is not configured.")
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are NetGuard AI, an expert network monitoring assistant. "
                        f"The operator currently logged in is: {operator}. "
                        "Analyze the network data and answer like a senior network engineer. "
                        "Be concise, technical, and professional. "
                        "Address the operator by their first name when appropriate."
                    )
                },
                {
                    "role": "user",
                    "content": f"Network Data:\n{network_context}\n\nQuestion: {user_query}"
                }
            ]
        )
        reply = completion.choices[0].message.content
    except Exception as e:
        reply = f"⚠️ AI engine error: {str(e)}"

    # Save query and AI response to history
    if user:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO ai_responses (user_id, user_query, ai_response, timestamp)
            VALUES (?, ?, ?, ?)
        """, (user["id"], user_query, reply, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

    return jsonify({
        "reply":     reply,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })

# ─────────────────────────────────────────────
#  Monitoring & Remote Agent Routes
# ─────────────────────────────────────────────

_scan_lock = threading.Lock()
_monitor_started = False
_monitor_start_lock = threading.Lock()
_process_lock_fd = None


def _is_valid_agent_request() -> bool:
    """Verify X-Monitor-Key matches MONITOR_SYNC_KEY or SECRET_KEY."""
    expected = os.environ.get("MONITOR_SYNC_KEY") or app.secret_key or ""
    provided = request.headers.get("X-Monitor-Key", "")
    return bool(expected and provided and hmac.compare_digest(expected, provided))


def _run_safe_scan() -> list:
    """Execute one monitoring pass under a lock using the app's configured DB_PATH."""
    import monitor
    with _scan_lock:
        conn = get_db()
        try:
            return monitor.run_monitor_cycle(conn=conn)
        finally:
            conn.close()


@app.route("/api/admin/db", methods=["GET"])
@admin_required
def api_admin_db_inspect():
    """Allow Admin to inspect live SQLite tables in the browser (no paid Shell needed)."""
    conn = get_db()
    cur = conn.cursor()
    try:
        tables = {}
        queries = {
            "devices": "SELECT * FROM devices ORDER BY id ASC",
            "network_logs": "SELECT * FROM network_logs ORDER BY id DESC LIMIT 25",
            "incidents": "SELECT * FROM incidents ORDER BY id DESC LIMIT 25",
            "incident_timeline": "SELECT * FROM incident_timeline ORDER BY id DESC LIMIT 25",
            "users": "SELECT id, first_name, last_name, username, email, role, created_at FROM users ORDER BY id ASC",
            "ai_responses": "SELECT id, user_id, user_query, timestamp FROM ai_responses ORDER BY id DESC LIMIT 20",
        }
        for name, sql in queries.items():
            cur.execute(f"SELECT COUNT(*) FROM {name}")
            total = cur.fetchone()[0]
            cur.execute(sql)
            tables[name] = {
                "total_rows": total,
                "rows": [dict(r) for r in cur.fetchall()],
            }
        return jsonify({"db_path": DB_PATH, "tables": tables})
    finally:
        conn.close()


@app.route("/api/admin/db/download", methods=["GET"])
@admin_required
def api_admin_db_download():
    """Allow Admin to download the SQLite database file from Render."""
    if not os.path.exists(DB_PATH):
        return jsonify({"error": "Database file not found."}), 404
    return send_file(DB_PATH, as_attachment=True, download_name="network_monitor.db")


@app.route("/api/monitor/scan", methods=["POST"])
@login_required
def api_monitor_scan():
    """Trigger an immediate device probe cycle from the dashboard."""
    try:
        results = _run_safe_scan()
        return jsonify({
            "success": True,
            "probed": len(results),
            "results": [
                {
                    "device": r["device"]["name"],
                    "ip": r["device"]["ip_address"],
                    "status": r["status"],
                    "latency_ms": r["latency_ms"],
                    "timestamp": r["timestamp"],
                }
                for r in results
            ],
        })
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@app.route("/api/agent/devices", methods=["GET"])
def api_agent_devices():
    """Expose configured devices to an authenticated remote monitor.py agent."""
    if not _is_valid_agent_request():
        return jsonify({"error": "Unauthorized monitor agent."}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, ip_address, category, criticality,
               is_maintenance, maintenance_reason,
               latency_threshold_ms, critical_latency_threshold_ms
        FROM devices
        ORDER BY id ASC
    """)
    devices = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"devices": devices})


@app.route("/api/agent/telemetry", methods=["POST"])
def api_agent_telemetry():
    """Ingest probe telemetry pushed by a remote monitor.py agent."""
    if not _is_valid_agent_request():
        return jsonify({"error": "Unauthorized monitor agent."}), 401

    data = request.get_json(force=True) if (request.is_json or request.data) else {}
    probes = data.get("probes", [])
    if not isinstance(probes, list):
        return jsonify({"error": "Invalid payload: 'probes' must be a list."}), 400

    import monitor

    conn = get_db()
    devices = monitor.get_devices(conn)
    devices_by_id = {d["id"]: d for d in devices}
    devices_by_ip = {d["ip_address"]: d for d in devices}

    telegram_enabled = os.environ.get("MONITOR_TELEGRAM_ALERTS", "true").lower() in ("true", "1", "yes")
    events_by_device = {}
    recorded = 0

    try:
        for probe in probes:
            dev = devices_by_id.get(probe.get("device_id")) or devices_by_ip.get(probe.get("ip_address"))
            if not dev:
                continue

            status = "Online" if probe.get("status") == "Online" else "Offline"
            try:
                latency = max(0.0, round(float(probe.get("latency_ms", 0.0)), 2))
            except (TypeError, ValueError):
                latency = 0.0
            ts = str(probe.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))[:19]

            monitor.save_to_db(conn, dev["name"], dev["ip_address"], status, latency, ts)
            recorded += 1

            events = incident_engine.process_device_telemetry(
                conn=conn,
                device=dev,
                status=status,
                latency_ms=latency,
                timestamp=ts,
            )
            if telegram_enabled and events:
                for ev in events:
                    msg = incident_engine.format_telegram_alert(ev)
                    incident_engine.send_telegram_alert_sync(msg)

            events_by_device[str(dev["id"])] = events
    finally:
        conn.close()

    return jsonify({"success": True, "recorded": recorded, "events_by_device": events_by_device})


def _acquire_process_lock() -> bool:
    """
    On Linux/Render, ensure only one Gunicorn worker process runs the background
    monitor loop even if multiple workers are spawned.
    """
    global _process_lock_fd
    if os.name == "nt":
        return True
    try:
        import fcntl
        lock_path = os.path.join("/tmp", "netguard_monitor.lock")
        fd = open(lock_path, "w")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _process_lock_fd = fd
        return True
    except (ImportError, OSError):
        return False


def _background_monitor_loop():
    """Run periodic device probes in the background while the web app is running."""
    interval = max(15, int(os.environ.get("MONITOR_INTERVAL_SECONDS", "60")))
    time.sleep(2)
    while True:
        try:
            _run_safe_scan()
        except Exception as exc:
            print(f"[NetGuard Monitor Thread] Cycle error: {exc}")
        time.sleep(interval)


def start_background_monitor(is_main_entry: bool = False):
    """
    Start the integrated background monitor thread once when running as a web server
    (automatically on Gunicorn/Render, or locally when ENABLE_BACKGROUND_MONITOR=true).
    """
    global _monitor_started
    env_flag = os.environ.get("ENABLE_BACKGROUND_MONITOR", "").strip().lower()
    if env_flag in ("false", "0", "no"):
        return

    is_cloud_server = ("gunicorn" in sys.modules) or (os.environ.get("RENDER", "").lower() == "true")
    if not is_cloud_server and env_flag not in ("true", "1", "yes"):
        return

    if is_main_entry and app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    with _monitor_start_lock:
        if _monitor_started:
            return
        if not _acquire_process_lock():
            return
        _monitor_started = True
        thread = threading.Thread(
            target=_background_monitor_loop,
            name="netguard-bg-monitor",
            daemon=True,
        )
        thread.start()
        print("[NetGuard] Background monitoring thread started.")


# ─────────────────────────────────────────────
#  Start the app
# ─────────────────────────────────────────────

# Initialize DB on load (for Gunicorn / Render production server)
try:
    init_db()
except Exception as _e:
    print(f"[NetGuard] DB init note: {_e}")

if __name__ != "__main__":
    start_background_monitor(is_main_entry=False)

if __name__ == "__main__":
    print("[OK] NetGuard AI running -> http://127.0.0.1:5000")
    app.debug = True
    start_background_monitor(is_main_entry=True)
    app.run(debug=True)