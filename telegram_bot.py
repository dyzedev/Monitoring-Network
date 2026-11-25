import asyncio
import os
import sqlite3
from datetime import datetime, date

from dotenv import load_dotenv
from groq import Groq
from telegram import Bot, Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)
from telegram.constants import ParseMode

# Import database connection factory from the main web application
from app import get_db  # noqa: E402
import incident_engine

# Load configuration variables from .env file (absolute path for PythonAnywhere)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_env_path)

TELEGRAM_BOT_TOKEN: str = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID:   str = os.environ.get("TELEGRAM_CHAT_ID", "")
GROQ_API_KEY:       str = os.environ.get("GROQ_API_KEY", "")
DEFAULT_LATENCY_THRESHOLD: float = float(os.environ.get("LATENCY_THRESHOLD_MS", "150"))

# Initialize Groq client for AI features
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
GROQ_MODEL  = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

# Tracks the last known status and alert state of every device to prevent duplicate alerts.
device_states: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
#  Security — access control
# ─────────────────────────────────────────────────────────────────────────────

def is_authorized(update: Update) -> bool:
    """
    Validate that the incoming message originates from the configured TELEGRAM_CHAT_ID.
    This prevents unauthorized users from interacting with the bot.
    Called at the top of every command handler before any processing.
    """
    if not TELEGRAM_CHAT_ID:
        return False
    return str(update.effective_chat.id) == str(TELEGRAM_CHAT_ID)


# ─────────────────────────────────────────────────────────────────────────────
#  Network Health Score
# ─────────────────────────────────────────────────────────────────────────────

def calculate_health_score(online: int, offline: int,
                           avg_latency: float,
                           high_latency_incidents: int = 0,
                           total_checks: int = 1) -> dict:
    """
    Compute a 0-100 Network Health Score from device and latency statistics.
    Returns a dict with 'score' (int) and 'label' (str).
    """
    total_devices = online + offline
    if total_devices == 0:
        return {"score": 0, "label": "No Data"}

    # Component 1: Online ratio (0-50 pts)
    online_score = (online / total_devices) * 50

    # Component 2: Latency score (0-30 pts)
    # Perfect at <=50ms, degrades linearly, zero at >=500ms
    clamped_latency = max(0.0, min(avg_latency, 500.0))
    latency_score   = (1 - (clamped_latency - 50) / 450) * 30 if clamped_latency > 50 else 30.0
    latency_score   = max(0.0, latency_score)

    # Component 3: Incident penalty (0-20 pts)
    # Deduct based on how many checks had high latency
    incident_ratio    = min(high_latency_incidents / max(total_checks, 1), 1.0)
    incident_score    = (1 - incident_ratio) * 20

    score = round(online_score + latency_score + incident_score)
    score = max(0, min(score, 100))

    if score >= 90:
        label = "Excellent"
    elif score >= 70:
        label = "Good"
    elif score >= 50:
        label = "Fair"
    elif score >= 25:
        label = "Poor"
    else:
        label = "Critical"

    return {"score": score, "label": label}


# ─────────────────────────────────────────────────────────────────────────────
#  Shared DB query helpers (wrappers around get_db())
# ─────────────────────────────────────────────────────────────────────────────

def db_get_stats() -> dict:
    """
    Fetch aggregate network stats — mirrors the logic in app.py /api/stats.
    Returns online_count, offline_count, avg_latency, overall_status, maintenance_count.
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT AVG(latency_ms)                                      AS avg_latency,
               SUM(CASE WHEN status='Online'  THEN 1 ELSE 0 END)   AS online_count,
               SUM(CASE WHEN status='Offline' THEN 1 ELSE 0 END)   AS offline_count
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
    online  = (row["online_count"] if row else 0) or 0
    offline = (row["offline_count"] if row else 0) or 0
    status  = ("Operational" if offline == 0
               else "Degraded" if online >= offline
               else "Critical")

    # Get device count and maintenance count
    cur.execute("SELECT COUNT(*), SUM(CASE WHEN is_maintenance=1 THEN 1 ELSE 0 END) FROM devices")
    d_row = cur.fetchone()
    total_devices = (d_row[0] if d_row else 0) or 0
    maint_count   = (d_row[1] if d_row else 0) or 0

    conn.close()
    return {
        "avg_latency":       round((row["avg_latency"] if row else 0) or 0, 2),
        "online_count":      online,
        "offline_count":     offline,
        "status":            status,
        "total_devices":     total_devices,
        "maintenance_count": maint_count,
    }


def db_get_latest_per_device() -> list:
    """
    Fetch all configured devices joined with their most recent telemetry log.
    Includes category, criticality, is_maintenance, thresholds, and last ping status.
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT d.id AS device_id, d.name AS device, d.ip_address AS ip,
               d.category, d.criticality, d.is_maintenance, d.maintenance_reason,
               d.latency_threshold_ms, d.critical_latency_threshold_ms,
               COALESCE(nl.status, 'Unknown') AS status,
               COALESCE(nl.latency_ms, 0.0) AS latency_ms,
               COALESCE(nl.timestamp, 'No telemetry') AS timestamp
        FROM devices d
        LEFT JOIN network_logs nl ON nl.id = (
            SELECT MAX(id) FROM network_logs WHERE device = d.name AND ip = d.ip_address
        )
        ORDER BY d.name ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def db_get_today_summary() -> dict:
    """
    Aggregate today's network logs into a compact statistics dictionary.
    This provides metrics for the AI summary generation.
    """
    today = date.today().strftime("%Y-%m-%d")
    conn  = get_db()
    cur   = conn.cursor()

    # Aggregate stats for today
    cur.execute("""
        SELECT
            COUNT(DISTINCT device)                                          AS total_devices,
            SUM(CASE WHEN status = 'Online'  THEN 1 ELSE 0 END)            AS online_checks,
            SUM(CASE WHEN status = 'Offline' THEN 1 ELSE 0 END)            AS offline_checks,
            ROUND(AVG(latency_ms), 2)                                       AS avg_latency,
            ROUND(MAX(latency_ms), 2)                                       AS max_latency,
            SUM(CASE WHEN latency_ms > ? THEN 1 ELSE 0 END)                AS high_latency_events,
            COUNT(*)                                                         AS total_checks
        FROM network_logs
        WHERE timestamp LIKE ?
          AND EXISTS (
              SELECT 1 FROM devices 
              WHERE devices.name = network_logs.device 
                AND devices.ip_address = network_logs.ip
          )
    """, (DEFAULT_LATENCY_THRESHOLD, f"{today}%"))
    row = cur.fetchone()

    # Count offline incidents: transitions from Online -> Offline per device
    cur.execute("""
        SELECT COUNT(*) AS offline_incidents
        FROM (
            SELECT device,
                   status,
                   LAG(status) OVER (PARTITION BY device ORDER BY id) AS prev_status
            FROM network_logs
            WHERE timestamp LIKE ?
              AND EXISTS (
                  SELECT 1 FROM devices 
                  WHERE devices.name = network_logs.device 
                    AND devices.ip_address = network_logs.ip
              )
        ) t
        WHERE status = 'Offline' AND prev_status = 'Online'
    """, (f"{today}%",))
    incident_row = cur.fetchone()

    # Count recovery events: transitions from Offline -> Online per device
    cur.execute("""
        SELECT COUNT(*) AS recovery_events
        FROM (
            SELECT device,
                   status,
                   LAG(status) OVER (PARTITION BY device ORDER BY id) AS prev_status
            FROM network_logs
            WHERE timestamp LIKE ?
              AND EXISTS (
                  SELECT 1 FROM devices 
                  WHERE devices.name = network_logs.device 
                    AND devices.ip_address = network_logs.ip
              )
        ) t
        WHERE status = 'Online' AND prev_status = 'Offline'
    """, (f"{today}%",))
    recovery_row = cur.fetchone()

    conn.close()

    return {
        "date":                today,
        "total_devices":       row["total_devices"]    or 0,
        "online_checks":       row["online_checks"]    or 0,
        "offline_checks":      row["offline_checks"]   or 0,
        "avg_latency":         row["avg_latency"]      or 0.0,
        "max_latency":         row["max_latency"]      or 0.0,
        "high_latency_events": row["high_latency_events"] or 0,
        "total_checks":        row["total_checks"]     or 1,
        "offline_incidents":   incident_row["offline_incidents"]  or 0,
        "recovery_events":     recovery_row["recovery_events"]    or 0,
    }


def db_get_device_logs(device_name: str, limit: int = 30) -> list:
    """
    Fetch the last N log entries for a specific device by name.
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT timestamp, device, ip, status, latency_ms
        FROM network_logs
        WHERE LOWER(device) = LOWER(?)
        ORDER BY id DESC
        LIMIT ?
    """, (device_name, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  AI helpers
# ─────────────────────────────────────────────────────────────────────────────

def ai_diagnose_device(device_name: str, logs: list) -> str:
    """
    Generate an AI diagnosis for a device using its recent logs.
    """
    if not groq_client:
        return "AI diagnostics unavailable: GROQ_API_KEY is not configured."

    if not logs:
        return f"No log data found for device '{device_name}'."

    network_context = f"Recent Network History for {device_name} (Last {len(logs)} events):\n"
    for r in logs:
        network_context += (
            f"- [{r['timestamp']}] {r['device']} ({r['ip']}): "
            f"{r['status']}, {r['latency_ms']}ms\n"
        )

    try:
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are NetGuard AI, an expert network monitoring assistant. "
                        "Analyze the network data and diagnose issues like a senior network engineer. "
                        "Be concise, technical, and professional. "
                        "Format your response clearly for a Telegram message (avoid markdown tables, use plain text)."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Network Data:\n{network_context}\n\n"
                        f"Question: Diagnose the current network condition for {device_name}. "
                        "Identify any issues, patterns, or anomalies and suggest actions."
                    )
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"AI engine error: {str(e)}"


def ai_generate_summary(stats: dict) -> str:
    """
    Generate an AI-powered summary using today's pre-aggregated statistics.
    """
    if not groq_client:
        return "AI summary unavailable: GROQ_API_KEY is not configured."

    if not stats or stats.get("total_checks", 0) == 0:
        return "No network data found for today yet."

    network_context = (
        f"Network Monitoring Summary for {stats['date']}:\n"
        f"- Total monitored devices   : {stats['total_devices']}\n"
        f"- Online checks             : {stats['online_checks']}\n"
        f"- Offline checks            : {stats['offline_checks']}\n"
        f"- Average latency           : {stats['avg_latency']} ms\n"
        f"- Highest recorded latency  : {stats['max_latency']} ms\n"
        f"- Offline incidents         : {stats['offline_incidents']}\n"
        f"- Recovery events           : {stats['recovery_events']}\n"
        f"- High latency events       : {stats['high_latency_events']}\n"
        f"- Total monitoring checks   : {stats['total_checks']}\n"
    )

    try:
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are NetGuard AI, an expert network monitoring assistant. "
                        "You are given a pre-computed statistical summary of today's network activity. "
                        "Based on these statistics, provide a concise professional summary for an operator. "
                        "Highlight any incidents, patterns, or recommendations. "
                        "Format your response clearly for a Telegram message (avoid markdown tables, use plain text)."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Today's Network Statistics:\n{network_context}\n\n"
                        "Please provide a concise summary of today's network performance and any actionable recommendations."
                    )
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"AI engine error: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
#  Bot command handlers
# ─────────────────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/start — Welcome message and command list."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    text = (
        "🛡️ NetGuard AI — Smart Telegram NOC Bot\n"
        "═══════════════════════════════════════\n\n"
        "Connected to live NetGuard monitoring engine.\n\n"
        "📋 Available Commands:\n"
        "  /status        — Network health, active counts & score\n"
        "  /devices       — Monitored hosts with category & thresholds\n"
        "  /diagnose <name> — AI-assisted device diagnostics\n"
        "  /summary       — AI operational summary for today\n"
        "  /help          — Command reference & alert policy\n\n"
        "🔔 Smart alerts active with per-device thresholds and maintenance suppression."
    )
    await update.message.reply_text(text)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/help — Detailed explanation of every command and alert policies."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    text = (
        "🛡️ NetGuard AI — Command Reference\n"
        "════════════════════════════════════\n\n"
        "📊 /status\n"
        "Shows overall network health: online/offline device count, devices in\n"
        "maintenance mode, average latency, and 0-100 Network Health Score.\n\n"
        "🖥️ /devices\n"
        "Lists every configured device with category, criticality rating, latency\n"
        "thresholds, and current status (🟢 Online, 🔴 Offline, 🔧 Maintenance).\n\n"
        "🔍 /diagnose <device_name>\n"
        "Runs an AI-powered diagnostic for the specified host using recent telemetry.\n"
        "Example: /diagnose Google DNS\n\n"
        "📝 /summary\n"
        "Generates an AI summary of today's network performance, incidents, and score.\n\n"
        "🔔 Smart Alert Policy\n"
        "  🔴 Device Offline: Alert dispatched on outage detection.\n"
        "  🟢 Device Online: Recovery alert dispatched on restoration.\n"
        "  🟡 Warning Latency: Dispatched when exceeding device warning threshold.\n"
        "  💥 Critical Latency: Escalation alert dispatched when exceeding critical threshold.\n"
        "  🔧 Maintenance Mode: All alerts are suppressed during active maintenance windows.\n"
        "Alerts are de-duplicated — you are notified once per state transition."
    )
    await update.message.reply_text(text)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/status — Current network status + health score + maintenance counts."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    await update.message.reply_text("⏳ Fetching network telemetry status...")
    try:
        stats = db_get_stats()

        status_emoji = {
            "Operational": "🟢",
            "Degraded":    "🟡",
            "Critical":    "🔴",
        }.get(stats["status"], "❓")

        health = calculate_health_score(
            online=stats["online_count"],
            offline=stats["offline_count"],
            avg_latency=stats["avg_latency"],
        )

        text = (
            f"📊 Network Status — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            "══════════════════════════════════\n\n"
            f"🟢  Online devices:      {stats['online_count']}\n"
            f"🔴  Offline devices:     {stats['offline_count']}\n"
            f"🔧  In Maintenance:      {stats['maintenance_count']}\n"
            f"📡  Average latency:     {stats['avg_latency']} ms\n"
            f"{status_emoji}  Overall status:      {stats['status']}\n\n"
            f"💯  Network Health:      {health['score']}%\n"
            f"    Evaluation:          {health['label']}"
        )
    except Exception as e:
        text = f"❌ Failed to fetch status: {str(e)}"

    await update.message.reply_text(text)


async def cmd_devices(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/devices — List all configured devices with category, criticality, and thresholds."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    await update.message.reply_text("⏳ Fetching monitored device inventory...")
    try:
        devices = db_get_latest_per_device()
        if not devices:
            await update.message.reply_text("⚠️ No device data found in the database yet.")
            return

        lines = [
            f"🖥️ Monitored Devices — {datetime.now().strftime('%H:%M:%S')}\n"
            "══════════════════════════════════\n"
        ]
        for d in devices:
            is_maint = d.get("is_maintenance") == 1
            status = d["status"]
            latency = d["latency_ms"]
            warn_th = d.get("latency_threshold_ms", 150.0)
            crit_th = d.get("critical_latency_threshold_ms", 300.0)

            if is_maint:
                status_icon = "🔧"
                mode_str = " [MAINTENANCE]"
            elif status == "Online":
                status_icon = "🟢"
                mode_str = ""
            else:
                status_icon = "🔴"
                mode_str = ""

            latency_str = f"{latency} ms"
            if status == "Online":
                if latency >= crit_th:
                    latency_str += f" 🔴 CRIT (>{crit_th}ms)"
                elif latency >= warn_th:
                    latency_str += f" ⚠️ WARN (>{warn_th}ms)"
                else:
                    latency_str += " (Normal)"

            crit_badge = f"[{d.get('criticality', 'Medium')}]"
            cat_badge = d.get('category', 'General')

            lines.append(
                f"{status_icon} {d['device']}{mode_str} {crit_badge}\n"
                f"   Category: {cat_badge}\n"
                f"   IP:       {d['ip']}\n"
                f"   Status:   {status}\n"
                f"   Latency:  {latency_str}\n"
                f"   Limits:   Warn: {warn_th}ms | Crit: {crit_th}ms\n"
                f"   Checked:  {d['timestamp']}\n"
            )
        await update.message.reply_text("\n".join(lines))
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch devices: {str(e)}")


async def cmd_diagnose(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/diagnose <device_name> — AI diagnosis for a specific device."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    if not context.args:
        await update.message.reply_text(
            "⚠️ Please specify a device name.\n"
            "Usage: /diagnose Google DNS"
        )
        return

    device_name = " ".join(context.args)
    await update.message.reply_text(
        f"🔍 Running AI diagnosis for '{device_name}'...\n⏳ This may take a moment."
    )

    try:
        logs = db_get_device_logs(device_name, limit=30)
        if not logs:
            await update.message.reply_text(
                f"⚠️ No log data found for device '{device_name}'.\n"
                "Check the device name and try again. Use /devices to see available devices."
            )
            return

        diagnosis = ai_diagnose_device(device_name, logs)
        header    = f"🔍 AI Diagnosis — {device_name}\n══════════════════════════════════\n\n"
        full_text = header + diagnosis

        if len(full_text) > 4000:
            await update.message.reply_text(header + diagnosis[:3900] + "\n\n[truncated]")
        else:
            await update.message.reply_text(full_text)
    except Exception as e:
        await update.message.reply_text(f"❌ Diagnosis failed: {str(e)}")


async def cmd_summary(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/summary — AI-powered summary of today's network activity."""
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized access.")
        return

    await update.message.reply_text(
        "📝 Generating AI network summary for today...\n⏳ This may take a moment."
    )
    try:
        stats   = db_get_today_summary()
        summary = ai_generate_summary(stats)

        total_devices  = max(stats["total_devices"], 1)
        online_devices = total_devices if stats["offline_checks"] == 0 else max(
            total_devices - (1 if stats["offline_incidents"] > 0 else 0), 0
        )
        health = calculate_health_score(
            online=online_devices,
            offline=total_devices - online_devices,
            avg_latency=stats["avg_latency"],
            high_latency_incidents=stats["high_latency_events"],
            total_checks=stats["total_checks"],
        )

        header = (
            f"📝 Network Summary — {stats['date']}\n"
            "══════════════════════════════════\n\n"
            f"💯 Network Health: {health['score']}% — {health['label']}\n"
            "──────────────────────────────────\n"
        )
        full_text = header + summary

        if len(full_text) > 4000:
            await update.message.reply_text(header + summary[:3900] + "\n\n[truncated]")
        else:
            await update.message.reply_text(full_text)
    except Exception as e:
        await update.message.reply_text(f"❌ Summary failed: {str(e)}")


# ─────────────────────────────────────────────────────────────────────────────
#  Smart Notification Loop
# ─────────────────────────────────────────────────────────────────────────────

async def notification_loop(bot: Bot) -> None:
    """
    Background asyncio task that polls device statuses every 60 seconds.
    Applies per-device warning and critical thresholds, respects maintenance mode,
    and deduplicates alerts across state transitions.
    """
    print("[NetGuard Bot] Smart notification loop initialized.")
    while True:
        try:
            devices = db_get_latest_per_device()
            for d in devices:
                name     = d["device"]
                status   = d["status"]
                latency  = d["latency_ms"]
                is_maint = int(d.get("is_maintenance", 0))
                warn_th  = float(d.get("latency_threshold_ms", 150.0))
                crit_th  = float(d.get("critical_latency_threshold_ms", 300.0))

                # Skip devices with no recorded telemetry
                if status == "Unknown":
                    continue

                # Maintenance Mode: suppress alerts and reset tracking so maintenance exit is clean
                if is_maint == 1:
                    device_states[name] = {
                        "state": "MAINTENANCE",
                        "latency_state": "MAINTENANCE"
                    }
                    continue

                cond = incident_engine.evaluate_device_condition(status, latency, warn_th, crit_th)
                prev = device_states.get(name)

                # First time seeing device: record initial baseline, no alert
                if prev is None:
                    device_states[name] = {
                        "state": cond,
                        "latency_state": cond if cond in ("WARNING_LATENCY", "CRITICAL_LATENCY") else "NORMAL"
                    }
                    continue

                prev_state     = prev.get("state", "NORMAL")
                prev_lat_state = prev.get("latency_state", "NORMAL")

                # ── State Transition: Device Goes Offline ─────────────────
                if cond == "OFFLINE" and prev_state != "OFFLINE":
                    event = {
                        "event_type": "NEW_OFFLINE",
                        "device": {
                            "name": d["device"],
                            "ip_address": d["ip"],
                            "category": d.get("category", "General"),
                            "criticality": d.get("criticality", "Medium")
                        },
                        "timestamp": d["timestamp"]
                    }
                    msg = incident_engine.format_telegram_alert(event)
                    await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
                    device_states[name] = {
                        "state": "OFFLINE",
                        "latency_state": "OFFLINE"
                    }
                    continue

                # ── State Transition: Device Recovers from Offline ────────
                if prev_state == "OFFLINE" and cond != "OFFLINE":
                    event = {
                        "event_type": "OFFLINE_RECOVERY",
                        "device": {
                            "name": d["device"],
                            "ip_address": d["ip"],
                            "category": d.get("category", "General"),
                            "criticality": d.get("criticality", "Medium")
                        },
                        "latency_ms": latency,
                        "timestamp": d["timestamp"]
                    }
                    msg = incident_engine.format_telegram_alert(event)
                    await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
                    prev_lat_state = "NORMAL"

                # ── Latency State Transitions (Online Devices) ────────────
                if cond == "CRITICAL_LATENCY":
                    if prev_lat_state == "WARNING_LATENCY":
                        # Escalation from Warning to Critical
                        event = {
                            "event_type": "LATENCY_ESCALATION",
                            "device": {
                                "name": d["device"],
                                "ip_address": d["ip"],
                                "category": d.get("category", "General"),
                                "criticality": d.get("criticality", "Medium")
                            },
                            "latency_ms": latency,
                            "threshold_ms": crit_th,
                            "timestamp": d["timestamp"]
                        }
                        msg = incident_engine.format_telegram_alert(event)
                        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
                        device_states[name] = {"state": "CRITICAL_LATENCY", "latency_state": "CRITICAL_LATENCY"}

                    elif prev_lat_state != "CRITICAL_LATENCY":
                        # New Critical Latency breach
                        event = {
                            "event_type": "NEW_CRITICAL_LATENCY",
                            "device": {
                                "name": d["device"],
                                "ip_address": d["ip"],
                                "category": d.get("category", "General"),
                                "criticality": d.get("criticality", "Medium")
                            },
                            "latency_ms": latency,
                            "threshold_ms": crit_th,
                            "timestamp": d["timestamp"]
                        }
                        msg = incident_engine.format_telegram_alert(event)
                        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
                        device_states[name] = {"state": "CRITICAL_LATENCY", "latency_state": "CRITICAL_LATENCY"}
                    else:
                        # Deduplicated: ongoing critical latency
                        device_states[name] = {"state": "CRITICAL_LATENCY", "latency_state": "CRITICAL_LATENCY"}

                elif cond == "WARNING_LATENCY":
                    if prev_lat_state not in ("WARNING_LATENCY", "CRITICAL_LATENCY"):
                        # New Warning Latency breach
                        event = {
                            "event_type": "NEW_WARNING_LATENCY",
                            "device": {
                                "name": d["device"],
                                "ip_address": d["ip"],
                                "category": d.get("category", "General"),
                                "criticality": d.get("criticality", "Medium")
                            },
                            "latency_ms": latency,
                            "threshold_ms": warn_th,
                            "timestamp": d["timestamp"]
                        }
                        msg = incident_engine.format_telegram_alert(event)
                        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
                        device_states[name] = {"state": "WARNING_LATENCY", "latency_state": "WARNING_LATENCY"}
                    else:
                        # Deduplicated: ongoing warning latency
                        device_states[name] = {"state": "WARNING_LATENCY", "latency_state": prev_lat_state}

                elif cond == "NORMAL":
                    if prev_lat_state in ("WARNING_LATENCY", "CRITICAL_LATENCY"):
                        # Latency Normalized Recovery alert
                        event = {
                            "event_type": "LATENCY_RECOVERY",
                            "device": {
                                "name": d["device"],
                                "ip_address": d["ip"],
                                "category": d.get("category", "General"),
                                "criticality": d.get("criticality", "Medium")
                            },
                            "latency_ms": latency,
                            "threshold_ms": warn_th,
                            "timestamp": d["timestamp"]
                        }
                        msg = incident_engine.format_telegram_alert(event)
                        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)

                    device_states[name] = {"state": "NORMAL", "latency_state": "NORMAL"}

        except Exception as e:
            print(f"[NetGuard Bot] Notification loop error: {e}")

        await asyncio.sleep(60)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Build and run the Telegram bot application."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise ValueError("[NetGuard Bot] TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in .env")

    print("[NetGuard Bot] Starting Telegram bot service...")
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start",    cmd_start))
    application.add_handler(CommandHandler("help",     cmd_help))
    application.add_handler(CommandHandler("status",   cmd_status))
    application.add_handler(CommandHandler("devices",  cmd_devices))
    application.add_handler(CommandHandler("device",   cmd_devices))
    application.add_handler(CommandHandler("diagnose", cmd_diagnose))
    application.add_handler(CommandHandler("summary",  cmd_summary))

    async def post_init(app: Application) -> None:
        asyncio.create_task(notification_loop(app.bot))
        print("[NetGuard Bot] Notification background task scheduled.")

    application.post_init = post_init
    print("[NetGuard Bot] Bot is running. Press Ctrl+C to stop.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
