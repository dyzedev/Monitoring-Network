"""
incident_engine.py -- Smart Incident Lifecycle & Alert Engine for NetGuard AI
=============================================================================
Manages state transitions, incident deduplication, escalation, recovery,
and Telegram alert formatting using each device's configuration:
  - category
  - criticality (Low, Medium, High, Critical)
  - is_maintenance (0 or 1) & maintenance_reason
  - latency_threshold_ms (Warning threshold)
  - critical_latency_threshold_ms (Critical threshold)
"""

import json
import logging
import os
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime

logger = logging.getLogger("NetGuard.IncidentEngine")

# Valid severities and statuses matching database constraints
VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VALID_STATUSES = ["Open", "Acknowledged", "Resolved"]


def evaluate_device_condition(status: str, latency_ms: float,
                              warn_threshold: float,
                              crit_threshold: float) -> str:
    """
    Classify observed device telemetry into one of four standard conditions:
      - OFFLINE: Ping probe failed
      - CRITICAL_LATENCY: Measured latency >= critical threshold
      - WARNING_LATENCY: Measured latency >= warning threshold
      - NORMAL: Device online and within normal threshold
    """
    if str(status).strip().lower() == "offline":
        return "OFFLINE"
    
    try:
        lat = float(latency_ms)
        crit = float(crit_threshold)
        warn = float(warn_threshold)
    except (ValueError, TypeError):
        lat = 0.0
        crit = 300.0
        warn = 150.0

    if lat >= crit:
        return "CRITICAL_LATENCY"
    elif lat >= warn:
        return "WARNING_LATENCY"
    else:
        return "NORMAL"


def get_incident_severity_for_outage(device_criticality: str) -> str:
    """
    Maps device criticality to outage incident severity.
    Critical -> Critical, High -> High, Medium -> Medium, Low -> Low.
    """
    crit = str(device_criticality or "Medium").capitalize()
    return crit if crit in VALID_SEVERITIES else "Medium"


def process_device_telemetry(conn: sqlite3.Connection, device: dict,
                             status: str, latency_ms: float,
                             timestamp: str = None) -> list:
    """
    Process telemetry for a single device, enforce incident lifecycle transitions,
    and return a list of actionable notification events.

    Lifecycle transitions handled:
      1. Maintenance Mode (is_maintenance == 1):
         - Continues recording network logs (handled by caller).
         - Suppresses NEW outage and latency incident creation.
         - Suppresses alert event dispatching.
      2. Device Offline:
         - If already active offline incident: DEDUPLICATED (retains existing incident).
         - If new outage: Creates incident in 'incidents' table with 'Open' status
           and logs to 'incident_timeline'. Generates NEW_OFFLINE event.
         - Resolves any stale latency incidents.
      3. Critical Latency (latency >= critical_threshold):
         - If active offline incident exists: Resolves it (device back online).
         - If active latency incident exists:
           - If not already Critical: ESCALATES severity to 'Critical', updates summary,
             adds timeline record, generates LATENCY_ESCALATION event.
           - If already Critical: DEDUPLICATED (retains existing incident).
         - If no active latency incident: Creates incident with 'Critical' severity,
           adds timeline record, generates NEW_CRITICAL_LATENCY event.
      4. Warning Latency (warn_threshold <= latency < crit_threshold):
         - If active offline incident exists: Resolves it (device back online).
         - If active latency incident exists: DEDUPLICATED.
         - If no active latency incident: Creates incident with 'High' or 'Medium' severity,
           adds timeline record, generates NEW_WARNING_LATENCY event.
      5. Normal Latency (latency < warn_threshold):
         - If active offline incident exists: Resolves it (device recovered),
           adds timeline record, generates OFFLINE_RECOVERY event.
         - If active latency incident exists: Resolves it (latency normalized),
           adds timeline record, generates LATENCY_RECOVERY event.
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_id = device.get("id")
    device_name = device.get("name", "Unknown Device")
    ip_address = device.get("ip_address", "Unknown IP")
    category = device.get("category", "General")
    criticality = device.get("criticality", "Medium")
    is_maintenance = int(device.get("is_maintenance", 0))
    maint_reason = device.get("maintenance_reason")
    warn_thresh = float(device.get("latency_threshold_ms", 150.0))
    crit_thresh = float(device.get("critical_latency_threshold_ms", 300.0))

    condition = evaluate_device_condition(status, latency_ms, warn_thresh, crit_thresh)
    events = []

    cur = conn.cursor()

    # Query active incidents for this device (Open or Acknowledged)
    cur.execute("""
        SELECT id, device_id, incident_type, severity, status, summary, started_at
        FROM incidents
        WHERE device_id = ? AND status IN ('Open', 'Acknowledged')
        ORDER BY id DESC
    """, (device_id,))
    active_incidents = [dict(r) for r in cur.fetchall()]

    active_offline = next((inc for inc in active_incidents if inc["incident_type"] == "Device Offline"), None)
    active_latency = next((inc for inc in active_incidents if inc["incident_type"] in ("High Latency", "Critical Latency")), None)

    # ─────────────────────────────────────────────────────────────
    # CASE A: MAINTENANCE MODE ACTIVE
    # ─────────────────────────────────────────────────────────────
    if is_maintenance == 1:
        # Maintenance mode suppresses NEW outage and latency incident creation and alerts
        # If healthy, we still resolve any pre-maintenance incidents
        if condition == "NORMAL":
            if active_offline:
                cur.execute("""
                    UPDATE incidents
                    SET status = 'Resolved', resolved_at = ?,
                        resolution_notes = 'Device recovered during maintenance window.'
                    WHERE id = ?
                """, (timestamp, active_offline["id"]))
                cur.execute("""
                    INSERT INTO incident_timeline (incident_id, source, message, created_at)
                    VALUES (?, 'system', 'Device confirmed online during maintenance window.', ?)
                """, (active_offline["id"], timestamp))

            if active_latency:
                cur.execute("""
                    UPDATE incidents
                    SET status = 'Resolved', resolved_at = ?,
                        resolution_notes = 'Latency normalized during maintenance window.'
                    WHERE id = ?
                """, (timestamp, active_latency["id"]))
                cur.execute("""
                    INSERT INTO incident_timeline (incident_id, source, message, created_at)
                    VALUES (?, 'system', 'Latency normalized during maintenance window.', ?)
                """, (active_latency["id"], timestamp))

        conn.commit()
        return []

    # ─────────────────────────────────────────────────────────────
    # CASE B: DEVICE IS OFFLINE
    # ─────────────────────────────────────────────────────────────
    if condition == "OFFLINE":
        # Resolve active latency incident if any (since state transitioned to offline)
        if active_latency:
            cur.execute("""
                UPDATE incidents
                SET status = 'Resolved', resolved_at = ?,
                    resolution_notes = 'Superseded: Device transitioned to Offline state.'
                WHERE id = ?
            """, (timestamp, active_latency["id"]))
            cur.execute("""
                INSERT INTO incident_timeline (incident_id, source, message, created_at)
                VALUES (?, 'system', 'Latency incident closed as device went offline.', ?)
            """, (active_latency["id"], timestamp))

        if active_offline:
            # Deduplication: Outage is ongoing. Keep active record without duplicate insertion.
            conn.commit()
            return []

        # Create new offline incident
        severity = get_incident_severity_for_outage(criticality)
        summary = (
            f"Device '{device_name}' ({ip_address}) is offline. "
            f"Automated ping probe failed."
        )
        cur.execute("""
            INSERT INTO incidents (
                device_id, incident_type, severity, status, summary,
                started_at, created_at
            ) VALUES (?, 'Device Offline', ?, 'Open', ?, ?, ?)
        """, (device_id, severity, summary, timestamp, timestamp))
        inc_id = cur.lastrowid

        cur.execute("""
            INSERT INTO incident_timeline (incident_id, source, message, created_at)
            VALUES (?, 'system', ?, ?)
        """, (
            inc_id,
            f"Automated probe detected device went offline. "
            f"(Category: {category}, Criticality: {criticality})",
            timestamp
        ))
        conn.commit()

        events.append({
            "event_type": "NEW_OFFLINE",
            "incident_id": inc_id,
            "device": device,
            "severity": severity,
            "latency_ms": latency_ms,
            "timestamp": timestamp
        })
        return events

    # ─────────────────────────────────────────────────────────────
    # CASE C: DEVICE IS ONLINE (Resolve offline incident if existed)
    # ─────────────────────────────────────────────────────────────
    if active_offline:
        # Device recovered to online state
        cur.execute("""
            UPDATE incidents
            SET status = 'Resolved', resolved_at = ?,
                resolution_notes = ?
            WHERE id = ?
        """, (
            timestamp,
            f"Device recovered to online state. Probe measured latency: {latency_ms} ms.",
            active_offline["id"]
        ))
        cur.execute("""
            INSERT INTO incident_timeline (incident_id, source, message, created_at)
            VALUES (?, 'system', ?, ?)
        """, (
            active_offline["id"],
            f"Automated probe confirmed device '{device_name}' recovered and is online "
            f"(latency: {latency_ms} ms).",
            timestamp
        ))
        events.append({
            "event_type": "OFFLINE_RECOVERY",
            "incident_id": active_offline["id"],
            "device": device,
            "latency_ms": latency_ms,
            "timestamp": timestamp
        })

    # ─────────────────────────────────────────────────────────────
    # CASE D: CRITICAL LATENCY (latency >= crit_thresh)
    # ─────────────────────────────────────────────────────────────
    if condition == "CRITICAL_LATENCY":
        if active_latency:
            if active_latency["severity"] != "Critical":
                # Escalation from Warning to Critical
                cur.execute("""
                    UPDATE incidents
                    SET severity = 'Critical',
                        summary = ?
                    WHERE id = ?
                """, (
                    f"Critical latency on '{device_name}' ({ip_address}): "
                    f"{latency_ms} ms exceeds critical threshold ({crit_thresh} ms).",
                    active_latency["id"]
                ))
                cur.execute("""
                    INSERT INTO incident_timeline (incident_id, source, message, created_at)
                    VALUES (?, 'system', ?, ?)
                """, (
                    active_latency["id"],
                    f"Latency escalated to Critical: probe measured {latency_ms} ms "
                    f"(critical threshold: {crit_thresh} ms, warning threshold: {warn_thresh} ms).",
                    timestamp
                ))
                conn.commit()

                events.append({
                    "event_type": "LATENCY_ESCALATION",
                    "incident_id": active_latency["id"],
                    "device": device,
                    "latency_ms": latency_ms,
                    "threshold_ms": crit_thresh,
                    "timestamp": timestamp
                })
                return events
            else:
                # Deduplication: already active critical latency incident
                conn.commit()
                return events
        else:
            # Create new Critical Latency incident
            summary = (
                f"Critical latency on '{device_name}' ({ip_address}): "
                f"{latency_ms} ms exceeds critical threshold ({crit_thresh} ms)."
            )
            cur.execute("""
                INSERT INTO incidents (
                    device_id, incident_type, severity, status, summary,
                    started_at, created_at
                ) VALUES (?, 'High Latency', 'Critical', 'Open', ?, ?, ?)
            """, (device_id, summary, timestamp, timestamp))
            inc_id = cur.lastrowid

            cur.execute("""
                INSERT INTO incident_timeline (incident_id, source, message, created_at)
                VALUES (?, 'system', ?, ?)
            """, (
                inc_id,
                f"Automated probe detected critical latency of {latency_ms} ms "
                f"(critical threshold: {crit_thresh} ms, warning threshold: {warn_thresh} ms).",
                timestamp
            ))
            conn.commit()

            events.append({
                "event_type": "NEW_CRITICAL_LATENCY",
                "incident_id": inc_id,
                "device": device,
                "latency_ms": latency_ms,
                "threshold_ms": crit_thresh,
                "timestamp": timestamp
            })
            return events

    # ─────────────────────────────────────────────────────────────
    # CASE E: WARNING LATENCY (warn_thresh <= latency < crit_thresh)
    # ─────────────────────────────────────────────────────────────
    if condition == "WARNING_LATENCY":
        if active_latency:
            # Deduplication: already open latency incident
            conn.commit()
            return events
        else:
            # Create new Warning Latency incident
            severity = "High" if criticality in ("Critical", "High") else "Medium"
            summary = (
                f"Elevated latency on '{device_name}' ({ip_address}): "
                f"{latency_ms} ms exceeds warning threshold ({warn_thresh} ms)."
            )
            cur.execute("""
                INSERT INTO incidents (
                    device_id, incident_type, severity, status, summary,
                    started_at, created_at
                ) VALUES (?, 'High Latency', ?, 'Open', ?, ?, ?)
            """, (device_id, severity, summary, timestamp, timestamp))
            inc_id = cur.lastrowid

            cur.execute("""
                INSERT INTO incident_timeline (incident_id, source, message, created_at)
                VALUES (?, 'system', ?, ?)
            """, (
                inc_id,
                f"Automated probe detected elevated latency of {latency_ms} ms "
                f"(warning threshold: {warn_thresh} ms).",
                timestamp
            ))
            conn.commit()

            events.append({
                "event_type": "NEW_WARNING_LATENCY",
                "incident_id": inc_id,
                "device": device,
                "latency_ms": latency_ms,
                "threshold_ms": warn_thresh,
                "timestamp": timestamp
            })
            return events

    # ─────────────────────────────────────────────────────────────
    # CASE F: NORMAL LATENCY (latency < warn_thresh)
    # ─────────────────────────────────────────────────────────────
    if condition == "NORMAL":
        if active_latency:
            # Latency resolved back to normal range
            cur.execute("""
                UPDATE incidents
                SET status = 'Resolved', resolved_at = ?,
                    resolution_notes = ?
                WHERE id = ?
            """, (
                timestamp,
                f"Latency normalized to {latency_ms} ms (below warning threshold {warn_thresh} ms).",
                active_latency["id"]
            ))
            cur.execute("""
                INSERT INTO incident_timeline (incident_id, source, message, created_at)
                VALUES (?, 'system', ?, ?)
            """, (
                active_latency["id"],
                f"Automated probe confirmed latency normalized to {latency_ms} ms "
                f"(warning threshold: {warn_thresh} ms).",
                timestamp
            ))
            events.append({
                "event_type": "LATENCY_RECOVERY",
                "incident_id": active_latency["id"],
                "device": device,
                "latency_ms": latency_ms,
                "threshold_ms": warn_thresh,
                "timestamp": timestamp
            })

        conn.commit()
        return events

    conn.commit()
    return events


def format_telegram_alert(event: dict) -> str:
    """
    Format incident events into rich NOC-themed Telegram alerts.
    Includes device name, IP address, category, criticality, observed condition,
    measured latency, thresholds, and timestamp.
    NEVER includes bot tokens, API keys, or database secrets.
    """
    event_type = event.get("event_type", "UNKNOWN")
    device = event.get("device", {})
    name = device.get("name", "Unknown Device")
    ip = device.get("ip_address", "Unknown IP")
    cat = device.get("category", "General")
    crit = device.get("criticality", "Medium")
    ts = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    latency = event.get("latency_ms", 0.0)
    thresh = event.get("threshold_ms", 0.0)

    if event_type == "NEW_OFFLINE":
        return (
            "🚨 ALERT — Device Offline\n"
            "════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🔴  Condition:    Offline (Probe Failed)\n"
            f"🕐  Timestamp:    {ts}"
        )

    elif event_type == "OFFLINE_RECOVERY":
        return (
            "✅ RECOVERY — Device Back Online\n"
            "════════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🟢  Condition:    Online (Recovered)\n"
            f"📡  Latency:      {latency} ms\n"
            f"🕐  Timestamp:    {ts}"
        )

    elif event_type == "NEW_WARNING_LATENCY":
        return (
            "⚠️ ALERT — Elevated Latency\n"
            "════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🟡  Condition:    Warning Threshold Exceeded\n"
            f"📡  Latency:      {latency} ms\n"
            f"🎯  Threshold:    {thresh} ms (Warning)\n"
            f"🕐  Timestamp:    {ts}"
        )

    elif event_type == "NEW_CRITICAL_LATENCY":
        return (
            "🚨 ALERT — Critical Latency Outage\n"
            "═══════════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🔴  Condition:    Critical Threshold Exceeded\n"
            f"📡  Latency:      {latency} ms\n"
            f"💥  Threshold:    {thresh} ms (Critical)\n"
            f"🕐  Timestamp:    {ts}"
        )

    elif event_type == "LATENCY_ESCALATION":
        return (
            "🚨 ESCALATION — Critical Latency\n"
            "════════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🔴  Condition:    Escalated to Critical Outage\n"
            f"📡  Latency:      {latency} ms\n"
            f"💥  Critical Max: {thresh} ms\n"
            f"🕐  Timestamp:    {ts}"
        )

    elif event_type == "LATENCY_RECOVERY":
        return (
            "✅ RECOVERY — Latency Normalized\n"
            "════════════════════════════════\n"
            f"🖥️  Device:       {name}\n"
            f"🌐  IP Address:   {ip}\n"
            f"🏷️  Category:     {cat}\n"
            f"⚡  Criticality:  {crit}\n"
            "🟢  Condition:    Normal Response Time\n"
            f"📡  Latency:      {latency} ms (within {thresh} ms limit)\n"
            f"🕐  Timestamp:    {ts}"
        )

    return f"ℹ️ NetGuard Notice: {name} ({ip}) telemetry update at {ts}."


def send_telegram_alert_sync(message: str, bot_token: str = None, chat_id: str = None) -> bool:
    """
    Synchronously dispatch a Telegram notification via HTTP POST.
    Handles network errors gracefully and never raises exceptions that would halt monitoring.
    """
    token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN")
    cid = chat_id or os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not cid:
        logger.warning("Telegram dispatch skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured.")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({"chat_id": str(cid), "text": message}).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            return resp.status == 200
    except Exception as e:
        logger.warning(f"Telegram notification dispatch error: {e}")
        return False
