import json
import os
import platform
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from colorama import Fore, Style, init

from dotenv import load_dotenv
import incident_engine

# Load environment configuration (absolute path for PythonAnywhere)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_env_path)

# Initialize Colorama for Windows terminal
init(autoreset=True)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETGUARD_DB_PATH", os.path.join(_BASE_DIR, "network_monitor.db"))
DEFAULT_INTERVAL_SECONDS = int(os.environ.get("MONITOR_INTERVAL_SECONDS", "60"))
TELEGRAM_ALERT_ENABLED = os.environ.get("MONITOR_TELEGRAM_ALERTS", "true").lower() in ("true", "1", "yes")
REMOTE_URL = os.environ.get("NETGUARD_REMOTE_URL", "").strip().rstrip("/")
AGENT_KEY = os.environ.get("MONITOR_SYNC_KEY") or os.environ.get("SECRET_KEY", "")

_ICMP_AVAILABLE = True


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """Create a SQLite connection with Row factory and timeout."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def get_devices(conn: sqlite3.Connection = None) -> list:
    """
    Retrieve all configured devices with their complete attributes:
    category, criticality, is_maintenance, maintenance_reason,
    latency_threshold_ms, and critical_latency_threshold_ms.
    """
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, ip_address, category, criticality,
                   is_maintenance, maintenance_reason,
                   latency_threshold_ms, critical_latency_threshold_ms
            FROM devices
            ORDER BY id ASC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        if rows:
            return rows
    except sqlite3.OperationalError:
        pass
    finally:
        if should_close:
            conn.close()

    # Fallback default seeds if database table is empty or unavailable
    return [
        {
            "id": 1,
            "name": "Google DNS",
            "ip_address": "8.8.8.8",
            "category": "Gateway/Router",
            "criticality": "Medium",
            "is_maintenance": 0,
            "maintenance_reason": None,
            "latency_threshold_ms": 150.0,
            "critical_latency_threshold_ms": 300.0
        },
        {
            "id": 2,
            "name": "Laptop",
            "ip_address": "10.82.186.219",
            "category": "Workstation/Laptop",
            "criticality": "Low",
            "is_maintenance": 0,
            "maintenance_reason": None,
            "latency_threshold_ms": 150.0,
            "critical_latency_threshold_ms": 300.0
        },
        {
            "id": 3,
            "name": "My Phone",
            "ip_address": "10.82.191.10",
            "category": "General Host",
            "criticality": "Low",
            "is_maintenance": 0,
            "maintenance_reason": None,
            "latency_threshold_ms": 150.0,
            "critical_latency_threshold_ms": 300.0
        }
    ]


def _tcp_probe(ip: str, ports: tuple = (443, 80, 53), timeout: float = 1.0) -> tuple:
    """
    Fallback reachability check via TCP handshake for cloud environments
    (like Render) where ICMP ping binary or raw sockets are blocked.
    """
    for port in ports:
        start_time = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                latency = round((time.time() - start_time) * 1000, 2)
                return "Online", latency
        except OSError:
            continue
    return "Offline", 0.0


def ping_device(ip: str) -> tuple:
    """
    Execute ICMP ping probe against target IP address, with TCP fallback
    when ICMP is unavailable or blocked in cloud containers.
    Returns (status: str, latency_ms: float).
    """
    global _ICMP_AVAILABLE
    if not _ICMP_AVAILABLE:
        return _tcp_probe(ip)

    is_windows = platform.system().lower() == 'windows'
    param = '-n' if is_windows else '-c'
    timeout_flag = '-w' if is_windows else '-W'
    timeout_val = '1000' if is_windows else '1'

    start_time = time.time()
    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        end_time = time.time()
        if result.returncode == 0:
            latency = round((end_time - start_time) * 1000, 2)
            return "Online", latency

        stderr_lower = (result.stderr or "").lower()
        if "operation not permitted" in stderr_lower or "socket" in stderr_lower:
            _ICMP_AVAILABLE = False
        return _tcp_probe(ip)
    except (FileNotFoundError, PermissionError):
        _ICMP_AVAILABLE = False
        return _tcp_probe(ip)
    except (subprocess.TimeoutExpired, Exception):
        return _tcp_probe(ip)


def save_to_db(conn: sqlite3.Connection, name: str, ip: str,
               status: str, latency: float, timestamp: str = None):
    """
    Persist ping telemetry log into network_logs table.
    Preserves exact historical schema and device/IP correlation.
    """
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO network_logs (device, ip, status, latency_ms, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (name, ip, status, latency, ts))
    conn.commit()


def _remote_request(path: str, method: str = "GET", payload: dict = None) -> dict:
    """Send an authenticated JSON request to a remote NetGuard dashboard server."""
    url = f"{REMOTE_URL}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"X-Monitor-Key": AGENT_KEY}
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_remote_monitor_cycle(ping_func=None) -> list:
    """
    Fetch monitored devices from REMOTE_URL, probe them from this machine
    (allowing monitoring of private LAN IPs), and push results to the cloud dashboard.
    """
    probe_fn = ping_func or ping_device
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices_resp = _remote_request("/api/agent/devices")
    devices = devices_resp.get("devices", [])

    probes = []
    cycle_results = []
    for dev in devices:
        status, latency = probe_fn(dev["ip_address"])
        warn_th = dev.get("latency_threshold_ms", 150.0)
        crit_th = dev.get("critical_latency_threshold_ms", 300.0)
        condition = incident_engine.evaluate_device_condition(status, latency, warn_th, crit_th)

        probes.append({
            "device_id": dev["id"],
            "name": dev["name"],
            "ip_address": dev["ip_address"],
            "status": status,
            "latency_ms": latency,
            "timestamp": now_str,
        })
        cycle_results.append({
            "device": dev,
            "status": status,
            "latency_ms": latency,
            "condition": condition,
            "events": [],
            "timestamp": now_str,
        })

    if probes:
        ingest_resp = _remote_request("/api/agent/telemetry", method="POST", payload={"probes": probes})
        events_by_dev = ingest_resp.get("events_by_device", {})
        for r in cycle_results:
            dev_id_str = str(r["device"]["id"])
            r["events"] = events_by_dev.get(dev_id_str, [])

    return cycle_results


def run_monitor_cycle(conn: sqlite3.Connection = None, ping_func=None) -> list:
    """
    Execute a single complete monitoring pass across all configured devices:
      1. Fetch device configurations
      2. Probe device reachability and round-trip latency
      3. Persist results in network_logs
      4. Drive incident state machine via incident_engine
      5. Dispatch Telegram notifications if configured
    Returns a summary list of results for each device.
    """
    if conn is None and REMOTE_URL:
        return run_remote_monitor_cycle(ping_func=ping_func)

    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True

    probe_fn = ping_func or ping_device
    cycle_results = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        devices = get_devices(conn)
        for dev in devices:
            name = dev["name"]
            ip = dev["ip_address"]
            warn_th = dev["latency_threshold_ms"]
            crit_th = dev["critical_latency_threshold_ms"]
            is_maint = dev["is_maintenance"]

            # 1. Execute probe
            status, latency = probe_fn(ip)

            # 2. Record telemetry in network_logs
            save_to_db(conn, name, ip, status, latency, now_str)

            # 3. Process incident lifecycle and state transitions
            events = incident_engine.process_device_telemetry(
                conn=conn,
                device=dev,
                status=status,
                latency_ms=latency,
                timestamp=now_str
            )

            # 4. Dispatch Telegram alerts for actionable transitions
            if TELEGRAM_ALERT_ENABLED and events:
                for ev in events:
                    msg = incident_engine.format_telegram_alert(ev)
                    incident_engine.send_telegram_alert_sync(msg)

            # Classify condition for display
            condition = incident_engine.evaluate_device_condition(status, latency, warn_th, crit_th)

            cycle_results.append({
                "device": dev,
                "status": status,
                "latency_ms": latency,
                "condition": condition,
                "events": events,
                "timestamp": now_str
            })

    finally:
        if should_close:
            conn.close()

    return cycle_results


def print_header():
    """Print NOC live monitoring dashboard banner."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Fore.CYAN}{'='*80}")
    print(f"{Fore.YELLOW}   NETGUARD AI — SMART NOC MONITORING AGENT (DEVICE-AWARE)")
    print(f"{Fore.CYAN}{'='*80}")
    print(f"{'TIMESTAMP':<20} | {'DEVICE':<16} | {'CATEGORY':<14} | {'STATUS':<9} | {'LATENCY':<12} | {'INCIDENTS/MODE'}")
    print(f"{'-'*80}")


def display_cycle_results(results: list):
    """Render color-coded tactical NOC output for the cycle."""
    for r in results:
        dev = r["device"]
        status = r["status"]
        lat = r["latency_ms"]
        cond = r["condition"]
        ts = r["timestamp"]
        events = r["events"]

        # Status color
        status_color = Fore.GREEN if status == "Online" else Fore.RED
        status_str = f"{status_color}{status:<9}{Style.RESET_ALL}"

        # Latency text & warning indicator
        if status == "Offline":
            lat_str = f"{Fore.RED}0.0 ms (OFF){Style.RESET_ALL}"
        elif cond == "CRITICAL_LATENCY":
            lat_str = f"{Fore.RED}{lat}ms [CRIT!]{Style.RESET_ALL}"
        elif cond == "WARNING_LATENCY":
            lat_str = f"{Fore.YELLOW}{lat}ms [WARN]{Style.RESET_ALL}"
        else:
            lat_str = f"{Fore.CYAN}{lat}ms (OK){Style.RESET_ALL}"

        # Maintenance and incident badges
        if dev.get("is_maintenance") == 1:
            mode_badge = f"{Fore.YELLOW}[MAINTENANCE MODE]{Style.RESET_ALL}"
        elif events:
            ev_names = ",".join(e["event_type"] for e in events)
            mode_badge = f"{Fore.MAGENTA}⚡ ALERT: {ev_names}{Style.RESET_ALL}"
        elif cond != "NORMAL":
            mode_badge = f"{Fore.RED}ACTIVE INCIDENT{Style.RESET_ALL}"
        else:
            mode_badge = f"{Fore.GREEN}STABLE{Style.RESET_ALL}"

        print(f"{ts:<20} | {dev['name'][:16]:<16} | {dev.get('category','General')[:14]:<14} | {status_str} | {lat_str:<21} | {mode_badge}")


def main():
    """Main continuous monitoring loop."""
    print(f"[NetGuard Monitor] Starting monitoring engine on {DB_PATH}...")
    try:
        while True:
            print_header()
            results = run_monitor_cycle()
            display_cycle_results(results)

            print(f"\n{Fore.BLUE}Next probe cycle in {DEFAULT_INTERVAL_SECONDS} seconds... (Press Ctrl+C to stop)")
            time.sleep(DEFAULT_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print(f"\n{Fore.MAGENTA}Monitoring engine stopped by operator. Telemetry preserved.")


if __name__ == "__main__":
    main()