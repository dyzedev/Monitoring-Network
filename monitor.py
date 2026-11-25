import os
import platform
import sqlite3
import time
from datetime import datetime
from colorama import Fore, Style, init

from dotenv import load_dotenv
import incident_engine

# Load environment configuration (absolute path for PythonAnywhere)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_env_path)

# Initialize Colorama for Windows terminal
init(autoreset=True)

# Use absolute path so PythonAnywhere scheduled tasks find the database
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETGUARD_DB_PATH", os.path.join(_BASE_DIR, "network_monitor.db"))
DEFAULT_INTERVAL_SECONDS = int(os.environ.get("MONITOR_INTERVAL_SECONDS", "60"))
TELEGRAM_ALERT_ENABLED = os.environ.get("MONITOR_TELEGRAM_ALERTS", "true").lower() in ("true", "1", "yes")


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


def ping_device(ip: str) -> tuple:
    """
    Execute ICMP ping probe against target IP address.
    Returns (status: str, latency_ms: float).
    status: 'Online' or 'Offline'.
    latency_ms: round-trip time in milliseconds.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Wait maximum 1000ms for response
    # Use subprocess ping (works on both local and PythonAnywhere)
    import subprocess
    timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    redirect = 'nul' if platform.system().lower() == 'windows' else '/dev/null'

    start_time = time.time()
    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        end_time = time.time()
        if result.returncode == 0:
            latency = round((end_time - start_time) * 1000, 2)
            return "Online", latency
        else:
            return "Offline", 0.0
    except (subprocess.TimeoutExpired, Exception):
        return "Offline", 0.0


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