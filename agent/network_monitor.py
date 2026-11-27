r"""
ThreatLens â€” Endpoint Network Monitor Agent
agent/network_monitor.py

Run with venv python:
  E:\Project\ThreatLens\.venv\Scripts\python agent\network_monitor.py
"""

import ipaddress
import sys
import psutil
import time
import requests
import socket
import os
import platform
from datetime import datetime, timezone

try:
    import winreg  # Windows only; used to read installed programs
except ImportError:
    winreg = None

# â”€â”€ Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
API_BASE       = "http://127.0.0.1:8000"
INCIDENTS_URL  = f"{API_BASE}/api/incidents"
CHECK_IP_URL   = f"{API_BASE}/api/check-ip"
ASSETS_URL     = f"{API_BASE}/api/assets"
POLL_INTERVAL  = 10      # seconds between scans
DEDUP_TTL      = 300     # seconds before the same IP can re-alert (5 min)
CHECK_TTL      = 600     # seconds before asking the backend about the same IP again

HOSTNAME = socket.gethostname()

# Ports considered normal â€” connections to these are not flagged
BENIGN_PORTS = {80, 443, 22, 3389, 53, 123, 8000, 5173}

# â”€â”€ Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# { ip: last_reported_timestamp }
_seen: dict[str, float] = {}
_checked: dict[str, float] = {}  # every IP asked about, malicious or not

def _already_reported(ip: str) -> bool:
    last = _seen.get(ip)
    if last and (time.time() - last) < DEDUP_TTL:
        return True
    return False

def _mark_reported(ip: str):
    _seen[ip] = time.time()

def _evict_stale():
    """Remove expired entries so the dict doesn't grow forever."""
    now = time.time()
    stale = [ip for ip, ts in _seen.items() if (now - ts) >= DEDUP_TTL]
    for ip in stale:
        del _seen[ip]
    for ip in [ip for ip, ts in _checked.items() if (now - ts) >= CHECK_TTL]:
        del _checked[ip]

# â”€â”€ Asset ID lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_machine_id: int | None = None

def get_machine_id() -> int | None:
    """
    Look up this machine's asset ID by hostname.
    Registers the asset if it doesn't exist yet.
    Caches the result; None while the backend can't be reached (asked again next time).
    """
    global _machine_id
    if _machine_id is not None:
        return _machine_id

    try:
        resp = requests.get(ASSETS_URL, timeout=5)
        if resp.status_code == 200:
            for asset in resp.json():
                if asset.get("name", "").lower() == HOSTNAME.lower():
                    _machine_id = asset["id"]
                    print(f"[*] Matched asset id={_machine_id} for hostname '{HOSTNAME}'")
                    return _machine_id

        # Asset not found â€” register it
        print(f"[*] Hostname '{HOSTNAME}' not found in assets. Registering...")
        payload = {
            "name": HOSTNAME,
            "os": os_name(),
            "software_list": [],
            "ip_address": lan_ip(),
            "status": "Online",
        }
        reg = requests.post(ASSETS_URL, json=payload, timeout=5)
        if reg.status_code in (200, 201):
            _machine_id = reg.json()["id"]
            print(f"[*] Registered as asset id={_machine_id}")
            return _machine_id
    except Exception as e:
        print(f"[!] Could not resolve machine_id: {e}")

    # Fallback â€” avoids crashing if backend is temporarily unreachable
    # No guessed id: incidents filed under a made-up asset would point at the wrong machine
    return None

# â”€â”€ IP Reputation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_ip_reputation(ip: str):
    """The backend's verdict dict for a public IP, or None (private IP, checked recently, or backend error)."""
    try:
        if not ipaddress.ip_address(ip).is_global:  # private, loopback, link-local, reserved
            return None
    except ValueError:
        return None
    last = _checked.get(ip)
    if last and (time.time() - last) < CHECK_TTL:
        return None
    try:
        resp = requests.get(f"{CHECK_IP_URL}/{ip}", params={"machine_id": get_machine_id()}, timeout=10)
        if resp.status_code == 200:
            _checked[ip] = time.time()
            data = resp.json()
            if data.get("error"):
                print(f"[!] {ip}: {data['error']}")
            return data
        print(f"[!] check-ip returned {resp.status_code} for {ip}")
    except Exception as e:
        print(f"[!] Error calling reputation API for {ip}: {e}")
    return None


def describe_source(verdict: dict) -> str:
    source, reference = verdict.get("source"), verdict.get("reference")
    if source == "AbuseIPDB":
        return f"AbuseIPDB score {verdict.get('score')}/100"
    return f"listed on {source}" + (f" ({reference})" if reference else "")

# â”€â”€ Incident Reporting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def report_incident(
    incident_type: str,
    severity: str,
    network_connection: str,
    details: str,
    process_name: str | None = None,
):
    machine_id = get_machine_id()
    if machine_id is None:
        print(f"[!] Backend unreachable; incident not filed: {incident_type} | {network_connection}")
        return
    payload = {
        "machine_id": machine_id,
        "type": incident_type,
        "severity": severity,
        "process_name": process_name,
        "network_connection": network_connection,
        "details": details,
        "status": "Active",
        "timeline": [
            {
                "time": datetime.now(timezone.utc).isoformat(),   # ISO string, not float
                "action": f"Detected malicious outbound connection to {network_connection}",
                "actor": "NetworkMonitor",
            }
        ],
    }
    try:
        resp = requests.post(INCIDENTS_URL, json=payload, timeout=5)
        if resp.status_code in (200, 201):
            inc_id = resp.json().get("id", "?")
            print(f"[+] Incident #{inc_id} created â€” {incident_type} | {network_connection}")
        else:
            print(f"[!] Failed to create incident: HTTP {resp.status_code} â€” {resp.text[:200]}")
    except Exception as e:
        print(f"[!] Failed to POST incident: {e}")

# â”€â”€ Network Scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_network():
    print(f"[*] [{datetime.now().strftime('%H:%M:%S')}] Scanning active connections...")

    try:
        # psutil 6+: net_connections() moved to psutil.net_connections()
        # but the process-level API is preferred for getting process name
        connections = psutil.net_connections(kind="inet")
    except AttributeError:
        # Fallback for very old psutil
        connections = psutil.net_connections(kind="inet")

    flagged = 0
    for conn in connections:
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue

        ip, port = conn.raddr.ip, conn.raddr.port

        # Resolve process name from PID
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Log unusual ports (not an incident, just informational)
        if port not in BENIGN_PORTS and not ip.startswith("127."):
            print(f"  [~] Unusual port: {process_name or 'unknown'} → {ip}:{port}")

        # Skip if already reported recently
        if _already_reported(ip):
            continue

        verdict = check_ip_reputation(ip)
        if verdict and verdict.get("is_malicious"):
            flagged += 1
            _mark_reported(ip)
            report_incident(
                incident_type="network_anomaly",
                severity="Critical",
                network_connection=f"{ip}:{port}",
                details=(
                    f"Process '{process_name or 'unknown'}' (PID {conn.pid}) "
                    f"established connection to malicious IP {ip} on port {port}: {describe_source(verdict)}"
                ),
                process_name=process_name,
            )

    _evict_stale()
    print(f"[*] Scan complete â€” {flagged} malicious connection(s) flagged.")

# â”€â”€ Entry Point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Heartbeat
# Inventory: what the agent reads from this machine, so CVEs are matched to real installed versions
INVENTORY_EVERY = 6 * 3600  # seconds; software rarely changes faster than this
_last_inventory = 0.0
UNINSTALL_KEYS = [
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def os_name() -> str:
    if platform.system() == "Windows":
        return f"Windows {platform.release()} (build {platform.version()})"
    return platform.platform()

def lan_ip() -> str:
    """Address of the interface that carries the default route (a UDP connect sends no packet)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET address: only used for the route lookup
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(HOSTNAME)

def installed_software() -> dict:
    """DisplayName -> DisplayVersion of installed programs, as Windows' Apps list shows them."""
    if winreg is None:
        return {}
    apps = {}
    for hive_name, path in UNINSTALL_KEYS:
        try:
            key = winreg.OpenKey(getattr(winreg, hive_name), path)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                values = {}
                try:
                    with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                        for value in ("DisplayName", "DisplayVersion", "SystemComponent", "ParentKeyName"):
                            try:
                                values[value] = winreg.QueryValueEx(sub, value)[0]
                            except OSError:
                                pass
                except OSError:
                    continue
                name = str(values.get("DisplayName") or "").strip()
                # hidden components and updates that belong to another program are not separate software
                if name and values.get("SystemComponent") != 1 and not values.get("ParentKeyName"):
                    apps[name] = str(values.get("DisplayVersion") or "").strip()
    return apps

def send_inventory():
    global _last_inventory, _machine_id
    machine_id = get_machine_id()
    if machine_id is None:
        return
    apps = installed_software()
    payload = {
        "os": os_name(),
        "ip_address": lan_ip(),
        "software_list": sorted(apps),
        "software_versions": {name: ver for name, ver in apps.items() if ver},
    }
    try:
        resp = requests.put(f"{ASSETS_URL}/{machine_id}/inventory", json=payload, timeout=30)
        if resp.status_code == 200:
            _last_inventory = time.time()
            print(f"[*] Inventory sent: {payload['os']}, {payload['ip_address']}, {len(apps)} programs")
        elif resp.status_code == 404:
            _machine_id = None
        else:
            print(f"[!] Inventory rejected: HTTP {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        print(f"[!] Inventory failed: {e}")

def send_heartbeat():
    """Tell the backend this agent is alive; its last_seen is what marks the machine online."""
    global _machine_id
    machine_id = get_machine_id()
    if machine_id is None:
        return
    try:
        resp = requests.post(f"{ASSETS_URL}/{machine_id}/heartbeat", timeout=5)
        if resp.status_code == 404:  # asset removed in the app: register again next poll
            global _last_inventory
            _machine_id, _last_inventory = None, 0.0
    except Exception as e:
        print(f"[!] Heartbeat failed: {e}")

if __name__ == "__main__":
    # Windows consoles and redirected logs are often not UTF-8; a non-ASCII print must not abort a scan
    sys.stdout.reconfigure(errors="replace")
    print(f"[*] ThreatLens Network Monitor starting on '{HOSTNAME}'")
    print(f"[*] Backend: {API_BASE} | Poll: {POLL_INTERVAL}s | Dedup TTL: {DEDUP_TTL}s")

    # Resolve machine ID once at startup
    get_machine_id()

    while True:
        send_heartbeat()
        if time.time() - _last_inventory > INVENTORY_EVERY:
            send_inventory()
        try:
            check_network()
        except Exception as e:
            print(f"[!] Unexpected error in check_network(): {e}")
        time.sleep(POLL_INTERVAL)
