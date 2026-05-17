"""
ThreatLens â€” Endpoint Network Monitor Agent
agent/network_monitor.py

Run with venv python:
  E:\Project\ThreatLens\.venv\Scripts\python agent\network_monitor.py
"""

import psutil
import time
import requests
import socket
import os
from datetime import datetime, timezone

# â”€â”€ Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
API_BASE       = "http://127.0.0.1:8000"
INCIDENTS_URL  = f"{API_BASE}/api/incidents"
CHECK_IP_URL   = f"{API_BASE}/api/check-ip"
ASSETS_URL     = f"{API_BASE}/api/assets"
POLL_INTERVAL  = 10      # seconds between scans
DEDUP_TTL      = 300     # seconds before the same IP can re-alert (5 min)

HOSTNAME = socket.gethostname()

# Ports considered normal â€” connections to these are not flagged
BENIGN_PORTS = {80, 443, 22, 3389, 53, 123, 8000, 5173}

# â”€â”€ Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# { ip: last_reported_timestamp }
_seen: dict[str, float] = {}

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

# â”€â”€ Asset ID lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_machine_id: int | None = None

def get_machine_id() -> int:
    """
    Look up this machine's asset ID by hostname.
    Registers the asset if it doesn't exist yet.
    Caches the result for the lifetime of the process.
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
            "os": os.name,
            "software_list": [],
            "ip_address": socket.gethostbyname(HOSTNAME),
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
    print("[!] Falling back to machine_id=1")
    return 1

# â”€â”€ IP Reputation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_ip_reputation(ip: str) -> bool:
    """Returns True if the IP is flagged as malicious by the backend."""
    # Skip private / loopback ranges immediately
    if (ip.startswith("127.") or ip.startswith("192.168.")
            or ip.startswith("10.") or ip.startswith("172.")):
        return False

    try:
        resp = requests.get(f"{CHECK_IP_URL}/{ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return bool(data.get("is_malicious", False))
        else:
            print(f"[!] check-ip returned {resp.status_code} for {ip}")
    except Exception as e:
        print(f"[!] Error calling reputation API for {ip}: {e}")

    return False

# â”€â”€ Incident Reporting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def report_incident(
    incident_type: str,
    severity: str,
    network_connection: str,
    details: str,
    process_name: str | None = None,
):
    machine_id = get_machine_id()
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

        if check_ip_reputation(ip):
            flagged += 1
            _mark_reported(ip)
            report_incident(
                incident_type="network_anomaly",
                severity="Critical",
                network_connection=f"{ip}:{port}",
                details=(
                    f"Process '{process_name or 'unknown'}' (PID {conn.pid}) "
                    f"established connection to malicious IP {ip} on port {port}"
                ),
                process_name=process_name,
            )

    _evict_stale()
    print(f"[*] Scan complete â€” {flagged} malicious connection(s) flagged.")

# â”€â”€ Entry Point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    print(f"[*] ThreatLens Network Monitor starting on '{HOSTNAME}'")
    print(f"[*] Backend: {API_BASE} | Poll: {POLL_INTERVAL}s | Dedup TTL: {DEDUP_TTL}s")

    # Resolve machine ID once at startup
    get_machine_id()

    while True:
        try:
            check_network()
        except Exception as e:
            print(f"[!] Unexpected error in check_network(): {e}")
        time.sleep(POLL_INTERVAL)
