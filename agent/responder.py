import psutil
import subprocess
import platform
import requests
import time
import os
import shutil

API_URL = "http://127.0.0.1:8000/api/incidents"
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def get_severity_tier(score):
    if score >= 86: return "critical"
    if score >= 61: return "confirmed"
    if score >= 31: return "suspicious"
    return "low"

def suspend_process(pid):
    try:
        p = psutil.Process(pid)
        p.suspend()
        print(f"[RESPONSE] Suspended PID {pid} ({p.name()})")
        return True
    except Exception as e:
        print(f"[ERROR] Could not suspend PID {pid}: {e}")
        return False

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.kill()
        print(f"[RESPONSE] Killed PID {pid}")
        return True
    except Exception as e:
        print(f"[ERROR] Could not kill PID {pid}: {e}")
        return False

def quarantine_file(filepath):
    try:
        if os.path.exists(filepath):
            dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath) + ".quarantined")
            shutil.move(filepath, dest)
            print(f"[RESPONSE] Quarantined: {filepath} -> {dest}")
            return True
    except Exception as e:
        print(f"[ERROR] Could not quarantine {filepath}: {e}")
    return False

def block_all_outbound():
    """Block all outbound network connections via Windows Firewall"""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                "blockinbound,blockoutbound"
            ], check=True, capture_output=True)
            print("[RESPONSE] CRITICAL: All outbound network connections blocked!")
        elif system == "Linux":
            subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True, capture_output=True)
            print("[RESPONSE] CRITICAL: All outbound network connections blocked!")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to block outbound: {e}")
        return False

def respond_to_incident(incident_id, score, pid=None, filepath=None):
    tier = get_severity_tier(score)
    actions_taken = []
    timeline_entry = {"time": time.time(), "action": None, "actor": "Auto-Responder"}

    if tier == "suspicious":
        if pid: suspend_process(pid)
        actions_taken.append(f"Process PID {pid} suspended - awaiting analyst approval")
        timeline_entry["action"] = "Process suspended. Awaiting analyst approval."
        # Poll for approval every 10 seconds
        print(f"[RESPONSE] Incident {incident_id}: SUSPICIOUS - process suspended, awaiting approval.")

    elif tier == "confirmed":
        if pid: kill_process(pid)
        if filepath: quarantine_file(filepath)
        actions_taken.append(f"Process killed, file quarantined")
        timeline_entry["action"] = "Process killed. File moved to quarantine."
        print(f"[RESPONSE] Incident {incident_id}: CONFIRMED MALICIOUS - process killed & file quarantined.")

    elif tier == "critical":
        if pid: kill_process(pid)
        if filepath: quarantine_file(filepath)
        block_all_outbound()
        actions_taken.append("Network blocked, process killed, file quarantined")
        timeline_entry["action"] = "CRITICAL: Network blocked. Process killed. File quarantined. SOC alerted."
        print(f"[RESPONSE] Incident {incident_id}: CRITICAL - full lockdown executed.")

    # Report back to API
    try:
        requests.patch(f"{API_URL}/{incident_id}", json={
            "auto_response_action": ", ".join(actions_taken),
            "timeline": [timeline_entry]
        })
    except Exception as e:
        print(f"[ERROR] Failed to update incident {incident_id}: {e}")


if __name__ == "__main__":
    print("[*] Auto-Responder Service Active")
