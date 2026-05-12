import psutil
import time
import requests
import socket

# Local backend API
API_URL = "http://127.0.0.1:8000/api/incidents"
HOSTNAME = socket.gethostname()

SUSPICIOUS_CHAINS = [
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("powershell.exe", "wscript.exe"),
    ("cmd.exe", "wscript.exe")
]

def check_process_chains():
    processes = {}
    for p in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            processes[p.info['pid']] = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for pid, info in processes.items():
        if info['ppid'] in processes:
            parent_name = processes[info['ppid']]['name'].lower()
            child_name = info['name'].lower()
            
            for parent, child in SUSPICIOUS_CHAINS:
                if parent_name == parent and child_name == child:
                    print(f"[ALERT] Suspicious chain detected: {parent_name} -> {child_name}")
                    report_incident(
                        type="process_anomaly",
                        severity="High",
                        process_name=f"{parent_name} -> {child_name}",
                        details=f"Process {child_name} (PID: {pid}) spawned by {parent_name} (PID: {info['ppid']})"
                    )

def report_incident(type, severity, process_name, details):
    payload = {
        "machine_id": 1, # Placeholder for registered machine
        "type": type,
        "severity": severity,
        "process_name": process_name,
        "details": details,
        "status": "Active",
        "timeline": [{"time": time.time(), "action": "Detected suspicious process chain"}]
    }
    try:
        requests.post(API_URL, json=payload)
    except Exception as e:
        print(f"Failed to report incident: {e}")

if __name__ == "__main__":
    print(f"[*] Starting Process Monitor on {HOSTNAME}...")
    while True:
        check_process_chains()
        time.sleep(5)
