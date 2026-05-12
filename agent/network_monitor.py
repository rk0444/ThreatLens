import psutil
import time
import requests
import socket
import os

API_URL = "http://127.0.0.1:8000/api/incidents"
HOSTNAME = socket.gethostname()
CHECK_IP_URL = "http://127.0.0.1:8000/api/check-ip/"

def check_ip_reputation(ip):
    # Simulated local cache for internal IPs
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return False
    
    try:
        response = requests.get(f"{CHECK_IP_URL}{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("is_malicious", False)
    except Exception as e:
        print(f"[!] Error calling reputation API: {e}")
    return False

def check_network():
    print("[*] Scanning active network connections...")
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip, port = conn.raddr
            if port not in [80, 443, 22, 3389]:
                print(f"[WARN] Unusual port detected: {ip}:{port}")
            
            is_malicious = check_ip_reputation(ip)
            if is_malicious:
                report_incident(
                    type="network_anomaly",
                    severity="Critical",
                    network_connection=f"{ip}:{port}",
                    details=f"Process {conn.pid} established connection to malicious IP {ip} on port {port}"
                )

def report_incident(type, severity, network_connection, details):
    payload = {
        "machine_id": 1,
        "type": type,
        "severity": severity,
        "network_connection": network_connection,
        "details": details,
        "status": "Active",
        "timeline": [{"time": time.time(), "action": f"Detected malicious outbound connection to {network_connection}"}]
    }
    try:
        requests.post(API_URL, json=payload)
    except Exception as e:
        print(f"Failed to report incident: {e}")

if __name__ == "__main__":
    print(f"[*] Starting Network Monitor on {HOSTNAME}...")
    while True:
        check_network()
        time.sleep(10)
