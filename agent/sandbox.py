import hashlib
import requests
import os
import time

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "dummy")
API_URL = "http://127.0.0.1:8000/api/incidents"

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    # Simulated VT check
    return {"malicious": 0, "suspicious": 0, "undetected": 70}

def detonate_in_cuckoo(filepath):
    # Simulated Cuckoo Sandbox integration
    print(f"[*] Detonating {filepath} in local Sandbox...")
    time.sleep(2)
    return {
        "verdict": "Suspicious",
        "behaviors": ["Drops executable in AppData", "Modifies Registry Run key"],
        "network_calls": ["evil-domain.com"],
        "file_writes": 12
    }

def analyze_file(filepath, incident_id):
    file_hash = get_file_hash(filepath)
    vt_results = check_virustotal(file_hash)
    
    if vt_results.get("malicious", 0) == 0:
        sandbox_report = detonate_in_cuckoo(filepath)
        verdict = sandbox_report["verdict"]
    else:
        sandbox_report = None
        verdict = "Malicious"
        
    # Update Incident with sandbox data
    print(f"[*] Analysis complete. Verdict: {verdict}")

if __name__ == "__main__":
    print("[*] Sandbox Detonation Service Active")
