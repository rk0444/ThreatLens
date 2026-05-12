import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3"

def check_file_hash(file_hash: str):
    """
    Checks a file hash (SHA-256, SHA-1, or MD5) against VirusTotal.
    """
    if not VT_API_KEY:
        return {"error": "VirusTotal API Key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(f"{VT_API_URL}/files/{file_hash}", headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "verdict": "Malicious" if stats.get("malicious", 0) > 0 else "Safe"
            }
        elif response.status_code == 404:
            return {"status": "not_found", "message": "Hash not found in VirusTotal database"}
    except Exception as e:
        print(f"Error checking VirusTotal hash {file_hash}: {e}")
    return None

def check_url_reputation(url: str):
    """
    Checks a URL against VirusTotal.
    """
    if not VT_API_KEY:
        return {"error": "VirusTotal API Key not configured"}

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(f"{VT_API_URL}/urls/{url_id}", headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "verdict": "Malicious" if stats.get("malicious", 0) > 0 else "Safe"
            }
    except Exception as e:
        print(f"Error checking VirusTotal URL: {e}")
    return None
