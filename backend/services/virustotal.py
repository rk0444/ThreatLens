import base64
import os

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3"


def _report(path: str) -> dict:
    """One VirusTotal report: {"found": True, engine counts...}, {"found": False} or {"error": reason}."""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    try:
        response = requests.get(f"{VT_API_URL}/{path}", headers={"x-apikey": VT_API_KEY}, timeout=15)
    except requests.RequestException as e:
        return {"error": f"VirusTotal unreachable: {e}"}
    if response.status_code == 404:
        return {"found": False, "message": "VirusTotal has no report for this"}
    if response.status_code == 429:
        return {"error": "VirusTotal quota used up (HTTP 429)"}
    if response.status_code in (401, 403):
        return {"error": f"VirusTotal rejected the API key (HTTP {response.status_code})"}
    if response.status_code != 200:
        return {"error": f"VirusTotal returned HTTP {response.status_code}"}
    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
    }


def check_file_hash(file_hash: str) -> dict:
    """VirusTotal file report for an MD5, SHA-1 or SHA-256."""
    return _report(f"files/{file_hash}")


def check_url_reputation(url: str) -> dict:
    """VirusTotal report for one exact URL (only exists if someone submitted it before)."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _report(f"urls/{url_id}")


def check_domain_reputation(domain: str) -> dict:
    """VirusTotal domain report (covers the whole domain, not one URL)."""
    return _report(f"domains/{domain}")
