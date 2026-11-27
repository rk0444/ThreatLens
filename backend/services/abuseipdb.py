"""Is an IP malicious? Checks published blocklists first (local, unlimited), then AbuseIPDB (cached 24 h)."""
import ipaddress
import os
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from backend.database import models
from backend.services import ip_blocklists

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB = "AbuseIPDB"
CACHE_TTL = timedelta(hours=24)  # free plan: 1,000 checks a day
QUOTA_PAUSE_SECONDS = 3600
_paused_until = 0.0  # set when AbuseIPDB answers 429 (daily quota used up)


def _utc(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _ask_abuseipdb(ip: str) -> dict:
    """AbuseIPDB's answer for one IP, or {"error": ...}. Errors are not cached."""
    global _paused_until
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    if time.monotonic() < _paused_until:
        return {"error": "AbuseIPDB daily quota used up; paused"}
    try:
        response = requests.get(ABUSEIPDB_URL, timeout=10,
                                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                                params={"ipAddress": ip, "maxAgeInDays": "90"})
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB unreachable: {e}"}
    if response.status_code == 429:
        _paused_until = time.monotonic() + QUOTA_PAUSE_SECONDS
        return {"error": "AbuseIPDB daily quota used up; paused for 1 hour"}
    if response.status_code != 200:
        return {"error": f"AbuseIPDB returned HTTP {response.status_code}"}
    data = response.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    return {"score": score, "is_malicious": score > 50, "country": data.get("countryCode"),
            "isp": data.get("isp"), "usage_type": data.get("usageType")}


def check_ip_reputation(ip: str, db_session=None, machine_id=None, machine_hostname=None) -> dict:
    """Verdict for one IP. Raises ValueError for a malformed IP.

    Order: private/reserved → not checked; published blocklist → malicious; fresh cache → cached answer;
    else AbuseIPDB (answer cached 24 h). A malicious result with machine_id is recorded in flagged_connections.
    """
    addr = ipaddress.ip_address(ip)
    result = {"ip": ip, "is_malicious": False, "source": None, "reference": None, "network": None,
              "score": None, "country": None, "isp": None, "usage_type": None}
    if not addr.is_global:
        return result

    hit = ip_blocklists.match(ip, db_session) if db_session is not None else None
    if hit:
        result.update(is_malicious=True, source=hit["source"], reference=hit["reference"], network=hit["network"])
    else:
        cached = db_session.query(models.IPReputationCache).filter_by(ip=ip).first() if db_session is not None else None
        if cached and _utc(cached.checked_at) > datetime.now(timezone.utc) - CACHE_TTL:
            answer = {"score": cached.score, "is_malicious": cached.is_malicious, "country": cached.country,
                      "isp": cached.isp, "usage_type": cached.usage_type}
        else:
            answer = _ask_abuseipdb(ip)
            if "error" in answer:
                result["error"] = answer["error"]
                return result
            if db_session is not None:
                if not cached:
                    cached = models.IPReputationCache(ip=ip)
                    db_session.add(cached)
                for field in ("score", "is_malicious", "country", "isp", "usage_type"):
                    setattr(cached, field, answer[field])
                cached.checked_at = datetime.now(timezone.utc)
                db_session.commit()
        result.update(source=ABUSEIPDB, **answer)

    if result["is_malicious"] and db_session is not None and machine_id:
        _record(db_session, result, machine_id, machine_hostname)
    return result


def _record(db_session, result: dict, machine_id: int, machine_hostname):
    row = db_session.query(models.FlaggedConnection).filter_by(
        machine_id=machine_id, destination_ip=result["ip"]).first()
    if row:
        row.times_seen += 1
        row.last_seen = datetime.now(timezone.utc)
    else:
        row = models.FlaggedConnection(machine_id=machine_id, machine_hostname=machine_hostname or "Unknown",
                                       destination_ip=result["ip"], times_seen=1)
        db_session.add(row)
    row.abuse_score = result["score"]
    row.country, row.isp = result["country"], result["isp"]
    row.source, row.reference = result["source"], result["reference"]
    db_session.commit()
