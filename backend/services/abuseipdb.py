import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

from database import models
from datetime import datetime, timezone

def check_ip_reputation(ip: str, db_session=None, machine_id=None, machine_hostname=None):
    if not ABUSEIPDB_API_KEY:
        return {"error": "API Key not configured"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            result = {
                "ip": ip,
                "score": score,
                "is_malicious": score > 50,
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType")
            }

            if score > 50 and db_session and machine_id:
                # Log to flagged_connections
                existing = db_session.query(models.FlaggedConnection).filter(
                    models.FlaggedConnection.machine_id == machine_id,
                    models.FlaggedConnection.destination_ip == ip
                ).first()
                if existing:
                    existing.times_seen += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.abuse_score = score
                else:
                    new_conn = models.FlaggedConnection(
                        machine_id=machine_id,
                        machine_hostname=machine_hostname or "Unknown",
                        destination_ip=ip,
                        abuse_score=score,
                        country=data.get("countryCode"),
                        isp=data.get("isp"),
                        times_seen=1
                    )
                    db_session.add(new_conn)
                db_session.commit()
            
            return result
    except Exception as e:
        print(f"Error checking IP reputation for {ip}: {e}")
    return None
