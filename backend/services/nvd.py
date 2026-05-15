import requests
import sqlite3
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from backend.database import models
from backend.services.epss import fetch_epss_score
from backend.services.asset_filter import cross_reference_cve_with_assets
from backend.services.scoring import calculate_risk_score
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

def _log_scheduler(status: str, message: str = ""):
    db_path = os.path.join(os.path.dirname(__file__), "..", "database", "threatlens.sqlite")
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO scheduler_logs (job_name, status, error_message, ran_at) VALUES (?,?,?,?)",
            ("nvd_ingest", status, message, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[nvd] log write failed: {e}")

def fetch_latest_cves(db_session: Session):
    _log_scheduler("started")
    ingested = 0
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)

    params = {
        "pubStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "pubEndDate":   end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        if response.status_code != 200:
            _log_scheduler("error", f"NVD API returned status {response.status_code}")
            return

        vulnerabilities = response.json().get("vulnerabilities", [])

        for v in vulnerabilities:
            cve_data = v.get("cve", {})
            cve_id = cve_data.get("id")

            existing = db_session.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
            if existing:
                continue

            description = (cve_data.get("descriptions") or [{}])[0].get("value", "")
            metrics = (cve_data.get("metrics", {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {})
            cvss_score = metrics.get("baseScore")
            published_date_str = cve_data.get("published")
            published_date = datetime.fromisoformat(published_date_str.replace("Z", "+00:00"))

            desc_lower = description.lower()
            actively_exploited = any(k in desc_lower for k in [
                "actively exploited", "exploit has been made public",
                "exploit is publicly available", "being exploited in the wild",
                "known to be exploited"
            ])
            ransomware_use  = "ransomware" in desc_lower
            patch_available = not any(k in desc_lower for k in [
                "no patch", "no fix", "unpatched", "no workaround"
            ])

            # Fetch EPSS before first commit
            epss_data = fetch_epss_score(cve_id) or {}
            epss_score       = epss_data.get("epss")
            epss_percentile  = epss_data.get("percentile")

            # Calculate risk before insert so risk_band is never null
            risk = calculate_risk_score(
                cvss_score=cvss_score or 0,
                epss_score=epss_score or 0,
                cisa_kev=False,
                actively_exploited=actively_exploited,
                asset_affected=False,
                affected_asset_count=0,
                ransomware_use=ransomware_use,
                patch_available=patch_available,
                published_date=published_date,
            )

            new_cve = models.CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                published_date=published_date,
                actively_exploited=actively_exploited,
                ransomware_use=ransomware_use,
                patch_available=patch_available,
                risk_score=risk["score"],
                risk_band=risk["band"],
                raw_json=cve_data,
            )
            db_session.add(new_cve)
            db_session.commit()
            db_session.refresh(new_cve)

            # Asset cross-reference — updates affected_asset_count if matched
            cross_reference_cve_with_assets(db_session, new_cve)
            db_session.commit()

            ingested += 1

        _log_scheduler("success", f"Ingested {ingested} CVEs")

    except Exception as e:
        _log_scheduler("error", str(e))
        print(f"[nvd] Error: {e}")