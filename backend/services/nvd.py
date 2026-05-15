import requests
import sqlite3
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from backend.database import models
from backend.services.epss import fetch_epss_bulk
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
    updated = 0
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
        print("[nvd] Fetching CVEs from NVD...")
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        if response.status_code != 200:
            _log_scheduler("error", f"NVD API returned status {response.status_code}")
            return

        vulnerabilities = response.json().get("vulnerabilities", [])
        print(f"[nvd] Got {len(vulnerabilities)} CVEs. Fetching EPSS scores in bulk...")

        cve_ids = [
            v.get("cve", {}).get("id")
            for v in vulnerabilities
            if v.get("cve", {}).get("id")
        ]
        epss_map = fetch_epss_bulk(cve_ids)
        print(f"[nvd] EPSS scores fetched for {len(epss_map)} CVEs. Processing...")

        for v in vulnerabilities:
            cve_data = v.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
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
            ransomware_use = "ransomware" in desc_lower
            patch_available = not any(k in desc_lower for k in [
                "no patch", "no fix", "unpatched", "no workaround"
            ])

            epss_data = epss_map.get(cve_id, {})
            epss_score = epss_data.get("epss")
            epss_percentile = epss_data.get("percentile")

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

            existing = db_session.query(models.CVE).filter_by(cve_id=cve_id).first()
            if existing:
                existing.cvss_score         = cvss_score
                existing.epss_score         = epss_score
                existing.epss_percentile    = epss_percentile
                existing.risk_score         = risk["score"]
                existing.risk_band          = risk["band"]
                existing.raw_json           = cve_data
                existing.patch_available    = patch_available
                existing.actively_exploited = actively_exploited
                existing.ransomware_use     = ransomware_use
                db_session.commit()
                cross_reference_cve_with_assets(db_session, existing)
                db_session.commit()
                updated += 1
            else:
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
                cross_reference_cve_with_assets(db_session, new_cve)
                db_session.commit()
                ingested += 1

        _log_scheduler("success", f"Ingested {ingested} new, updated {updated} existing CVEs")
        print(f"[nvd] Done. Ingested {ingested} new, updated {updated} existing.")

    except Exception as e:
        import traceback
        err = f"{str(e)}\n{traceback.format_exc()}"
        _log_scheduler("error", err)
        print(f"[nvd] Error: {err}")


def run_nvd_sync():
    """Scheduler wrapper — creates its own DB session."""
    from backend.database.db import SessionLocal
    session = SessionLocal()
    try:
        fetch_latest_cves(session)
    except Exception as e:
        print(f"[nvd_sync] failed: {e}")
    finally:
        session.close()