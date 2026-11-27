import json
import requests
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from backend.database import models
from backend.services.epss import fetch_epss_bulk
from backend.services.asset_filter import _match_assets
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


def evidence_flags(cve_data: dict, cisa_kev=False, kev_ransomware=False):
    """(actively_exploited, ransomware_use, patch_available) from published evidence only.

    - exploited: on CISA KEV, or NVD links a reference tagged "Exploit"
    - ransomware: CISA KEV's knownRansomwareCampaignUse (set by the KEV sync)
    - patch: NVD links a reference tagged "Patch" (absence is not evidence of no patch)
    """
    tags = {t for ref in (cve_data or {}).get("references", []) for t in ref.get("tags", [])}
    exploited = bool(cisa_kev) or "Exploit" in tags
    ransomware = bool(cisa_kev and kev_ransomware)
    patch_available = "Patch" in tags
    return exploited, ransomware, patch_available


def _fetch_window(params: dict, headers: dict) -> list:
    """Every CVE in the window: NVD pages at most 2000 results, so walk startIndex to totalResults."""
    vulnerabilities, start = [], 0
    while True:
        response = requests.get(NVD_API_URL, params={**params, "startIndex": start},
                                headers=headers, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f"NVD API returned status {response.status_code} at startIndex {start}")
        page = response.json()
        batch = page.get("vulnerabilities", [])
        vulnerabilities.extend(batch)
        start += len(batch)
        if not batch or start >= page.get("totalResults", 0):
            return vulnerabilities
        # NVD rate limit: 5 requests / 30 s without a key, 50 with one
        time.sleep(0.6 if NVD_API_KEY else 6)


def fetch_latest_cves(db_session: Session, notify=None):
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
        vulnerabilities = _fetch_window(params, headers)
        print(f"[nvd] Got {len(vulnerabilities)} CVEs. Fetching EPSS scores in bulk...")

        cve_ids = [
            v.get("cve", {}).get("id")
            for v in vulnerabilities
            if v.get("cve", {}).get("id")
        ]
        epss_map = fetch_epss_bulk(cve_ids)
        print(f"[nvd] EPSS scores fetched for {len(epss_map)} CVEs. Processing...")

        # one query each instead of one per CVE
        existing_map = {c.cve_id: c for c in db_session.query(models.CVE).filter(models.CVE.cve_id.in_(cve_ids))}
        assets = db_session.query(models.Asset).all()

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

            epss_data = epss_map.get(cve_id, {})
            epss_score = epss_data.get("epss")
            epss_percentile = epss_data.get("percentile")

            existing = existing_map.get(cve_id)
            if existing:
                existing.cvss_score         = cvss_score
                existing.epss_score         = epss_score
                existing.epss_percentile    = epss_percentile
                existing.raw_json           = cve_data
                (existing.actively_exploited, existing.ransomware_use,
                 existing.patch_available) = evidence_flags(cve_data, existing.cisa_kev, existing.ransomware_use)
                _match_assets(existing, assets)  # also rescores
                updated += 1
            else:
                actively_exploited, ransomware_use, patch_available = evidence_flags(cve_data)
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
                    raw_json=cve_data,
                )
                _match_assets(new_cve, assets)  # sets risk_band (NOT NULL)
                db_session.add(new_cve)
                existing_map[cve_id] = new_cve  # NVD can repeat an ID across pages
                ingested += 1
        db_session.commit()

        _log_scheduler("success", f"Ingested {ingested} new, updated {updated} existing CVEs")
        if notify and ingested:
            notify(json.dumps({"type": "CVES_UPDATED", "data": {"ingested": ingested}}))
        print(f"[nvd] Done. Ingested {ingested} new, updated {updated} existing.")

    except Exception as e:
        import traceback
        err = f"{str(e)}\n{traceback.format_exc()}"
        _log_scheduler("error", err)
        print(f"[nvd] Error: {err}")
        raise


def run_nvd_sync(notify=None):
    """Scheduler wrapper — creates its own DB session. notify(str) broadcasts to open pages."""
    from backend.database.db import SessionLocal
    session = SessionLocal()
    try:
        fetch_latest_cves(session, notify)
    finally:
        session.close()
