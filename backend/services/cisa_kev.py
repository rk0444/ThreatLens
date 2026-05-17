import requests
from datetime import datetime
from sqlalchemy.orm import Session
from ..database import models
from .scoring import calculate_risk_score

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def sync_cisa_kev(db: Session):
    print("[INIT] Syncing CISA KEV Catalog...")
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] Failed to download CISA KEV: {e}")
        return
        
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"[INIT] Fetched {len(vulnerabilities)} exploited vulnerabilities from CISA.")
    
    for v in vulnerabilities:
        cve_id = v.get("cveID")
        ransomware_use = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        
        db_kev = db.query(models.CisaKev).filter(models.CisaKev.cve_id == cve_id).first()
        if not db_kev:
            db_kev = models.CisaKev(
                cve_id=cve_id,
                vendor=v.get("vendorProject"),
                product=v.get("product"),
                vulnerability_name=v.get("vulnerabilityName"),
                date_added=v.get("dateAdded"),
                required_action=v.get("requiredAction"),
                due_date=v.get("dueDate"),
                ransomware_use=ransomware_use
            )
            db.add(db_kev)
        else:
            db_kev.ransomware_use = ransomware_use
            
    db.commit()
    
    print("[INIT] Cross-referencing CISA KEV with local CVEs...")
    local_cves = db.query(models.CVE).all()
    for cve in local_cves:
        kev = db.query(models.CisaKev).filter(models.CisaKev.cve_id == cve.cve_id).first()
        if kev:
            # Set both flags correctly
            cve.cisa_kev = True
            cve.actively_exploited = True
            cve.ransomware_use = kev.ransomware_use

            # Recalculate risk score with updated flags
            risk = calculate_risk_score(
                cvss_score=cve.cvss_score or 0,
                epss_score=cve.epss_score or 0,
                cisa_kev=True,
                actively_exploited=True,
                asset_affected=cve.asset_affected or False,
                affected_asset_count=getattr(cve, 'affected_asset_count', 0),
                ransomware_use=kev.ransomware_use,
                patch_available=getattr(cve, 'patch_available', None),
                published_date=cve.published_date,
            )
            cve.risk_score = risk["score"]
            cve.risk_band = risk["band"]
            print(f"[KEV MATCH] {cve.cve_id} -> Risk Score: {risk['score']} ({risk['band']})")

    db.commit()
    print("[INIT] CISA KEV sync complete.")