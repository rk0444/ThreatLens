import requests
from datetime import datetime
from sqlalchemy.orm import Session
from ..database import models
from .scoring import rescore_cve

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
    
    kev_map = {k.cve_id: k for k in db.query(models.CisaKev)}  # one query, not one per entry
    for v in vulnerabilities:
        cve_id = v.get("cveID")
        ransomware_use = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        
        db_kev = kev_map.get(cve_id)
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
            kev_map[cve_id] = db_kev
        else:
            db_kev.ransomware_use = ransomware_use
            
    db.commit()
    
    print("[INIT] Cross-referencing CISA KEV with local CVEs...")
    local_cves = db.query(models.CVE).all()
    for cve in local_cves:
        kev = kev_map.get(cve.cve_id)
        if kev:
            # Set both flags correctly
            cve.cisa_kev = True
            cve.actively_exploited = True
            cve.ransomware_use = kev.ransomware_use

            risk = rescore_cve(cve)
            print(f"[KEV MATCH] {cve.cve_id} -> Risk Score: {risk['score']} ({risk['band']})")

    db.commit()
    print("[INIT] CISA KEV sync complete.")