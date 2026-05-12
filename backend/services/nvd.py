import requests
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from ..database import models, db
from .epss import fetch_epss_score
from .asset_filter import cross_reference_cve_with_assets
from .scoring import calculate_risk_score
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

def fetch_latest_cves(db_session: Session):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)
    
    params = {
        "pubStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "pubEndDate": end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    }
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            for v in vulnerabilities:
                cve_data = v.get("cve", {})
                cve_id = cve_data.get("id")
                
                # Check if exists
                existing = db_session.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
                if existing:
                    continue
                
                description = cve_data.get("descriptions", [{}])[0].get("value", "")
                metrics = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = metrics.get("baseScore")
                published_date_str = cve_data.get("published")
                published_date = datetime.fromisoformat(published_date_str.replace("Z", "+00:00"))

                # Parse exploitation signals from description
                desc_lower = description.lower()
                actively_exploited = any(keyword in desc_lower for keyword in [
                    "actively exploited", "exploit has been made public",
                    "exploit is publicly available", "being exploited in the wild",
                    "known to be exploited"
                ])
                ransomware_use = "ransomware" in desc_lower
                patch_available = not any(keyword in desc_lower for keyword in [
                    "no patch", "no fix", "unpatched", "no workaround"
                ])

                # Create CVE
                new_cve = models.CVE(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    published_date=published_date,
                    actively_exploited=actively_exploited,
                    ransomware_use=ransomware_use,
                    patch_available=patch_available,
                    raw_json=cve_data
                )
                db_session.add(new_cve)
                db_session.commit()
                db_session.refresh(new_cve)
                
                # Fetch EPSS score
                epss_data = fetch_epss_score(cve_id)
                if epss_data:
                    new_cve.epss_score = epss_data.get("epss")
                    new_cve.epss_percentile = epss_data.get("percentile")
                    db_session.commit()

                # Asset cross-reference
                is_affected = cross_reference_cve_with_assets(db_session, new_cve)

                # Calculate and store risk score
                risk = calculate_risk_score(
                    cvss_score=cvss_score or 0,
                    epss_score=new_cve.epss_score or 0,
                    cisa_kev=getattr(new_cve, 'cisa_kev', False),
                    actively_exploited=actively_exploited,
                    asset_affected=is_affected,
                    affected_asset_count=getattr(new_cve, 'affected_asset_count', 0),
                    ransomware_use=ransomware_use,
                    patch_available=patch_available,
                    published_date=published_date,
                )
                new_cve.risk_score = risk["score"]
                new_cve.risk_band = risk["band"]
                db_session.commit()

        else:
            print(f"NVD API returned status {response.status_code}")
                
    except Exception as e:
        print(f"Error fetching CVEs from NVD: {e}")