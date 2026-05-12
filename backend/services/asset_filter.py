from sqlalchemy.orm import Session
from ..database import models
import json

def cross_reference_cve_with_assets(db_session: Session, cve: models.CVE):
    """
    Checks if a CVE affects any registered assets.
    For simplicity, matches description/affected_products against asset software list.
    """
    assets = db_session.query(models.Asset).all()
    description_lower = cve.description.lower()
    
    # In a real app, this would use CPE matches or more complex logic
    # Here we check if any software name in asset list appears in CVE description
    affected = False
    for asset in assets:
        software_list = asset.software_list or []
        for software in software_list:
            if software.lower() in description_lower:
                affected = True
                break
        if affected:
            break
            
    if affected:
        cve.asset_affected = True
        db_session.commit()
        
    return affected
