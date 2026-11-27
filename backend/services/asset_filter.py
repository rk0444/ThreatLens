from sqlalchemy.orm import Session
from backend.database import models
from backend.services.scoring import rescore_cve


def _match_assets(cve: models.CVE, assets) -> None:
    """Store which assets a CVE affects and recompute its risk score.

    In a real app this would use CPE matches; here any asset software name
    that appears in the CVE description counts as a match.
    """
    description_lower = (cve.description or "").lower()
    affected_count = sum(
        1 for asset in assets
        if any(software.lower() in description_lower for software in (asset.software_list or []))
    )
    cve.asset_affected = affected_count > 0
    cve.affected_asset_count = affected_count
    rescore_cve(cve)


def cross_reference_cve_with_assets(db_session: Session, cve: models.CVE):
    """Match one CVE against all registered assets (used by the NVD sync)."""
    _match_assets(cve, db_session.query(models.Asset).all())
    db_session.commit()
    return cve.asset_affected


def rematch_all_cves(db_session: Session) -> int:
    """Re-match every stored CVE after the asset inventory changes. Returns affected count."""
    assets = db_session.query(models.Asset).all()
    affected = 0
    for cve in db_session.query(models.CVE).all():
        _match_assets(cve, assets)
        affected += cve.asset_affected
    db_session.commit()
    return affected
