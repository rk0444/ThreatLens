import re
from sqlalchemy.orm import Session
from backend.database import models
from backend.services.scoring import rescore_cve


def cpe_products(cve: models.CVE) -> set:
    """(vendor, product) pairs NVD lists as vulnerable for this CVE (empty until NVD analyses it)."""
    configs = (cve.raw_json or {}).get("configurations", [])
    pairs = set()
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if match.get("vulnerable") and len(parts) > 4:
                    pairs.add((parts[3], parts[4]))
    return pairs


def _normalize(software: str) -> str:
    # "Python 3.10" -> "python", "Google Chrome" -> "google_chrome"
    words = [w for w in re.split(r"[\s_]+", software.lower()) if w and not any(c.isdigit() for c in w)]
    return "_".join(words)


def matched_software(cve: models.CVE, software_list) -> list:
    """Asset software entries that name a vulnerable CPE product of this CVE.

    shortcut: matches vendor/product names only and ignores CPE version ranges,
    upgrade when assets report installed versions in a structured form.
    """
    products = cpe_products(cve)
    if not products:
        return []
    names = {p for _, p in products} | {f"{v}_{p}" for v, p in products}
    return [s for s in (software_list or []) if _normalize(s) in names]


def _match_assets(cve: models.CVE, assets) -> None:
    """Store affected products and matching assets (by NVD CPE data), then recompute the risk score."""
    cve.affected_products = sorted({p.replace("_", " ") for _, p in cpe_products(cve)})
    affected_count = sum(1 for asset in assets if matched_software(cve, asset.software_list))
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
