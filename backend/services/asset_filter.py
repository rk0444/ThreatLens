import re
from sqlalchemy.orm import Session
from backend.database import models
from backend.services.scoring import rescore_cve


def _vulnerable_matches(cve: models.CVE) -> list:
    """NVD cpeMatch entries marked vulnerable (empty until NVD analyses the CVE)."""
    configs = (cve.raw_json or {}).get("configurations", [])
    return [m for config in configs for node in config.get("nodes", []) for m in node.get("cpeMatch", [])
            if m.get("vulnerable") and len(m.get("criteria", "").split(":")) > 5]


def cpe_products(cve: models.CVE) -> set:
    """(vendor, product) pairs NVD lists as vulnerable for this CVE (empty until NVD analyses it)."""
    return {tuple(m["criteria"].split(":")[3:5]) for m in _vulnerable_matches(cve)}


def _normalize(software: str) -> str:
    # "Python 3.10 (64-bit)" -> "python", "Google Chrome" -> "google_chrome", "VS Code (User)" -> "vs_code"
    software = re.sub(r"\([^)]*\)", " ", software.lower())
    words = [w for w in re.split(r"[\s_]+", software) if w and not any(c.isdigit() for c in w)]
    return "_".join(words)


def _version_tuple(version) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", str(version or "")))


def _version_in_range(match: dict, installed: str) -> bool:
    """Whether an installed version falls inside one NVD cpeMatch entry (exact version or version range)."""
    v = _version_tuple(installed)
    exact = match["criteria"].split(":")[5]
    if exact not in ("*", "-", ""):  # one specific version listed
        e = _version_tuple(exact)
        if v[:len(e)] != e:
            return False
    checks = [("versionStartIncluding", lambda b: v >= b), ("versionStartExcluding", lambda b: v > b),
              ("versionEndIncluding", lambda b: v <= b), ("versionEndExcluding", lambda b: v < b)]
    return all(test(_version_tuple(match[key])) for key, test in checks if key in match)


def matched_software(cve: models.CVE, software_list, versions=None) -> list:
    """Asset software entries that NVD lists as vulnerable for this CVE.

    With an installed version (agent inventory), the version must fall in NVD's published range.
    shortcut: without one (manually registered software), the product name alone matches;
    upgrade by recording versions when software is entered by hand.
    """
    matches = _vulnerable_matches(cve)
    if not matches:
        return []
    found = []
    for software in software_list or []:
        name = _normalize(software)
        hits = [m for m in matches if name in {m["criteria"].split(":")[4], "_".join(m["criteria"].split(":")[3:5])}]
        installed = (versions or {}).get(software)
        if hits and (not _version_tuple(installed) or any(_version_in_range(m, installed) for m in hits)):
            found.append(software)
    return found


def _match_assets(cve: models.CVE, assets) -> None:
    """Store affected products and matching assets (by NVD CPE data), then recompute the risk score."""
    cve.affected_products = sorted({p.replace("_", " ") for _, p in cpe_products(cve)})
    affected_count = sum(1 for asset in assets if matched_software(cve, asset.software_list, asset.software_versions))
    cve.asset_affected = affected_count > 0
    cve.affected_asset_count = affected_count
    rescore_cve(cve)


def rematch_all_cves(db_session: Session) -> int:
    """Re-match every stored CVE after the asset inventory changes. Returns affected count."""
    assets = db_session.query(models.Asset).all()
    affected = 0
    for cve in db_session.query(models.CVE).all():
        _match_assets(cve, assets)
        affected += cve.asset_affected
    db_session.commit()
    return affected
