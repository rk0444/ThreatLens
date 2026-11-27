"""Run: .venv\\Scripts\\python backend\\tests\\test_endpoints.py  (also works under pytest)."""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models, schemas


def _db():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _cve(cve_id, score, band, product):
    criteria = f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*"
    return models.CVE(cve_id=cve_id, description="x", risk_score=score, risk_band=band, asset_affected=True,
                      raw_json={"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria}]}]}]})


def test_status_comes_from_heartbeat_and_exposure_from_published_cves():
    db = _db()
    long_ago = datetime.now(timezone.utc) - timedelta(days=190)
    db.add(models.Asset(id=7, name="PC", os="Windows 11", software_list=["chrome"], ip_address="10.0.0.5",
                        status="Online", last_seen=long_ago))  # stored "Online" must not be believed
    db.add_all([_cve("CVE-1", 74.2, "HIGH", "chrome"), _cve("CVE-2", 40.0, "MEDIUM", "chrome"),
                _cve("CVE-3", 99.0, "CRITICAL", "firefox")])  # firefox is not installed
    db.add_all([models.Incident(machine_id=7, type="old", severity="Low", status="Resolved", created_at=datetime(2026, 1, 1)),
                models.Incident(machine_id=7, type="new", severity="High", status="Active", created_at=datetime(2026, 11, 1))])
    db.commit()

    asset = asyncio.run(main.get_assets(db))[0]
    assert asset["online"] is False
    assert asset["last_seen"].endswith("+00:00")
    assert asset["matching_cve_count"] == 2
    assert asset["top_cve"] == {"cve_id": "CVE-1", "risk_score": 74.2, "risk_band": "HIGH"}
    assert asset["latest_incident_summary"] == "new"  # newest, not the first row
    assert "risk_score" not in asset and "threats_blocked" not in asset and "files_quarantined" not in asset

    asyncio.run(main.asset_heartbeat(7, db))
    assert asyncio.run(main.get_assets(db))[0]["online"] is True


def _cpe_cve(match):
    return models.CVE(cve_id="CVE-X", description="x", raw_json={"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, **match}]}]}]})


def test_installed_version_must_fall_in_nvd_range():
    from backend.services.asset_filter import matched_software
    chrome = _cpe_cve({"criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "158.0.8127.88"})
    assert matched_software(chrome, ["Google Chrome"], {"Google Chrome": "158.0.8127.38"}) == ["Google Chrome"]
    assert matched_software(chrome, ["Google Chrome"], {"Google Chrome": "158.0.8127.88"}) == []  # already patched
    assert matched_software(chrome, ["Google Chrome"]) == ["Google Chrome"]  # no version known: name only
    exact = _cpe_cve({"criteria": "cpe:2.3:a:rarlab:winrar:5.50:*:*:*:*:*:*:*"})
    assert matched_software(exact, ["WinRAR 5.50 (64-bit)"], {"WinRAR 5.50 (64-bit)": "5.50.0"}) == ["WinRAR 5.50 (64-bit)"]
    assert matched_software(exact, ["WinRAR 6.0"], {"WinRAR 6.0": "6.0"}) == []
    code = _cpe_cve({"criteria": "cpe:2.3:a:microsoft:visual_studio_code:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.140",
                     "versionEndIncluding": "1.147.0"})
    name = "Microsoft Visual Studio Code (User)"  # the "(User)" suffix must not hide the product
    assert matched_software(code, [name], {name: "1.147.0"}) == [name]


def test_agent_inventory_updates_the_asset():
    db = _db()
    db.add(models.Asset(id=7, name="PC", os="nt", software_list=[], ip_address="192.168.49.1"))
    db.commit()
    main.rematch_in_background = lambda: None  # no background thread in a unit test
    inv = schemas.AssetInventory(os="Windows 11 (build 10.0.26300)", ip_address="192.168.0.100",
                                 software_list=["Google Chrome"], software_versions={"Google Chrome": "158.0.8127.38"})
    result = asyncio.run(main.update_asset_inventory(7, inv, db))
    assert result["rematching"] is True
    asset = db.query(models.Asset).one()
    assert (asset.os, asset.ip_address, asset.software_versions) == (inv.os, inv.ip_address, inv.software_versions)
    assert asyncio.run(main.update_asset_inventory(7, inv, db))["rematching"] is False  # unchanged: no re-match


def test_register_does_not_need_a_status():
    assert schemas.AssetCreate(name="PC", os="Windows 11", software_list=[], ip_address="10.0.0.5").status is None


if __name__ == "__main__":
    test_status_comes_from_heartbeat_and_exposure_from_published_cves()
    test_register_does_not_need_a_status()
    test_installed_version_must_fall_in_nvd_range()
    test_agent_inventory_updates_the_asset()
    print("endpoints tests passed")
