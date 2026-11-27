"""Run: .venv\\Scripts\\python backend\\tests\\test_overview.py  (also works under pytest)."""
import asyncio
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models


def test_overview_times_carry_utc_offset_and_top_threats_carry_band():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.CVE(cve_id="CVE-2026-0001", description="x", risk_score=74.2, risk_band="HIGH",
                      created_at=datetime(2026, 11, 27, 17, 25, 55)))  # SQLite returns naive UTC
    db.add(models.MorningBrief(date=datetime(2026, 11, 27, 3, 0), content="brief", top_threats=[],
                               active_incidents=[], patterns="", actions=[]))
    db.commit()
    result = asyncio.run(main.get_overview(db))
    assert result["activityLog"][0]["timestamp"] == "2026-11-27T17:25:55+00:00"  # not read as local time
    assert result["morningBrief"]["date"] == "2026-11-27T03:00:00+00:00"
    assert result["topThreats"][0]["risk_band"] == "HIGH"


def test_activity_log_is_newest_first_and_names_the_asset():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.Asset(id=7, name="Workstation-1", os="Windows", software_list=[], ip_address="10.0.0.5", status="Online"))
    db.add(models.CVE(cve_id="CVE-2026-0001", description="x", risk_band="HIGH", created_at=datetime(2026, 11, 27, 10, 0)))
    db.add(models.Incident(machine_id=7, type="Suspicious process", severity="High", status="Active",
                           created_at=datetime(2026, 11, 27, 12, 0)))
    db.commit()
    log = asyncio.run(main.get_overview(db))["activityLog"]
    assert [a["type"] for a in log] == ["Incident", "CVE"]  # newer incident first, not CVEs then incidents
    assert log[0]["message"] == "Suspicious process on Workstation-1"


if __name__ == "__main__":
    test_overview_times_carry_utc_offset_and_top_threats_carry_band()
    test_activity_log_is_newest_first_and_names_the_asset()
    print("overview tests passed")
