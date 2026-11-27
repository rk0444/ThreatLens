"""Run: .venv\\Scripts\\python backend\\tests\\test_incidents.py  (also works under pytest)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models, schemas


def test_analyst_sets_status_by_hand_and_it_is_logged():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.Incident(id=1, machine_id=7, type="network_anomaly", severity="Critical", status="Active", timeline=[]))
    db.commit()

    act = lambda a, note=None: asyncio.run(main.respond_to_incident(1, schemas.AnalystAction(action=a, analyst_note=note), db))
    assert act("investigate")["incident_status"] == "Investigating"
    assert act("resolve", "blocked at firewall")["incident_status"] == "Resolved"
    timeline = db.query(models.Incident).one().timeline
    assert [e["action"] for e in timeline] == ["Analyst marked the incident investigating",
                                                "Analyst marked the incident resolved. Note: blocked at firewall"]
    assert "T" in timeline[0]["time"] and timeline[0]["time"].endswith("+00:00")  # ISO with offset
    try:
        act("approve")  # old wording referred to an auto-response that doesn't exist
        assert False, "unknown action accepted"
    except HTTPException as e:
        assert e.status_code == 422


def test_made_up_correlation_route_is_gone():
    paths = {getattr(r, "path", "") for r in main.app.routes}
    assert "/api/incidents/{incident_id}/correlations" not in paths


if __name__ == "__main__":
    test_analyst_sets_status_by_hand_and_it_is_logged()
    test_made_up_correlation_route_is_gone()
    print("incidents tests passed")
