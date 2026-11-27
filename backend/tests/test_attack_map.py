"""Run: .venv\\Scripts\\python backend\\tests\\test_attack_map.py  (also works under pytest)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models


def test_map_uses_only_published_otx_fields():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.MitreGroup(mitre_id="G0046", name="FIN7", aliases=["Carbon Spider"], techniques=["Phishing"]))
    db.add_all([
        models.OSINTAlert(source="AlienVault OTX", indicator="a", type="Pulse", description="", severity="Medium",
                          adversary="carbon spider", targeted_countries=["United States of America", "Japan"],
                          industries=["Finance"]),
        models.OSINTAlert(source="AlienVault OTX", indicator="b", type="Pulse", description="Russia China Iran",
                          severity="Medium", adversary="Unlisted Crew", targeted_countries=["Japan", "Atlantis"],
                          industries=["Energy"]),
        models.OSINTAlert(source="AlienVault OTX", indicator="c", type="Pulse", description="Lazarus targets the USA",
                          severity="High", adversary=None, targeted_countries=[], industries=["Retail"]),
    ])
    db.commit()

    result = asyncio.run(main.get_attack_map(db))
    nodes = {n["country"]: n for n in result["nodes"]}
    assert set(nodes) == {"United States", "Japan"}  # alert c's description is never read
    assert nodes["Japan"]["alert_count"] == 2 and nodes["United States"]["alert_count"] == 1
    assert nodes["United States"]["sectors"] == ["Finance"]  # per country, not global
    assert sorted(nodes["Japan"]["sectors"]) == ["Energy", "Finance"]
    fin7 = nodes["United States"]["actors"][0]
    assert (fin7["name"], fin7["mitre_id"], fin7["techniques"]) == ("FIN7", "G0046", ["Phishing"])  # alias match
    assert {a["mitre_id"] for a in nodes["Japan"]["actors"]} == {"G0046", None}  # unlisted actor kept, not linked
    assert result["unmapped_countries"] == ["Atlantis"]  # reported, not silently dropped
    assert "threat_level" not in nodes["Japan"] and "activity_score" not in nodes["Japan"]
    assert result["summary"]["alerts_with_countries"] == 2 and result["summary"]["osint_alerts"] == 3


def test_map_is_empty_without_published_countries():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.MitreGroup(mitre_id="G0032", name="Lazarus Group", aliases=[], techniques=[]))
    db.add(models.OSINTAlert(source="AlienVault OTX", indicator="x", type="Pulse", description="North Korea",
                             severity="Medium", targeted_countries=[]))
    db.commit()
    result = asyncio.run(main.get_attack_map(db))
    assert result["nodes"] == [] and result["summary"]["targeted_countries"] == 0


def test_same_country_or_actor_spelled_twice_counts_once():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.MitreGroup(mitre_id="G0046", name="FIN7", aliases=["Carbon Spider"], techniques=[]))
    db.add_all([
        models.OSINTAlert(source="AlienVault OTX", indicator="a", type="Pulse", description="", severity="Medium",
                          adversary="FIN7", targeted_countries=["United States", "United States of America"],
                          industries=["Retail"]),
        models.OSINTAlert(source="AlienVault OTX", indicator="b", type="Pulse", description="", severity="Medium",
                          adversary="Carbon Spider", targeted_countries=["USA"], industries=[]),
        models.OSINTAlert(source="AlienVault OTX", indicator="c", type="Pulse", description="", severity="Medium",
                          adversary="Some Crew", targeted_countries=["usa"]),
        models.OSINTAlert(source="AlienVault OTX", indicator="d", type="Pulse", description="", severity="Medium",
                          adversary="some crew", targeted_countries=["USA"]),
    ])
    db.commit()
    us = asyncio.run(main.get_attack_map(db))["nodes"][0]
    assert us["alert_count"] == 4  # alert a names the US twice but counts once
    actors = {(a["name"], a["mitre_id"]): a["alert_count"] for a in us["actors"]}
    assert actors == {("FIN7", "G0046"): 2, ("Some Crew", None): 2}


def _db():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_asset_pins_only_where_the_user_placed_them():
    from backend.database import schemas
    db = _db()
    db.add_all([
        models.Asset(id=7, name="hq-pc", os="nt", software_list=[], ip_address="10.0.0.5", status="Online"),
        models.Asset(id=8, name="laptop", os="nt", software_list=[], ip_address="10.0.0.6", status="Online"),
        models.Incident(id=1, machine_id=7, type="process_anomaly", severity="High", details="x", status="Active"),
        models.Incident(id=2, machine_id=7, type="network", severity="Critical", details="y", status="Resolved"),
    ])
    db.commit()
    assert asyncio.run(main.get_attack_map(db))["asset_pins"] == []  # nothing placed yet
    asyncio.run(main.set_asset_location(7, schemas.AssetLocation(latitude=28.6139, longitude=77.209,
                                                                 location_label="HQ"), db))
    pins = asyncio.run(main.get_attack_map(db))["asset_pins"]
    assert [(p["id"], p["lat"], p["lng"], p["location_label"]) for p in pins] == [(7, 28.6139, 77.209, "HQ")]
    assert [i["id"] for i in pins[0]["open_incidents"]] == [1]  # resolved incident left out
    assert pins[0]["highest_severity"] == "High"
    asyncio.run(main.set_asset_location(7, schemas.AssetLocation(), db))  # cleared
    assert asyncio.run(main.get_attack_map(db))["asset_pins"] == []


def test_location_must_be_valid_and_complete():
    from fastapi import HTTPException
    from pydantic import ValidationError
    from backend.database import schemas
    for bad in ({"latitude": 91, "longitude": 0}, {"latitude": 0, "longitude": -181}):
        try:
            schemas.AssetLocation(**bad)
            assert False, bad
        except ValidationError:
            pass
    db = _db()
    db.add(models.Asset(id=7, name="h", os="nt", software_list=[], ip_address="1", status="Online"))
    db.commit()
    try:
        asyncio.run(main.set_asset_location(7, schemas.AssetLocation(latitude=10), db))
        assert False, "latitude without longitude"
    except HTTPException as e:
        assert e.status_code == 422


def test_ip_areas_are_approximate_and_skip_unlocated_ips():
    from unittest import mock
    db = _db()
    db.add_all([
        models.FlaggedConnection(machine_id=7, machine_hostname="hq-pc", destination_ip="203.0.113.9",
                                 abuse_score=90, times_seen=1, blocked=False),
        models.FlaggedConnection(machine_id=7, machine_hostname="hq-pc", destination_ip="198.51.100.1",
                                 abuse_score=80, times_seen=1, blocked=False),
        models.OSINTAlert(source="IOC Hunter", indicator="203.0.113.9", type="IP", description="", severity="High"),
    ])
    db.commit()
    places = {"203.0.113.9": {"lat": 52.37, "lng": 4.89, "accuracy_km": 20, "city": "Amsterdam", "country": "Netherlands"}}
    with mock.patch.object(main.geoip, "locate", side_effect=places.get), \
         mock.patch.object(main.geoip, "configured", return_value=True):
        result = asyncio.run(main.get_attack_map(db))
    assert result["geoip_configured"] is True
    assert [(a["ip"], a["accuracy_km"], a["abuse_score"]) for a in result["ip_areas"]] == [("203.0.113.9", 20, 90)]


def test_geoip_off_without_database():
    from unittest import mock
    from backend.services import geoip
    with mock.patch.dict(os.environ, {"GEOIP_DB_PATH": ""}):
        assert geoip.configured() is False and geoip.locate("8.8.8.8") is None
    with mock.patch.dict(os.environ, {"GEOIP_DB_PATH": __file__}), mock.patch.object(geoip, "_reader"):
        assert geoip.locate("10.0.0.5") is None  # private addresses are never looked up


if __name__ == "__main__":
    test_map_uses_only_published_otx_fields()
    test_map_is_empty_without_published_countries()
    test_same_country_or_actor_spelled_twice_counts_once()
    test_asset_pins_only_where_the_user_placed_them()
    test_location_must_be_valid_and_complete()
    test_ip_areas_are_approximate_and_skip_unlocated_ips()
    test_geoip_off_without_database()
    print("attack map tests passed")
