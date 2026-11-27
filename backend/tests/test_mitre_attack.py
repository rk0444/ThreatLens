"""Run: .venv\\Scripts\\python backend\\tests\\test_mitre_attack.py  (also works under pytest)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import models
from backend.services import mitre_attack


def _ref(ext_id):
    return [{"source_name": "mitre-attack", "external_id": ext_id}]


def _sync(objects, db):
    with tempfile.TemporaryDirectory() as tmp:
        mitre_attack.CACHE_FILE = os.path.join(tmp, "bundle.json")  # fresh file, so no download
        with open(mitre_attack.CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"objects": objects}, f)
        mitre_attack.sync_mitre_data(db)


def _db():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_retired_groups_and_techniques_are_skipped_and_removed():
    db = _db()
    db.add(models.MitreGroup(mitre_id="G0057", name="APT34", aliases=[], techniques=[]))  # left by an older sync
    db.add(models.MitreTechnique(technique_id="T9999", name="Old", tactic="", associated_groups=[]))
    db.commit()
    _sync([
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "OilRig", "aliases": ["APT34"], "external_references": _ref("G0049")},
        {"type": "intrusion-set", "id": "intrusion-set--2", "name": "APT34", "revoked": True, "external_references": _ref("G0057")},
        {"type": "intrusion-set", "id": "intrusion-set--3", "name": "Frankenstein", "x_mitre_deprecated": True, "external_references": _ref("G0101")},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Phishing", "external_references": _ref("T1566"),
         "kill_chain_phases": [{"phase_name": "initial-access"}]},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Retired", "x_mitre_deprecated": True, "external_references": _ref("T1000")},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--2"},
        {"type": "attack-pattern", "id": "attack-pattern--3", "name": "Old link", "external_references": _ref("T1001")},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--3", "revoked": True},
    ], db)
    groups = {g.mitre_id: g for g in db.query(models.MitreGroup).all()}
    assert set(groups) == {"G0049"}
    assert groups["G0049"].techniques == ["Phishing"]
    assert {t.technique_id for t in db.query(models.MitreTechnique).all()} == {"T1566", "T1001"}
    assert db.query(models.MitreTechnique).filter_by(technique_id="T1001").one().associated_groups == []  # revoked link ignored


def test_descriptions_names_and_tactics_are_refreshed():
    db = _db()
    db.add(models.MitreGroup(mitre_id="G0049", name="Old name", aliases=[], techniques=[]))
    db.add(models.MitreTechnique(technique_id="T1078", name="Old", tactic="old", associated_groups=[]))
    db.commit()
    _sync([
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "OilRig", "external_references": _ref("G0049"),
         "description": "[OilRig](https://attack.mitre.org/groups/G0049) uses [Helminth](https://attack.mitre.org/software/S0170).(Citation: FireEye APT34 Dec 2017)(Citation: Unit 42)"},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Valid Accounts", "external_references": _ref("T1078"),
         "kill_chain_phases": [{"phase_name": "persistence"}, {"phase_name": "initial-access"}]},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Cloud Accounts", "external_references": _ref("T1078.004"),
         "kill_chain_phases": [{"phase_name": "new-tactic"}]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Persistence", "x_mitre_shortname": "persistence"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "name": "Initial Access", "x_mitre_shortname": "initial-access"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--2"},
    ], db)
    group = db.query(models.MitreGroup).one()
    assert (group.name, group.description) == ("OilRig", "OilRig uses Helminth.")
    assert group.techniques == ["Valid Accounts: Cloud Accounts"]  # sub-technique named with its parent
    techs = {t.technique_id: t for t in db.query(models.MitreTechnique).all()}
    assert (techs["T1078"].name, techs["T1078"].tactic) == ("Valid Accounts", "Persistence, Initial Access")
    assert techs["T1078.004"].tactic == "new-tactic"  # no published display name: keep MITRE's tag


def test_detail_lists_technique_ids():
    import asyncio
    from backend import main
    db = _db()
    group = models.MitreGroup(mitre_id="G0049", name="OilRig", aliases=[], techniques=["Web Protocols"])
    db.add(group)
    db.add_all([
        models.MitreTechnique(technique_id="T1071.001", name="Web Protocols", tactic="command-and-control", associated_groups=["G0049"]),
        models.MitreTechnique(technique_id="T1566", name="Phishing", tactic="initial-access", associated_groups=["G0007"]),
    ])
    db.commit()
    detail = asyncio.run(main.get_threat_actor_detail(group.id, db))
    assert [t["technique_id"] for t in detail["techniques"]] == ["T1071.001"]


def test_unreadable_cache_is_removed_so_next_run_downloads():
    db = _db()
    with tempfile.TemporaryDirectory() as tmp:
        mitre_attack.CACHE_FILE = os.path.join(tmp, "bundle.json")
        with open(mitre_attack.CACHE_FILE, "w", encoding="utf-8") as f:
            f.write('{"objects": [{"type": "intrus')  # half-written file with today's date
        mitre_attack.sync_mitre_data(db)
        assert not os.path.exists(mitre_attack.CACHE_FILE)


def test_list_is_sorted_by_name():
    import asyncio
    from backend import main
    db = _db()
    db.add_all([models.MitreGroup(mitre_id=g, name=n, aliases=[], techniques=["Phishing"], description="long text")
                for g, n in [("G1", "Turla"), ("G2", "admin@338"), ("G3", "APT28")]])
    db.commit()
    result = asyncio.run(main.get_all_threat_actors(db))
    assert [a["name"] for a in result] == ["admin@338", "APT28", "Turla"]
    assert result[0]["technique_count"] == 1 and "description" not in result[0]  # list stays small


def test_empty_bundle_keeps_existing_data():
    db = _db()
    db.add(models.MitreGroup(mitre_id="G0049", name="OilRig", aliases=[], techniques=[]))
    db.commit()
    _sync([], db)
    assert db.query(models.MitreGroup).count() == 1


if __name__ == "__main__":
    test_retired_groups_and_techniques_are_skipped_and_removed()
    test_descriptions_names_and_tactics_are_refreshed()
    test_detail_lists_technique_ids()
    test_unreadable_cache_is_removed_so_next_run_downloads()
    test_list_is_sorted_by_name()
    test_empty_bundle_keeps_existing_data()
    print("ok")
