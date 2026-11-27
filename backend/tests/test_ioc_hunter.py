"""Run: .venv\\Scripts\\python backend\\tests\\test_ioc_hunter.py  (also works under pytest). No network calls."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models, schemas
from backend.services import virustotal


def _db():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_types():
    assert main._detect_ioc_type("2001:db8::1") == "ip"          # IPv6 accepted
    assert main._detect_ioc_type("8.8.8.8") == "ip"
    assert main._detect_ioc_type("999.1.1.1") == "unknown"       # not a valid IPv4
    assert main._detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert main._detect_ioc_type("HTTPS://example.com/x") == "url"
    assert main._detect_ioc_type("example.com") == "domain"


def test_verdicts_never_default_to_clean():
    db = _db()
    look = lambda ioc: main.ioc_lookup(schemas.IOCLookup(ioc=ioc), db)
    assert look("192.168.0.1")["verdict"] == "Not checked"       # private: nothing was asked

    virustotal.check_file_hash = lambda h: {"found": False, "message": "no report"}
    assert look("0" * 64)["verdict"] == "Unknown"                 # never seen is not safe

    virustotal.check_file_hash = lambda h: {"error": "VirusTotal quota used up (HTTP 429)"}
    assert look("0" * 64)["verdict"] == "Unknown"                 # a failed source is not a clean result

    virustotal.check_domain_reputation = lambda d: {"found": True, "malicious": 0, "suspicious": 0, "harmless": 60,
                                                    "undetected": 10, "reputation": 5}
    r = look("example.com")
    assert (r["verdict"], r["checked_by"]) == ("Not flagged", ["VirusTotal"])

    virustotal.check_file_hash = lambda h: {"found": True, "malicious": 56, "suspicious": 0, "harmless": 0,
                                            "undetected": 2, "reputation": 3804}
    r = look("44d88612fea8a8f36de82e1278abb02f")
    assert (r["verdict"], r["saved"]) == ("Flagged", False)       # VT gives counts, not a verdict
    assert r["tags"] == ["VirusTotal: 56 of 58 engines flagged it"]
    assert db.query(models.OSINTAlert).count() == 0               # nothing is stored without asking

    try:
        look("not an ioc")
        assert False, "accepted garbage"
    except HTTPException as e:
        assert e.status_code == 422


def test_save_only_when_asked_and_once():
    db = _db()
    body = schemas.IOCSave(ioc="44d88612fea8a8f36de82e1278abb02f", summary="VirusTotal: 56 engines flagged it")
    assert main.ioc_save(body, db)["already_saved"] is False
    assert main.ioc_save(body, db)["already_saved"] is True
    alert = db.query(models.OSINTAlert).one()
    assert (alert.source, alert.type) == ("IOC Hunter", "HASH")


if __name__ == "__main__":
    test_types()
    test_verdicts_never_default_to_clean()
    test_save_only_when_asked_and_once()
    print("ioc hunter tests passed")
