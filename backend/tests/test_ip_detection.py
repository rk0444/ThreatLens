"""Run: .venv\\Scripts\\python backend\\tests\\test_ip_detection.py  (also works under pytest). Network is mocked."""
import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models
from backend.services import abuseipdb, ip_blocklists

FEODO_JSON = json.dumps([{"ip_address": "5.188.10.50", "port": 443, "malware": "QakBot", "last_online": "2026-11-20"}])
DROP_NDJSON = ('{"cidr":"45.9.20.0/24","sblid":"SBL1","rir":"arin"}\n'
               '{"type":"metadata","records":1}\n')


def _db():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(models.Asset(id=7, name="hq-pc", os="nt", software_list=[], ip_address="10.0.0.5", status="Online"))
    db.commit()
    ip_blocklists._networks = None
    abuseipdb._paused_until = 0.0
    return db


def _feeds(feodo=FEODO_JSON, drop=DROP_NDJSON, fail=()):
    def get(url, headers, timeout):
        source = next(s for s, u in ip_blocklists.FEEDS.items() if u == url)
        if source in fail:
            raise ip_blocklists.requests.ConnectionError("down")
        return SimpleNamespace(text=feodo if source == ip_blocklists.FEODO else drop, raise_for_status=lambda: None)
    return mock.patch.object(ip_blocklists.requests, "get", side_effect=get)


def _abuseipdb(score=0, status=200):
    reply = SimpleNamespace(status_code=status, json=lambda: {"data": {
        "abuseConfidenceScore": score, "countryCode": "NL", "isp": "Example ISP", "usageType": "Data Center"}})
    return mock.patch.object(abuseipdb.requests, "get", return_value=reply)


def check(db, ip, machine_id=7):
    return asyncio.run(main.get_ip_reputation_endpoint(ip, machine_id, db))


def test_blocklists_parse_match_and_survive_a_failed_download():
    db = _db()
    with _feeds():
        assert ip_blocklists.sync_ip_blocklists(db) == {ip_blocklists.FEODO: 1, ip_blocklists.SPAMHAUS: 1}
    assert ip_blocklists.match("5.188.10.50", db)["reference"] == "QakBot C2, last online 2026-11-20"
    assert ip_blocklists.match("45.9.20.77", db) == {"source": "Spamhaus DROP", "network": "45.9.20.0/24",
                                                        "reference": "SBL1"}
    assert ip_blocklists.match("192.0.2.1", db) is None
    with _feeds(fail=(ip_blocklists.SPAMHAUS,), feodo="[]"):  # one feed down, the other empty
        assert ip_blocklists.sync_ip_blocklists(db) == {}
    assert ip_blocklists.match("45.9.20.77", db) and ip_blocklists.match("5.188.10.50", db)  # old rows kept


def test_invalid_and_private_ips_never_reach_abuseipdb():
    db = _db()
    with _abuseipdb() as api, mock.patch.object(abuseipdb, "ABUSEIPDB_API_KEY", "k"):
        try:
            check(db, "not-an-ip")
            assert False
        except HTTPException as e:
            assert e.status_code == 400
        for ip in ("10.0.0.9", "192.168.1.1", "127.0.0.1", "172.16.4.4"):
            assert check(db, ip)["is_malicious"] is False
        assert api.call_count == 0


def test_blocklist_hit_is_recorded_without_inventing_a_score():
    db = _db()
    with _feeds():
        ip_blocklists.sync_ip_blocklists(db)
    with _abuseipdb() as api, mock.patch.object(abuseipdb, "ABUSEIPDB_API_KEY", "k"):
        verdict = check(db, "45.9.20.77")
        assert api.call_count == 0  # the local list answered
    assert (verdict["is_malicious"], verdict["source"], verdict["reference"]) == (True, "Spamhaus DROP", "SBL1")
    row = db.query(models.FlaggedConnection).one()
    assert (row.machine_id, row.machine_hostname, row.source, row.reference, row.abuse_score) == \
           (7, "hq-pc", "Spamhaus DROP", "SBL1", None)
    check(db, "45.9.20.77")
    assert db.query(models.FlaggedConnection).one().times_seen == 2


def test_abuseipdb_answers_are_cached_a_day_and_quota_errors_are_not():
    db = _db()
    with _abuseipdb(score=5) as api, mock.patch.object(abuseipdb, "ABUSEIPDB_API_KEY", "k"):
        assert check(db, "8.8.8.8")["is_malicious"] is False
        assert check(db, "8.8.8.8")["source"] == "AbuseIPDB"
        assert api.call_count == 1  # second answer came from the cache
    assert db.query(models.FlaggedConnection).count() == 0  # clean IPs are not flagged
    with _abuseipdb(status=429) as api, mock.patch.object(abuseipdb, "ABUSEIPDB_API_KEY", "k"):
        assert "quota" in check(db, "1.0.0.1")["error"]
        assert "paused" in check(db, "1.0.0.2")["error"]
        assert api.call_count == 1  # paused after the 429
    assert db.query(models.IPReputationCache).filter_by(ip="1.0.0.1").count() == 0
    abuseipdb._paused_until = 0.0
    with _abuseipdb(score=90), mock.patch.object(abuseipdb, "ABUSEIPDB_API_KEY", "k"):
        verdict = check(db, "1.0.0.1")
    assert verdict["is_malicious"] and db.query(models.FlaggedConnection).one().abuse_score == 90


def test_old_flagged_connections_table_is_rebuilt_keeping_rows():
    path = os.path.join(tempfile.mkdtemp(), "old.sqlite")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE flagged_connections (id INTEGER NOT NULL PRIMARY KEY, machine_id INTEGER NOT NULL, "
                "machine_hostname VARCHAR NOT NULL, destination_ip VARCHAR NOT NULL, abuse_score INTEGER NOT NULL, "
                "country VARCHAR, isp VARCHAR, times_seen INTEGER NOT NULL, last_seen DATETIME NOT NULL, "
                "blocked BOOLEAN NOT NULL, created_at DATETIME NOT NULL)")
    con.execute("CREATE INDEX ix_flagged_connections_id ON flagged_connections (id)")
    con.execute("INSERT INTO flagged_connections VALUES (1,7,'h','203.0.113.9',90,'NL','isp',3,'2026-11-27',0,'2026-11-27')")
    con.commit()
    con.close()
    engine = create_engine(f"sqlite:///{path}")
    for _ in range(2):  # second run must be a no-op
        with engine.begin() as conn:
            main._relax_flagged_abuse_score(conn)
    con = sqlite3.connect(path)
    notnull = {r[1]: r[3] for r in con.execute("PRAGMA table_info(flagged_connections)")}
    assert notnull["abuse_score"] == 0 and "source" in notnull and "reference" in notnull
    assert con.execute("SELECT destination_ip, abuse_score, times_seen FROM flagged_connections").fetchall() == \
           [("203.0.113.9", 90, 3)]
    con.close()
    engine.dispose()


if __name__ == "__main__":
    test_blocklists_parse_match_and_survive_a_failed_download()
    test_invalid_and_private_ips_never_reach_abuseipdb()
    test_blocklist_hit_is_recorded_without_inventing_a_score()
    test_abuseipdb_answers_are_cached_a_day_and_quota_errors_are_not()
    test_old_flagged_connections_table_is_rebuilt_keeping_rows()
    print("ip detection tests passed")
