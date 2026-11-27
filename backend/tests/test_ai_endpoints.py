"""Run: .venv\\Scripts\\python backend\\tests\\test_ai_endpoints.py  (also works under pytest). GPT-4o is mocked."""
import asyncio
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend import main
from backend.database import models


def _session():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(models.Asset(id=7, name="host", os="nt", software_list=[], ip_address="10.0.0.1", status="Online"))
    session.add(models.Incident(id=1, machine_id=7, type="process_anomaly", severity="High",
                                process_name="winword.exe -> cmd.exe", details="cmd spawned by winword", status="Active"))
    session.add(models.CVE(cve_id="CVE-2026-0001", description="x", risk_score=80, risk_band="HIGH", cisa_kev=True))
    session.commit()
    return session


def test_brief_stores_model_output_and_real_top_threats():
    session = _session()
    reply = {"summary": "One HIGH CVE on KEV.", "patterns": "", "actions": [{"task": "Patch CVE-2026-0001", "priority": "High"}, "junk"]}
    with mock.patch.object(main, "ask_gpt4o_json", mock.AsyncMock(return_value=reply)) as ask:
        brief = asyncio.run(main.generate_morning_brief(session))
    prompt = ask.call_args.args[1]
    assert "CVE-2026-0001 Risk:80 (HIGH)" in prompt and "winword.exe -> cmd.exe" in prompt
    assert brief.content == "One HIGH CVE on KEV."
    assert brief.actions == [{"task": "Patch CVE-2026-0001", "priority": "High"}]  # non-dict dropped
    assert brief.top_threats == [{"name": "CVE-2026-0001", "risk": "HIGH"}]  # from the DB, not the model


def test_playbook_numbers_steps_and_rejects_empty():
    session = _session()
    reply = {"steps": [{"action": "Collect cmd.exe command line", "command": "", "priority": "high", "risk_level": "low"},
                       {"command": "no action -> dropped"}]}
    with mock.patch.object(main, "ask_gpt4o_json", mock.AsyncMock(return_value=reply)) as ask:
        book = asyncio.run(main.get_incident_playbook(1, session))
    assert '"os": "nt"' in ask.call_args.args[1]
    assert book["total_steps"] == 1 and book["steps"][0]["step"] == 1 and book["model"] == "gpt-4o"
    with mock.patch.object(main, "ask_gpt4o_json", mock.AsyncMock(return_value={"steps": []})):
        try:
            asyncio.run(main.get_incident_playbook(1, session))
            assert False, "empty playbook must be an error, not a fallback"
        except HTTPException as e:
            assert e.status_code == 502


def test_missing_key_is_an_error():
    with mock.patch.dict(os.environ, {"GPT4O_API_KEY": ""}):
        try:
            asyncio.run(main.ask_gpt4o("s", "u"))
            assert False
        except HTTPException as e:
            assert e.status_code == 503


def test_cve_summary_is_stored_and_reused():
    session = _session()
    assert asyncio.run(main.get_cve_ai_summary("CVE-2026-0001", session)) == {"generated": False}
    reply = {"what_is_affected": "a", "how_it_works": "b", "what_to_do_now": "c"}
    with mock.patch.object(main, "ask_gpt4o_json", mock.AsyncMock(return_value=reply)) as ask:
        asyncio.run(main.generate_cve_ai_summary("CVE-2026-0001", session))
    assert '"cve_id": "CVE-2026-0001"' in ask.call_args.args[1]
    stored = asyncio.run(main.get_cve_ai_summary("CVE-2026-0001", session))
    assert stored["what_to_do_now"] == "c" and stored["generated"] is True and "confidence_score" not in stored
    with mock.patch.object(main, "ask_gpt4o_json", mock.AsyncMock(return_value={"what_is_affected": "a"})):
        try:
            asyncio.run(main.generate_cve_ai_summary("CVE-2026-0001", session))
            assert False, "incomplete summary must be an error"
        except HTTPException as e:
            assert e.status_code == 502


def test_cve_correlation_needs_a_real_asset_match():
    session = _session()  # incident #1 is open on asset 7, which runs no matching software
    cve = session.query(models.CVE).one()
    assert asyncio.run(main.get_cve_correlations("CVE-2026-0001", session)) == {"affected_assets": [], "open_incidents": []}
    cve.cvss_score = None  # used to crash the old endpoint
    cve.raw_json = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}]}]}]}
    session.query(models.Asset).one().software_list = ["OpenSSL 3.0"]
    session.commit()
    result = asyncio.run(main.get_cve_correlations("CVE-2026-0001", session))
    assert result["affected_assets"] == [{"id": 7, "name": "host", "software": ["OpenSSL 3.0"]}]
    assert [i["id"] for i in result["open_incidents"]] == [1]


if __name__ == "__main__":
    test_brief_stores_model_output_and_real_top_threats()
    test_playbook_numbers_steps_and_rejects_empty()
    test_missing_key_is_an_error()
    test_cve_summary_is_stored_and_reused()
    test_cve_correlation_needs_a_real_asset_match()
    print("AI endpoint tests passed")
