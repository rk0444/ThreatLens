"""Run: .venv\\Scripts\\python backend\\tests\\test_scoring.py  (also works under pytest)."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from backend.services.scoring import calculate_risk_score as score


def test_epss_percentile_preferred_over_raw():
    assert score(epss_score=0.0003, epss_percentile=0.5)["breakdown"]["epss"] == 10.0
    assert score(epss_score=0.5)["breakdown"]["epss"] == 10.0  # falls back to raw EPSS


def test_kev_floors():
    assert score(cvss_score=2, cisa_kev=True)["band"] == "HIGH"
    assert score(cvss_score=2, cisa_kev=True, asset_affected=True)["band"] == "CRITICAL"
    assert score(cvss_score=2, asset_affected=True)["band"] == "LOW"  # no floor without KEV


def test_asset_match_sets_count_clears_and_rescores():
    from types import SimpleNamespace
    from backend.services.asset_filter import _match_assets

    raw = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}]}]}]}
    cve = SimpleNamespace(description="Mentions nginx and Python bindings", raw_json=raw, cvss_score=2,
                          epss_score=0, epss_percentile=None, cisa_kev=True, actively_exploited=True,
                          asset_affected=False, affected_asset_count=0, ransomware_use=False,
                          patch_available=True, published_date=None, risk_score=None, risk_band=None)
    # matches the CPE product only; names that merely appear in the description don't count
    assets = [SimpleNamespace(software_list=["OpenSSL 3.0"]), SimpleNamespace(software_list=["nginx", "Python 3.10"])]
    _match_assets(cve, assets)
    assert (cve.asset_affected, cve.affected_asset_count, cve.risk_band) == (True, 1, "CRITICAL")
    _match_assets(cve, [])  # asset removed -> match cleared, back to KEV floor
    assert (cve.asset_affected, cve.affected_asset_count, cve.risk_band) == (False, 0, "HIGH")
    cve.raw_json = {}  # NVD hasn't analysed the CVE yet -> no match
    _match_assets(cve, assets)
    assert cve.asset_affected is False


def test_evidence_flags_use_published_sources_only():
    from backend.services.nvd import evidence_flags

    words = {"references": [{"tags": ["Vendor Advisory"]}],
             "descriptions": [{"value": "actively exploited ransomware, no patch"}]}
    assert evidence_flags(words) == (False, False, False)  # description wording is ignored
    tagged = {"references": [{"tags": ["Exploit"]}, {"tags": ["Patch", "Vendor Advisory"]}]}
    assert evidence_flags(tagged) == (True, False, True)
    assert evidence_flags({}, cisa_kev=True, kev_ransomware=True) == (True, True, False)


if __name__ == "__main__":
    test_epss_percentile_preferred_over_raw()
    test_kev_floors()
    test_asset_match_sets_count_clears_and_rescores()
    test_evidence_flags_use_published_sources_only()
    print("scoring tests passed")
