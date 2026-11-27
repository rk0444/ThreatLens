from datetime import datetime, timezone


def rescore_cve(cve):
    """Recompute and store risk_score/risk_band on a CVE model from its own fields."""
    risk = calculate_risk_score(
        cvss_score=cve.cvss_score or 0,
        epss_score=cve.epss_score or 0,
        epss_percentile=cve.epss_percentile,
        cisa_kev=bool(cve.cisa_kev),
        actively_exploited=bool(cve.actively_exploited),
        asset_affected=bool(cve.asset_affected),
        affected_asset_count=cve.affected_asset_count or 0,
        ransomware_use=bool(cve.ransomware_use),
        patch_available=cve.patch_available,
        published_date=cve.published_date,
    )
    cve.risk_score = risk["score"]
    cve.risk_band = risk["band"]
    return risk


def calculate_risk_score(
    cvss_score=0,
    epss_score=0,
    cisa_kev=False,
    epss_percentile=None,
    actively_exploited=False,
    asset_affected=False,
    affected_asset_count=0,
    ransomware_use=False,
    patch_available=None,
    published_date=None,
):
    """
    ThreatLens Risk Score v2 (0-100)
    Formula:
      0.25 × CVSS + 0.20 × EPSS percentile + 0.15 × KEV + 0.10 × Exploit
    + 0.10 × Asset + 0.05 × Exposure + 0.05 × Threat
    + 0.05 × Patch + 0.05 × Temporal
    All components normalized to 0-100 before weighting.
    """

    # 1. CVSS Component (0-100 normalized) × 0.25
    cvss_component = ((cvss_score or 0) / 10.0) * 100 * 0.25

    # 2. EPSS Component × 0.20 — percentile, since raw EPSS is heavily skewed toward 0
    epss_component = (epss_percentile if epss_percentile is not None else (epss_score or 0)) * 100 * 0.20

    # 3. KEV Component (binary) × 0.15
    kev_component = 100 * 0.15 if cisa_kev else 0

    # 4. Exploit Component (binary) × 0.10
    exploit_component = 100 * 0.10 if actively_exploited else 0

    # 5. Asset Component (binary) × 0.10
    asset_component = 100 * 0.10 if asset_affected else 0

    # 6. Exposure Component (scaled by asset count) × 0.05
    if not asset_affected:
        exposure_component = 0
    elif affected_asset_count >= 10:
        exposure_component = 100 * 0.05
    elif affected_asset_count >= 5:
        exposure_component = 75 * 0.05
    elif affected_asset_count >= 2:
        exposure_component = 50 * 0.05
    else:
        exposure_component = 25 * 0.05

    # 7. Threat Component (ransomware association) × 0.05
    threat_component = 100 * 0.05 if ransomware_use else 0

    # 8. Patch Component (no patch = higher risk) × 0.05
    patch_component = 100 * 0.05 if patch_available is False else 0

    # 9. Temporal Component (recency) × 0.05
    temporal_component = 0.0
    if published_date:
        if published_date.tzinfo is None:
            published_date = published_date.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - published_date).days
        if days <= 7:
            temporal_component = 100 * 0.05
        elif days <= 30:
            temporal_component = 60 * 0.05
        elif days <= 90:
            temporal_component = 30 * 0.05

    total_score = min(100.0, max(0.0,
        cvss_component + epss_component + kev_component +
        exploit_component + asset_component + exposure_component +
        threat_component + patch_component + temporal_component
    ))

    # Confirmed exploitation floors (CISA KEV): KEV >= HIGH, KEV on your assets = CRITICAL
    if cisa_kev:
        total_score = max(total_score, 86.0 if asset_affected else 61.0)

    # Band classification
    if total_score >= 86:
        band, color = "CRITICAL", "pulsing-red"
    elif total_score >= 61:
        band, color = "HIGH", "red"
    elif total_score >= 31:
        band, color = "MEDIUM", "orange"
    else:
        band, color = "LOW", "green"

    return {
        "score": round(total_score, 2),
        "band": band,
        "color": color,
        "breakdown": {
            "cvss":     round(cvss_component, 2),
            "epss":     round(epss_component, 2),
            "kev":      round(kev_component, 2),
            "exploit":  round(exploit_component, 2),
            "asset":    round(asset_component, 2),
            "exposure": round(exposure_component, 2),
            "threat":   round(threat_component, 2),
            "patch":    round(patch_component, 2),
            "temporal": round(temporal_component, 2),
        },
    }