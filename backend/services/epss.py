import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_score(cve_id: str):
    try:
        response = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            results = data.get("data", [])
            if results:
                epss_info = results[0]
                return {
                    "epss": float(epss_info.get("epss", 0)),
                    "percentile": float(epss_info.get("percentile", 0))
                }
    except Exception as e:
        print(f"Error fetching EPSS score for {cve_id}: {e}")
    return None


def fetch_epss_bulk(cve_ids: list) -> dict:
    """
    Fetch EPSS scores for up to 2000 CVE IDs in a single request.
    Returns: {cve_id: {"epss": float, "percentile": float}, ...}
    """
    result = {}
    if not cve_ids:
        return result
    try:
        params = {"cve": ",".join(cve_ids), "limit": 2000}
        response = requests.get(EPSS_API_URL, params=params, timeout=30)
        if response.status_code == 200:
            for item in response.json().get("data", []):
                cve_id = item.get("cve")
                if cve_id:
                    result[cve_id] = {
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0))
                    }
    except Exception as e:
        print(f"[epss] Bulk fetch error: {e}")
    return result