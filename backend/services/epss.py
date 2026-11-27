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
    Fetch EPSS scores for any number of CVE IDs, 100 per request
    (the API answers 414 URI Too Long for a few hundred IDs).
    Returns: {cve_id: {"epss": float, "percentile": float}, ...}
    """
    result = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i + 100]
        try:
            params = {"cve": ",".join(chunk), "limit": len(chunk)}
            response = requests.get(EPSS_API_URL, params=params, timeout=30)
            if response.status_code != 200:
                print(f"[epss] Bulk fetch returned {response.status_code}")
                continue
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