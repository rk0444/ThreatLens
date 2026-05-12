import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_score(cve_id: str):
    """
    Fetches the EPSS score and percentile for a given CVE ID.
    Returns: {"epss": float, "percentile": float} or None
    """
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
