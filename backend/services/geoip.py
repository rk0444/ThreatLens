"""Approximate IP location from a local MaxMind GeoLite2-City database (GEOIP_DB_PATH).

Lookups stay on this machine. GeoIP places an IP's network roughly (city level at best),
so callers must show the accuracy radius, never a precise point.
"""
import ipaddress
import os
from functools import lru_cache

import maxminddb
from dotenv import load_dotenv

load_dotenv()


@lru_cache(maxsize=1)
def _reader(path: str):
    return maxminddb.open_database(path)


def configured() -> bool:
    path = os.getenv("GEOIP_DB_PATH")
    return bool(path) and os.path.isfile(path)


def locate(ip: str):
    """{lat, lng, accuracy_km, city, country} or None (not configured, private IP, or not in the database)."""
    if not configured():
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None
    record = _reader(os.getenv("GEOIP_DB_PATH")).get(ip) or {}
    loc = record.get("location") or {}
    if loc.get("latitude") is None or loc.get("longitude") is None:
        return None
    return {
        "lat": loc["latitude"],
        "lng": loc["longitude"],
        "accuracy_km": loc.get("accuracy_radius"),  # published by MaxMind with each record
        "city": (record.get("city") or {}).get("names", {}).get("en"),
        "country": (record.get("country") or {}).get("names", {}).get("en"),
    }
