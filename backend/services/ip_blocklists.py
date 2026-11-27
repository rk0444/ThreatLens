"""Published IP blocklists, matched locally so every live connection can be checked instantly.

- abuse.ch Feodo Tracker: botnet command-and-control IPs (CC0)
- Spamhaus DROP: netblocks hijacked or run by criminals (free for non-commercial use)
"""
import ipaddress
import json
import threading
from datetime import datetime, timezone

import requests
from sqlalchemy.orm import Session

from backend.database import models

FEODO = "abuse.ch Feodo Tracker"
SPAMHAUS = "Spamhaus DROP"
FEEDS = {
    FEODO: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    SPAMHAUS: "https://www.spamhaus.org/drop/drop_v4.json",
}
HEADERS = {"User-Agent": "ThreatLens blocklist sync"}

_lock = threading.Lock()
_networks = None  # [(ip_network, source, reference)], loaded lazily from the database


def _parse_feodo(text: str) -> list:
    entries = []
    for row in json.loads(text):
        ip = row.get("ip_address")
        if not ip:
            continue
        reference = f"{row.get('malware') or 'botnet'} C2"
        if row.get("last_online"):
            reference += f", last online {row['last_online']}"
        entries.append((str(ipaddress.ip_network(ip)), reference))
    return entries


def _parse_spamhaus(text: str) -> list:
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("cidr"):  # the last line is metadata
            entries.append((str(ipaddress.ip_network(row["cidr"])), row.get("sblid")))
    return entries


PARSERS = {FEODO: _parse_feodo, SPAMHAUS: _parse_spamhaus}


def sync_ip_blocklists(db: Session) -> dict:
    """Replace each source's rows with its latest list. A failed or empty download keeps the old rows."""
    counts = {}
    for source, url in FEEDS.items():
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
            response.raise_for_status()
            entries = PARSERS[source](response.text)
        except Exception as e:
            print(f"[blocklists] {source} not updated: {e}")
            continue
        if not entries:
            print(f"[blocklists] {source} returned no entries; keeping the previous list")
            continue
        now = datetime.now(timezone.utc)
        db.query(models.IPBlocklistEntry).filter(models.IPBlocklistEntry.source == source).delete()
        db.add_all(models.IPBlocklistEntry(network=net, source=source, reference=ref, updated_at=now)
                   for net, ref in entries)
        db.commit()
        counts[source] = len(entries)
    _load(db)
    print(f"[blocklists] synced: {counts}")
    return counts


def _load(db: Session):
    global _networks
    rows = db.query(models.IPBlocklistEntry).all()
    with _lock:
        _networks = [(ipaddress.ip_network(r.network), r.source, r.reference) for r in rows]


def match(ip: str, db: Session):
    """{source, network, reference} if a published list contains this IP, else None."""
    if _networks is None:
        _load(db)
    addr = ipaddress.ip_address(ip)
    with _lock:
        for network, source, reference in _networks:
            if addr.version == network.version and addr in network:
                return {"source": source, "network": str(network), "reference": reference}
    return None
