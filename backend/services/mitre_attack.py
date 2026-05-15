import os
import json
import requests
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from backend.database import models

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "backend/database/mitre_attack.json"

def sync_mitre_data(db: Session):
    print("[MITRE] Checking MITRE ATT&CK CTI data...")
    needs_download = True
    if os.path.exists(CACHE_FILE):
        mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE), tz=timezone.utc)
        if (datetime.now(timezone.utc) - mtime) < timedelta(days=7):
            needs_download = False
            print("[MITRE] Cache is fresh, skipping download.")

    if needs_download:
        print("[MITRE] Downloading MITRE ATT&CK STIX bundle (~50MB)...")
        try:
            response = requests.get(MITRE_URL, timeout=60)
            response.raise_for_status()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                f.write(response.text)
            print("[MITRE] Download complete.")
        except Exception as e:
            print(f"[MITRE][ERROR] Download failed: {e}")
            return

    print("[MITRE] Parsing STIX bundle...")
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            stix_data = json.load(f)
    except Exception as e:
        print(f"[MITRE][ERROR] Failed to read cache: {e}")
        return

    objects = stix_data.get("objects", [])

    # --- Build lookup dicts ---
    intrusion_sets = {}   # stix_id -> {name, mitre_id}
    vulnerabilities = {}  # stix_id -> cve_id string

    for obj in objects:
        t = obj.get("type")

        if t == "intrusion-set":
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break
            if mitre_id:
                intrusion_sets[obj["id"]] = {
                    "name": obj.get("name"),
                    "mitre_id": mitre_id,
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", ""),
                }

        elif t == "vulnerability":
            cve_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "cve":
                    cve_id = ref.get("external_id")
                    break
            if cve_id:
                vulnerabilities[obj["id"]] = cve_id

    print(f"[MITRE] Found {len(intrusion_sets)} groups, {len(vulnerabilities)} vulnerabilities.")

    # --- Sync MitreGroup rows ---
    for stix_id, grp in intrusion_sets.items():
        desc = grp["description"]
        country, motivation = "Unknown", "Unknown"
        if any(x in desc for x in ["Russia", "Russian"]): country = "Russia"
        elif any(x in desc for x in ["China", "Chinese"]): country = "China"
        elif any(x in desc for x in ["Iran", "Iranian"]): country = "Iran"
        elif any(x in desc for x in ["North Korea", "DPRK"]): country = "North Korea"

        dl = desc.lower()
        if "financial" in dl or "ransomware" in dl: motivation = "Financial"
        elif "espionage" in dl or "intelligence" in dl: motivation = "Espionage"
        elif "sabotage" in dl or "disruption" in dl: motivation = "Sabotage"

        db_group = db.query(models.MitreGroup).filter(
            models.MitreGroup.mitre_id == grp["mitre_id"]
        ).first()
        if not db_group:
            db.add(models.MitreGroup(
                mitre_id=grp["mitre_id"],
                name=grp["name"],
                aliases=grp["aliases"],
                description=desc,
                country=country,
                motivation=motivation,
            ))
        else:
            db_group.aliases = grp["aliases"]
            db_group.description = desc
            db_group.country = country
            db_group.motivation = motivation

    db.commit()
    print("[MITRE] MitreGroup table synced.")

    # --- Build CVE -> Group mappings from relationship objects ---
    print("[MITRE] Processing relationship objects...")
    mappings_added = 0

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue

        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")

        # We want: intrusion-set --uses--> vulnerability
        if not source_ref.startswith("intrusion-set--"):
            continue
        if not target_ref.startswith("vulnerability--"):
            continue

        group = intrusion_sets.get(source_ref)
        cve_id = vulnerabilities.get(target_ref)

        if not group or not cve_id:
            continue

        # Only map CVEs that exist in our DB
        local_cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
        if not local_cve:
            continue

        existing = db.query(models.CveToGroup).filter(
            models.CveToGroup.cve_id == cve_id,
            models.CveToGroup.group_mitre_id == group["mitre_id"]
        ).first()

        if not existing:
            db.add(models.CveToGroup(
                cve_id=cve_id,
                group_name=group["name"],
                group_mitre_id=group["mitre_id"],
                confidence="confirmed",
                source="MITRE CTI"
            ))
            mappings_added += 1

    db.commit()
    print(f"[MITRE] CVE→Group mappings added: {mappings_added}")
    print("[MITRE] Sync complete.")