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
    intrusion_sets = {}   # stix_id -> {name, mitre_id, description, aliases}
    attack_patterns = {}  # stix_id -> {tid, name, tactic, keywords}

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

        elif t == "attack-pattern":
            tid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            if tid:
                kill_chain = obj.get("kill_chain_phases", [])
                tactic = kill_chain[0].get("phase_name", "") if kill_chain else ""
                name = obj.get("name", "")
                desc = obj.get("description", "")
                # Build keyword list: technique name words + first sentence of desc
                first_sentence = desc.split(".")[0] if desc else ""
                keywords = set()
                for word in name.lower().split():
                    if len(word) > 4:
                        keywords.add(word)
                for word in first_sentence.lower().split():
                    if len(word) > 5:
                        keywords.add(word)
                attack_patterns[obj["id"]] = {
                    "tid": tid,
                    "name": name,
                    "tactic": tactic,
                    "keywords": keywords,
                    "name_lower": name.lower(),
                }

    print(f"[MITRE] Found {len(intrusion_sets)} groups, {len(attack_patterns)} techniques.")

    # --- Build group -> technique_ids map from STIX relationships ---
    group_to_techniques = {}  # mitre_id -> set of technique stix_ids
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if not src.startswith("intrusion-set--"):
            continue
        if not tgt.startswith("attack-pattern--"):
            continue
        group = intrusion_sets.get(src)
        if not group:
            continue
        gid = group["mitre_id"]
        if gid not in group_to_techniques:
            group_to_techniques[gid] = set()
        group_to_techniques[gid].add(tgt)

    print(f"[MITRE] Built technique maps for {len(group_to_techniques)} groups.")

    # --- Sync MitreGroup rows ---
    for stix_id, grp in intrusion_sets.items():
        desc = grp["description"]
        # MITRE publishes no country or motivation field for groups; guessing them from the
        # description mislabels groups by the countries they target, so they stay empty.
        country, motivation = None, None

        # Build technique list for this group
        gid = grp["mitre_id"]
        tech_stix_ids = group_to_techniques.get(gid, set())
        tech_names = [
            attack_patterns[sid]["name"]
            for sid in tech_stix_ids
            if sid in attack_patterns
        ]

        db_group = db.query(models.MitreGroup).filter(
            models.MitreGroup.mitre_id == gid
        ).first()
        if not db_group:
            db.add(models.MitreGroup(
                mitre_id=gid,
                name=grp["name"],
                aliases=grp["aliases"],
                description=desc,
                country=country,
                motivation=motivation,
                techniques=tech_names,
            ))
        else:
            db_group.aliases = grp["aliases"]
            db_group.description = desc
            db_group.country = country
            db_group.motivation = motivation
            db_group.techniques = tech_names

    db.commit()
    print("[MITRE] MitreGroup table synced.")

    # --- Sync MitreTechnique rows with associated_groups ---
    print("[MITRE] Syncing MitreTechnique rows...")
    # Build reverse map: technique stix_id -> list of group mitre_ids
    technique_to_groups = {}
    for gid, tech_set in group_to_techniques.items():
        for sid in tech_set:
            if sid not in technique_to_groups:
                technique_to_groups[sid] = []
            technique_to_groups[sid].append(gid)

    for stix_id, ap in attack_patterns.items():
        assoc_groups = technique_to_groups.get(stix_id, [])
        db_tech = db.query(models.MitreTechnique).filter(
            models.MitreTechnique.technique_id == ap["tid"]
        ).first()
        if not db_tech:
            db.add(models.MitreTechnique(
                technique_id=ap["tid"],
                name=ap["name"],
                tactic=ap["tactic"],
                associated_groups=assoc_groups,
            ))
        else:
            db_tech.tactic = ap["tactic"]
            db_tech.associated_groups = assoc_groups

    db.commit()
    print("[MITRE] MitreTechnique table synced.")

    # No source links CVEs to groups, so none are inferred; clear rows left by older versions.
    db.query(models.CveToGroup).delete()
    db.commit()

    print("[MITRE] Sync complete.")