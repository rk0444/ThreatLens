import os
import re
import json
import requests
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from backend.database import models
from backend.database.db import DATA_DIR

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = os.path.join(DATA_DIR, "mitre_attack.json")  # user-data folder in the installed app


def clean_description(text):
    """MITRE descriptions are markdown with inline citations: keep link text, drop the citation markers."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text or "")
    return re.sub(r"\s*\(Citation:[^)]*\)", "", text).strip()


def _mitre_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


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
            # Write a temp file, then swap it in: an interrupted write never leaves a half file
            # with a fresh date (which would skip downloads for 7 days).
            with open(CACHE_FILE + ".tmp", 'w', encoding='utf-8') as f:
                f.write(response.text)
            os.replace(CACHE_FILE + ".tmp", CACHE_FILE)
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
        os.remove(CACHE_FILE)  # unreadable: download a fresh copy on the next run
        return

    objects = stix_data.get("objects", [])

    # --- Build lookup dicts ---
    intrusion_sets = {}   # stix_id -> {name, mitre_id, description, aliases}
    attack_patterns = {}  # stix_id -> {tid, name, tactic}
    # Tactic display names as MITRE publishes them, e.g. "credential-access" -> "Credential Access"
    tactic_names = {o["x_mitre_shortname"]: o["name"] for o in objects
                    if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname") and o.get("name")}

    for obj in objects:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue  # MITRE retired it (e.g. APT34 was merged into OilRig)

        if t == "intrusion-set":
            mitre_id = _mitre_id(obj)
            if mitre_id:
                intrusion_sets[obj["id"]] = {
                    "name": obj.get("name"),
                    "mitre_id": mitre_id,
                    "aliases": obj.get("aliases", []),
                    "description": clean_description(obj.get("description")),
                }

        elif t == "attack-pattern":
            tid = _mitre_id(obj)
            if tid:
                phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
                attack_patterns[obj["id"]] = {
                    "tid": tid,
                    "name": obj.get("name", ""),
                    "tactic": ", ".join(tactic_names.get(p, p) for p in phases if p),  # can serve several tactics
                }

    # Sub-techniques get their parent's name, as on attack.mitre.org ("OS Credential Dumping: LSASS Memory")
    names_by_tid = {ap["tid"]: ap["name"] for ap in attack_patterns.values()}
    for ap in attack_patterns.values():
        parent = names_by_tid.get(ap["tid"].split(".")[0]) if "." in ap["tid"] else None
        if parent:
            ap["name"] = f"{parent}: {ap['name']}"

    print(f"[MITRE] Found {len(intrusion_sets)} groups, {len(attack_patterns)} techniques.")
    if not intrusion_sets or not attack_patterns:
        print("[MITRE][ERROR] Bundle has no groups or techniques; keeping existing data.")
        return

    # --- Build group -> technique_ids map from STIX relationships ---
    group_to_techniques = {}  # mitre_id -> set of technique stix_ids
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        group = intrusion_sets.get(obj.get("source_ref", ""))
        if not group or obj.get("target_ref") not in attack_patterns:
            continue
        group_to_techniques.setdefault(group["mitre_id"], set()).add(obj["target_ref"])

    print(f"[MITRE] Built technique maps for {len(group_to_techniques)} groups.")

    # --- Sync MitreGroup rows ---
    # MITRE publishes no country or motivation field for groups; guessing them from the
    # description mislabels groups by the countries they target, so they stay empty.
    existing = {g.mitre_id: g for g in db.query(models.MitreGroup).all()}
    for grp in intrusion_sets.values():
        gid = grp["mitre_id"]
        fields = dict(
            name=grp["name"],
            aliases=grp["aliases"],
            description=grp["description"],
            country=None,
            motivation=None,
            techniques=sorted(attack_patterns[sid]["name"] for sid in group_to_techniques.get(gid, ())),
        )
        if gid in existing:
            for key, value in fields.items():
                setattr(existing[gid], key, value)
        else:
            db.add(models.MitreGroup(mitre_id=gid, **fields))

    current_groups = [g["mitre_id"] for g in intrusion_sets.values()]
    db.query(models.MitreGroup).filter(models.MitreGroup.mitre_id.notin_(current_groups)).delete(synchronize_session=False)
    db.commit()
    print("[MITRE] MitreGroup table synced.")

    # --- Sync MitreTechnique rows with associated_groups ---
    technique_to_groups = {}  # technique stix_id -> group mitre_ids
    for gid, tech_set in group_to_techniques.items():
        for sid in tech_set:
            technique_to_groups.setdefault(sid, []).append(gid)

    existing = {t.technique_id: t for t in db.query(models.MitreTechnique).all()}
    for stix_id, ap in attack_patterns.items():
        fields = dict(name=ap["name"], tactic=ap["tactic"], associated_groups=sorted(technique_to_groups.get(stix_id, [])))
        if ap["tid"] in existing:
            for key, value in fields.items():
                setattr(existing[ap["tid"]], key, value)
        else:
            db.add(models.MitreTechnique(technique_id=ap["tid"], **fields))

    current_techniques = [ap["tid"] for ap in attack_patterns.values()]
    db.query(models.MitreTechnique).filter(models.MitreTechnique.technique_id.notin_(current_techniques)).delete(synchronize_session=False)
    db.commit()
    print("[MITRE] MitreTechnique table synced.")

    print("[MITRE] Sync complete.")
