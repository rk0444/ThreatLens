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
        country, motivation = "Unknown", "Unknown"
        if any(x in desc for x in ["Russia", "Russian"]): country = "Russia"
        elif any(x in desc for x in ["China", "Chinese"]): country = "China"
        elif any(x in desc for x in ["Iran", "Iranian"]): country = "Iran"
        elif any(x in desc for x in ["North Korea", "DPRK"]): country = "North Korea"

        dl = desc.lower()
        if "financial" in dl or "ransomware" in dl: motivation = "Financial"
        elif "espionage" in dl or "intelligence" in dl: motivation = "Espionage"
        elif "sabotage" in dl or "disruption" in dl: motivation = "Sabotage"

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

    # --- Map CVEs to Groups via description keyword matching ---
    print("[MITRE] Mapping CVEs to threat groups via keyword matching...")

    # Pre-build: technique_name_lower -> list of group mitre_ids that use it
    technique_name_to_groups = {}
    for stix_id, ap in attack_patterns.items():
        groups_using = technique_to_groups.get(stix_id, [])
        if groups_using:
            technique_name_to_groups[ap["name_lower"]] = groups_using

    # Also build tactic -> groups map (broader match)
    tactic_to_groups = {}
    for stix_id, ap in attack_patterns.items():
        tactic = ap["tactic"]
        if not tactic:
            continue
        groups_using = technique_to_groups.get(stix_id, [])
        if tactic not in tactic_to_groups:
            tactic_to_groups[tactic] = set()
        tactic_to_groups[tactic].update(groups_using)

    # Keyword patterns: CVE description phrases -> technique names to match
    KEYWORD_TECHNIQUE_MAP = {
        "remote code execution": ["exploit public-facing application", "command and scripting interpreter"],
        "buffer overflow": ["exploit public-facing application"],
        "sql injection": ["exploit public-facing application"],
        "authentication bypass": ["valid accounts", "exploit public-facing application"],
        "privilege escalation": ["exploitation for privilege escalation"],
        "denial of service": ["network denial of service", "endpoint denial of service"],
        "cross-site scripting": ["exploit public-facing application"],
        "path traversal": ["exploit public-facing application"],
        "directory traversal": ["exploit public-facing application"],
        "command injection": ["command and scripting interpreter", "exploit public-facing application"],
        "memory corruption": ["exploit public-facing application"],
        "use after free": ["exploit public-facing application"],
        "null pointer": ["exploit public-facing application"],
        "out-of-bounds": ["exploit public-facing application"],
        "heap overflow": ["exploit public-facing application"],
        "stack overflow": ["exploit public-facing application"],
        "arbitrary code": ["exploit public-facing application", "command and scripting interpreter"],
        "information disclosure": ["data from local system", "unsecured credentials"],
        "credential": ["brute force", "valid accounts", "unsecured credentials"],
        "password": ["brute force", "valid accounts", "unsecured credentials"],
        "ransomware": ["data encrypted for impact", "inhibit system recovery"],
        "phishing": ["phishing"],
        "backdoor": ["ingress tool transfer", "command and scripting interpreter"],
        "malware": ["ingress tool transfer"],
        "lateral movement": ["lateral tool transfer"],
        "persistence": ["scheduled task/job", "boot or logon autostart execution"],
        "exfiltration": ["exfiltration over c2 channel", "exfiltration over web service"],
        "encryption": ["data encrypted for impact"],
        "vpn": ["exploit public-facing application", "valid accounts"],
        "smb": ["exploitation of remote services", "lateral tool transfer"],
        "rdp": ["remote desktop protocol", "exploitation of remote services"],
        "ssh": ["remote services", "exploitation of remote services"],
        "zero-day": ["exploit public-facing application"],
        "supply chain": ["supply chain compromise"],
        "man-in-the-middle": ["adversary-in-the-middle"],
        "injection": ["exploit public-facing application", "command and scripting interpreter"],
        "deserialization": ["exploit public-facing application"],
        "xml": ["exploit public-facing application"],
        "ldap": ["exploitation of remote services"],
        "kerberos": ["steal or forge kerberos tickets"],
        "active directory": ["exploitation for privilege escalation", "steal or forge kerberos tickets"],
    }

    # Clear existing mappings to rebuild clean
    db.query(models.CveToGroup).delete()
    db.commit()

    cves = db.query(models.CVE).all()
    mappings_added = 0
    cves_mapped = 0

    for cve in cves:
        desc = (cve.description or "").lower()
        if not desc:
            continue

        matched_group_ids = set()

        # Match via keyword -> technique -> groups
        for keyword, technique_names in KEYWORD_TECHNIQUE_MAP.items():
            if keyword not in desc:
                continue
            for tech_name in technique_names:
                groups_using = technique_name_to_groups.get(tech_name, [])
                matched_group_ids.update(groups_using)

        if not matched_group_ids:
            continue

        cves_mapped += 1

        # Score confidence by number of keyword matches
        match_count = sum(
            1 for kw in KEYWORD_TECHNIQUE_MAP if kw in desc
        )
        confidence = "high" if match_count >= 3 else "medium" if match_count >= 2 else "low"

        for gid in matched_group_ids:
            group_info = next(
                (g for g in intrusion_sets.values() if g["mitre_id"] == gid),
                None
            )
            if not group_info:
                continue

            db.add(models.CveToGroup(
                cve_id=cve.cve_id,
                group_name=group_info["name"],
                group_mitre_id=gid,
                confidence=confidence,
                source="MITRE CTI",
            ))
            mappings_added += 1

        # Commit in batches to avoid memory buildup
        if mappings_added % 500 == 0 and mappings_added > 0:
            db.commit()
            print(f"[MITRE] ...{mappings_added} mappings written so far")

    db.commit()
    print(f"[MITRE] CVE->Group mappings added: {mappings_added} across {cves_mapped} CVEs")
    print("[MITRE] Sync complete.")