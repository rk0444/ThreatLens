import os
import json
import requests
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from ..database import models

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "backend/database/mitre_attack.json"

def sync_mitre_data(db: Session):
    print("[INIT] Checking MITRE ATT&CK CTI Data...")
    needs_download = True
    if os.path.exists(CACHE_FILE):
        mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE), tz=timezone.utc)
        if (datetime.now(timezone.utc) - mtime) < timedelta(days=7):
            needs_download = False
            print("[INIT] MITRE ATT&CK data is fresh.")
            
    if needs_download:
        print("[INIT] Downloading MITRE ATT&CK STIX bundle...")
        try:
            response = requests.get(MITRE_URL, timeout=30)
            response.raise_for_status()
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                f.write(response.text)
        except Exception as e:
            print(f"[ERROR] Failed to download MITRE CTI: {e}")
            return
            
    print("[INIT] Parsing MITRE STIX data...")
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            stix_data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read cache file: {e}")
        return

    objects = stix_data.get("objects", [])
    
    intrusion_sets = {}
    attack_patterns = {}

    for obj in objects:
        t = obj.get("type")
        if t == "intrusion-set":
            intrusion_sets[obj["id"]] = obj
        elif t == "attack-pattern":
            attack_patterns[obj["id"]] = obj

    print(f"[INIT] Found {len(intrusion_sets)} Groups, {len(attack_patterns)} Techniques.")

    for stix_id, grp in intrusion_sets.items():
        name = grp.get("name")
        aliases = grp.get("aliases", [])
        desc = grp.get("description", "")
        country = "Unknown"
        motivation = "Unknown"
        if "Russia" in desc or "Russian" in desc: country = "Russia"
        elif "China" in desc or "Chinese" in desc: country = "China"
        elif "Iran" in desc or "Iranian" in desc: country = "Iran"
        elif "North Korea" in desc or "DPRK" in desc: country = "North Korea"
        
        if "financial" in desc.lower() or "ransomware" in desc.lower(): motivation = "Financial"
        elif "espionage" in desc.lower() or "intelligence" in desc.lower(): motivation = "Espionage"
        elif "sabotage" in desc.lower() or "disruption" in desc.lower(): motivation = "Sabotage"
        
        mitre_id = None
        for ref in grp.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
                
        if not mitre_id: continue
        
        db_group = db.query(models.MitreGroup).filter(models.MitreGroup.mitre_id == mitre_id).first()
        if not db_group:
            db_group = models.MitreGroup(
                mitre_id=mitre_id,
                name=name,
                aliases=aliases,
                description=desc,
                country=country,
                motivation=motivation
            )
            db.add(db_group)
        else:
            db_group.aliases = aliases
            db_group.description = desc
            db_group.country = country
            db_group.motivation = motivation

    for stix_id, tech in attack_patterns.items():
        name = tech.get("name")
        desc = tech.get("description", "")
        platforms = tech.get("x_mitre_platforms", [])
        
        mitre_id = None
        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
                
        if not mitre_id: continue
        
        db_tech = db.query(models.MitreTechnique).filter(models.MitreTechnique.technique_id == mitre_id).first()
        if not db_tech:
            db_tech = models.MitreTechnique(
                technique_id=mitre_id,
                name=name,
                description=desc,
                platforms=platforms
            )
            db.add(db_tech)
    
    db.commit()
    
    print("[INIT] Cross-referencing MITRE data with local CVEs...")
    cves = db.query(models.CVE).all()
    groups = db.query(models.MitreGroup).all()
    
    # We will do keyword matching for CVEs in group descriptions as requested
    for cve in cves:
        cve_id = cve.cve_id
        for group in groups:
            if group.description and cve_id in group.description:
                mapping = db.query(models.CveToGroup).filter(
                    models.CveToGroup.cve_id == cve_id,
                    models.CveToGroup.group_mitre_id == group.mitre_id
                ).first()
                if not mapping:
                    mapping = models.CveToGroup(
                        cve_id=cve_id,
                        group_name=group.name,
                        group_mitre_id=group.mitre_id,
                        confidence="confirmed",
                        source="MITRE CTI"
                    )
                    db.add(mapping)
    db.commit()
    print("[INIT] MITRE CTI sync complete.")
