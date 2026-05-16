"""
score_cve_groups.py
Run from E:\\Project\\ThreatLens:
  python score_cve_groups.py

Scores KEV/high-EPSS CVEs against MITRE groups using Groq,
then writes matches into cve_to_groups.
"""

import sqlite3
import json
import os
import time
from groq import Groq
from dotenv import load_dotenv

load_dotenv(r"E:\Project\ThreatLens\.env")

DB_PATH = r"E:\Project\ThreatLens\backend\database\threatlens.sqlite"
GROQ_MODEL = "llama3-70b-8192"
TOP_N_GROUPS = 5      # max actor matches per CVE
CONFIDENCE_MIN = 0.3  # discard weak matches below this

client = Groq(api_key=os.environ["GROQ_API_KEY"])


def get_candidate_cves(conn):
    rows = conn.execute("""
        SELECT c.cve_id, c.description, c.cvss_score, c.epss_score
        FROM cves c
        WHERE c.epss_score > 0.5
           OR c.cve_id IN (SELECT cve_id FROM cisa_kev)
        ORDER BY (c.epss_score OR 0) DESC
    """).fetchall()
    return rows


def get_mitre_groups(conn):
    rows = conn.execute("""
        SELECT mitre_id, name, description, country, motivation, techniques
        FROM mitre_groups
    """).fetchall()
    return rows


def build_group_summary(groups):
    """Build a compact JSON list of groups for the prompt."""
    summaries = []
    for mitre_id, name, desc, country, motivation, techniques in groups:
        # Truncate description to keep prompt size manageable
        short_desc = (desc or "")[:300].replace("\n", " ")
        tech_list = []
        if techniques:
            try:
                tech_list = json.loads(techniques)[:10]  # top 10 techniques
            except Exception:
                pass
        summaries.append({
            "mitre_id": mitre_id,
            "name": name,
            "country": country or "Unknown",
            "motivation": motivation or "Unknown",
            "description": short_desc,
            "techniques": tech_list,
        })
    return summaries


def score_cve_against_groups(cve_id, description, cvss, epss, group_summaries):
    """Ask Groq which groups are likely to exploit this CVE."""

    groups_json = json.dumps(group_summaries, indent=None)

    prompt = f"""You are a cyber threat intelligence analyst.

CVE ID: {cve_id}
CVSS Score: {cvss or 'N/A'}
EPSS Score: {epss or 'N/A'}
Description: {description or 'No description available.'}

Below is a JSON array of {len(group_summaries)} known threat actor groups with their MITRE IDs, names, countries, motivations, and techniques.

{groups_json}

Task: Based on the CVE description, identify which threat actor groups are MOST LIKELY to exploit this vulnerability. Consider:
- The type of vulnerability (RCE, SQLi, auth bypass, etc.)
- The affected product/vendor and which sectors use it
- The group's known motivation (financial/espionage/disruption)
- The group's known techniques and past targeting

Return ONLY a JSON array (no markdown, no explanation) of up to {TOP_N_GROUPS} matches, ordered by confidence descending:
[
  {{
    "mitre_id": "G0001",
    "group_name": "Group Name",
    "confidence": 0.85,
    "reason": "One sentence reason"
  }},
  ...
]

Only include groups with confidence >= {CONFIDENCE_MIN}. If no groups are a good match, return an empty array [].
"""

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=1024,
    )

    raw = response.choices[0].message.content.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    return json.loads(raw)


def insert_matches(conn, cve_id, matches):
    inserted = 0
    for match in matches:
        mitre_id = match.get("mitre_id", "")
        group_name = match.get("group_name", "")
        confidence = float(match.get("confidence", 0))
        reason = match.get("reason", "AI scoring")

        if confidence < CONFIDENCE_MIN:
            continue

        # Check for duplicate
        exists = conn.execute(
            "SELECT 1 FROM cve_to_groups WHERE cve_id=? AND group_mitre_id=?",
            (cve_id, mitre_id)
        ).fetchone()

        if exists:
            print(f"    [skip] {cve_id} → {group_name} already exists")
            continue

        conn.execute("""
            INSERT INTO cve_to_groups
                (cve_id, group_name, group_mitre_id, technique_id, technique_name, confidence, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            group_name,
            mitre_id,
            None,
            None,
            str(round(confidence, 2)),
            f"ai_scoring: {reason[:200]}",
        ))
        inserted += 1

    conn.commit()
    return inserted


def main():
    conn = sqlite3.connect(DB_PATH)

    print("=== ThreatLens CVE→Group AI Scorer ===\n")

    cves = get_candidate_cves(conn)
    print(f"Found {len(cves)} candidate CVEs (KEV + EPSS>0.5)\n")

    groups = get_mitre_groups(conn)
    print(f"Loaded {len(groups)} MITRE groups\n")

    group_summaries = build_group_summary(groups)

    total_inserted = 0

    for i, (cve_id, description, cvss, epss) in enumerate(cves):
        print(f"[{i+1}/{len(cves)}] Scoring {cve_id} (CVSS={cvss}, EPSS={epss})")
        print(f"    {(description or '')[:100].strip()}...")

        try:
            matches = score_cve_against_groups(
                cve_id, description, cvss, epss, group_summaries
            )
            print(f"    Got {len(matches)} matches from Groq")

            inserted = insert_matches(conn, cve_id, matches)
            total_inserted += inserted
            print(f"    Inserted {inserted} new rows into cve_to_groups")

            for m in matches:
                print(f"      → {m.get('group_name')} ({m.get('mitre_id')}) conf={m.get('confidence')}")

        except json.JSONDecodeError as e:
            print(f"    [ERROR] Groq returned invalid JSON: {e}")
        except Exception as e:
            print(f"    [ERROR] {e}")

        # Rate limit safety — Groq free tier: ~30 req/min
        if i < len(cves) - 1:
            time.sleep(2)

    print(f"\n=== Done. Total rows inserted: {total_inserted} ===")

    # Quick verification
    count = conn.execute("SELECT COUNT(*) FROM cve_to_groups").fetchone()[0]
    print(f"cve_to_groups now has {count} total rows")

    sample = conn.execute("""
        SELECT cve_id, group_name, group_mitre_id, confidence
        FROM cve_to_groups
        LIMIT 10
    """).fetchall()
    print("\nSample rows:")
    for row in sample:
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    main()
