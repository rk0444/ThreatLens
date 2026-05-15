"""
ThreatLens — CVE schema checker
Run from your project root:  python check_schema.py
"""

import sqlite3
import os
import sys

DB_PATH = os.path.join("backend", "database", "threatlens.sqlite")

REQUIRED_COLUMNS = {
    # column_name: (type, default_value, nullable)
    "cisa_kev":             ("INTEGER", "0",    False),
    "ransomware_use":       ("INTEGER", "0",    False),
    "patch_available":      ("INTEGER", "0",    False),
    "actively_exploited":   ("INTEGER", "0",    False),
    "asset_affected":       ("INTEGER", "0",    False),
    "affected_asset_count": ("INTEGER", "0",    False),
    "risk_score":           ("REAL",    "0.0",  False),
    "risk_band":            ("TEXT",    "'LOW'", False),
    "ai_summary":           ("TEXT",    "NULL", True),
    "mitre_tags":           ("TEXT",    "NULL", True),
}

if not os.path.exists(DB_PATH):
    print(f"[ERROR] Database not found at: {DB_PATH}")
    print("       Check your DB_PATH at the top of this script.")
    sys.exit(1)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(cves)")
existing = {row[1]: row[2] for row in cursor.fetchall()}  # {name: type}
conn.close()

print(f"\nThreatLens CVE Schema Check")
print(f"Database: {DB_PATH}")
print(f"{'='*50}")
print(f"\nExisting columns ({len(existing)}):")
for col, typ in existing.items():
    print(f"  [OK]  {col} ({typ})")

missing = {k: v for k, v in REQUIRED_COLUMNS.items() if k not in existing}

print(f"\nMissing columns ({len(missing)}):")
if not missing:
    print("  None — schema is up to date!")
else:
    for col, (typ, default, nullable) in missing.items():
        print(f"  [MISSING]  {col} ({typ})")

print(f"\n{'='*50}")
if missing:
    print(f"Run migrate.py to add the {len(missing)} missing column(s).")
else:
    print("No migration needed.")
