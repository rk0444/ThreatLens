import sys
sys.path.insert(0, 'E:/Project/ThreatLens')

from backend.database.db import SessionLocal
from sqlalchemy import text
from collections import defaultdict
import json as _json

db = SessionLocal()

try:
    mg_rows = db.execute(text("SELECT mitre_id, name, country, motivation, techniques FROM mitre_groups")).fetchall()
    print(f"mitre_groups rows: {len(mg_rows)}")

    cve_counts = db.execute(text("SELECT group_name, COUNT(DISTINCT cve_id) as cnt, GROUP_CONCAT(DISTINCT cve_id) as ids FROM cve_to_groups GROUP BY group_name")).fetchall()
    print(f"cve_counts rows: {len(cve_counts)}")

    osint_rows = db.execute(text("SELECT source, indicator, description, severity, created_at FROM osint_alerts ORDER BY created_at DESC LIMIT 200")).fetchall()
    print(f"osint_rows: {len(osint_rows)}")

    # Test the constants exist
    from backend.main import COUNTRY_COORDS, OSINT_COUNTRY_HINTS, SECTOR_KEYWORDS
    print(f"COUNTRY_COORDS keys: {len(COUNTRY_COORDS)}")
    print(f"OSINT_COUNTRY_HINTS keys: {len(OSINT_COUNTRY_HINTS)}")
    print(f"SECTOR_KEYWORDS keys: {len(SECTOR_KEYWORDS)}")

except Exception as e:
    import traceback
    print("ERROR:", e)
    traceback.print_exc()
finally:
    db.close()
