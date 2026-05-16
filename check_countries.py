import sys
sys.path.insert(0, 'E:/Project/ThreatLens')

from backend.main import COUNTRY_COORDS
import sqlite3

c = sqlite3.connect('E:/Project/ThreatLens/backend/database/threatlens.sqlite')
db_countries = c.execute("SELECT DISTINCT country FROM mitre_groups WHERE country IS NOT NULL").fetchall()
db_countries = [r[0] for r in db_countries]

print('DB countries:', db_countries)
print()
print('COUNTRY_COORDS keys:', list(COUNTRY_COORDS.keys()))
print()
matches = [x for x in db_countries if x in COUNTRY_COORDS]
misses  = [x for x in db_countries if x not in COUNTRY_COORDS]
print('MATCHES:', matches)
print('MISSING from COUNTRY_COORDS:', misses)
