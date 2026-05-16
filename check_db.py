import sqlite3
c = sqlite3.connect('E:/Project/ThreatLens/backend/database/threatlens.sqlite')
print('mitre_groups:', c.execute('SELECT mitre_id, name, country FROM mitre_groups LIMIT 3').fetchall())
print('osint_alerts:', c.execute('SELECT id, source, severity FROM osint_alerts LIMIT 3').fetchall())
print('incidents:', c.execute('SELECT id, severity FROM incidents LIMIT 3').fetchall())
print('threat_actors:', c.execute('SELECT id, name FROM threat_actors LIMIT 3').fetchall())
