import sqlite3
c = sqlite3.connect('E:/Project/ThreatLens/backend/database/threatlens.sqlite')
tables = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', [t[0] for t in tables])
print('cves count:', c.execute('SELECT COUNT(*) FROM cves').fetchone())
print('cisa_kev count:', c.execute('SELECT COUNT(*) FROM cisa_kev').fetchone())
