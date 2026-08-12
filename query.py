import sqlite3
import datetime

conn = sqlite3.connect('backend/database/threatlens.sqlite')
c = conn.cursor()
c.execute("SELECT name, last_seen FROM assets")
rows = c.fetchall()
for row in rows:
    print(row)
conn.close()
