import sqlite3, json
con = sqlite3.connect(r'backend/data/warnetix.db')
con.row_factory = sqlite3.Row
tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
print('tables =', tables)
cnt = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
print('events_count =', cnt)
rows = [dict(r) for r in con.execute("SELECT id,ts,type,device_id,filename,severity FROM events ORDER BY id DESC LIMIT 3")]
print('last_events =', json.dumps(rows, indent=2))
