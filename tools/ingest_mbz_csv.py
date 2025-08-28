import csv, io, json, sys, time, sqlite3, pathlib, datetime

DB = pathlib.Path("backend/data/warnetix.db")
SRC = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("backend/intel/download.csv")

def to_ts(dtstr):
    try:
        return int(datetime.datetime.strptime(dtstr, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp())
    except:
        return int(time.time())

con = sqlite3.connect(DB); con.execute("PRAGMA journal_mode=WAL"); cur = con.cursor()
rows = 0

# strip komentar "#"
buf = io.StringIO()
with SRC.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.strip().startswith("#") or line.strip()=="":
            continue
        buf.write(line)
buf.seek(0)

r = csv.reader(buf, delimiter=",", quotechar='"', skipinitialspace=True)
for row in r:
    if len(row) < 2: continue
    # kolom: first_seen_utc, sha256, md5, sha1, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh
    first_seen = to_ts(row[0])
    sha256 = row[1].lower() if row[1] and row[1]!="n/a" else None
    md5    = row[2].lower() if len(row)>2 and row[2]!="n/a" else None
    reporter = row[4]
    file_name = row[5]
    ftype = (row[6] or "").lower()
    mime = (row[7] or "").lower()
    family = row[8] if row[8]!="n/a" else None
    vtpercent = row[10] if len(row)>10 and row[10]!="n/a" else None

    # heuristik severity sederhana
    sev = "high"
    if family and any(k in family.lower() for k in ("ransom","locker","lockbit","black","conti","maze","stop")):
        sev = "critical"
    elif ftype in {"exe","dll","scr","js","vbs","jar","ps1","apk","msi"}:
        sev = "high"
    if vtpercent:
        try:
            vp = int(str(vtpercent).replace("%",""))
            if vp >= 30: sev = "critical"
        except: pass

    meta = {
        "reporter": reporter, "file_name": file_name,
        "file_type": ftype, "mime": mime, "vtpercent": vtpercent
    }

    cur.execute("""
    INSERT INTO signatures (sha256, md5, threat_family, threat_type, severity, source, first_seen, last_seen, meta_json)
    VALUES (?, ?, ?, ?, ?, 'malwarebazaar', ?, ?, ?)
    ON CONFLICT(sha256) DO UPDATE SET
      threat_family=COALESCE(excluded.threat_family, signatures.threat_family),
      threat_type=COALESCE(excluded.threat_type, signatures.threat_type),
      severity=CASE WHEN excluded.severity IN ('critical','high') THEN excluded.severity ELSE signatures.severity END,
      first_seen=COALESCE(signatures.first_seen, excluded.first_seen),
      last_seen=MAX(COALESCE(signatures.last_seen,0), COALESCE(excluded.last_seen,0)),
      meta_json=excluded.meta_json
    """, (sha256, md5, family or "unknown", "malware", sev, first_seen, first_seen, json.dumps(meta)))
    rows += 1

con.commit()
print(f"[OK] MBZ ingested {rows} rows -> signatures")
