import os, sqlite3, time, json, pathlib

def upsert_signature(conn, *, sha256=None, md5=None, family=None,
                     threat_type="malware", severity="high", source="manual",
                     first_seen=None, meta=None):
    if not (sha256 or md5):
        return False
    if first_seen is None:
        first_seen = int(time.time())
    meta_json = json.dumps(meta or {}, ensure_ascii=False)
    conn.execute("""
    INSERT INTO signatures (sha256, md5, threat_family, threat_type, severity, source, first_seen, last_seen, meta_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(sha256) DO UPDATE SET
        threat_family=COALESCE(excluded.threat_family, signatures.threat_family),
        threat_type=COALESCE(excluded.threat_type, signatures.threat_type),
        severity=CASE
            WHEN excluded.severity IN ('critical','high') THEN excluded.severity
            ELSE signatures.severity END,
        source=signatures.source,
        first_seen=COALESCE(signatures.first_seen, excluded.first_seen),
        last_seen=MAX(COALESCE(signatures.last_seen,0), COALESCE(excluded.last_seen,0)),
        meta_json=excluded.meta_json
    """, (sha256, md5, family, threat_type, severity, source, first_seen, first_seen, meta_json))
    return True

def signature_lookup(conn, *, sha256=None, md5=None):
    if sha256:
        row = conn.execute("""SELECT sha256, md5, threat_family, threat_type, severity, source, first_seen, last_seen, meta_json
                              FROM signatures WHERE sha256=?""", (sha256.lower(),)).fetchone()
        if row:
            return _sig_row_to_dict(row)
    if md5:
        row = conn.execute("""SELECT sha256, md5, threat_family, threat_type, severity, source, first_seen, last_seen, meta_json
                              FROM signatures WHERE md5=?""", (md5.lower(),)).fetchone()
        if row:
            return _sig_row_to_dict(row)
    return None

def _sig_row_to_dict(row):
    import json
    return {
        "sha256": row[0], "md5": row[1], "family": row[2], "type": row[3], "severity": row[4],
        "source": row[5], "first_seen": row[6], "last_seen": row[7],
        "meta": json.loads(row[8]) if row[8] else {}
    }

DB_PATH = os.getenv("DB_PATH", "backend/data/warnetix.db")
SCHEMA_SQL = os.path.join(os.path.dirname(__file__), "sql", "schema.sql")

def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON;")
    return con

def migrate():
    con = connect()
    with open(SCHEMA_SQL,"r",encoding="utf-8") as f:
        con.executescript(f.read())
    con.commit()
    con.close()

# ---- UPSERT DEVICE ----
def upsert_device(con, dev: dict):
    """
    dev = {"id":"dev-xav","hostname":"XavPC","os":"Windows","arch":"x64","version":"0.1", ...}
    """
    now = int(time.time())
    # gunakan name=hostname
    payload = {
        "id": dev.get("id"),
        "name": dev.get("hostname") or dev.get("name"),
        "os": dev.get("os"),
        "arch": dev.get("arch"),
        "version": dev.get("version"),
        "last_seen": now,
        "meta_json": json.dumps(dev, ensure_ascii=False)
    }
    con.execute("""
    INSERT INTO devices(id,name,os,arch,version,last_seen,meta_json)
    VALUES(:id,:name,:os,:arch,:version,:last_seen,:meta_json)
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      os=excluded.os,
      arch=excluded.arch,
      version=excluded.version,
      last_seen=:last_seen,
      meta_json=:meta_json
    """, payload)

# ---- INSERT EVENT ----
def insert_event(con, ev: dict):
    """
    ev minimal:
    {
      "ts": 1756..., "type":"fast_event"|"scan_result",
      "source":"agent"|"api",
      "path": "C:\\path\\file.bin",
      "severity": "low|medium|high|critical" (opsional),
      "action": "simulate|allow|quarantine|delete|ignore" (opsional),
      "agent": {"id":"dev-xav","hostname":"XavPC","os":"Windows"},
      "meta": {...},                # optional
      "details": {...},             # optional (hasil parsers/heuristik)
      "category": "document|image|archive|executable|...",
      "size": 1234,
      "sha256": "..."               # kalau ada
    }
    """
    ts = int(ev.get("ts") or time.time())
    agent = ev.get("agent") or {}
    device_id = agent.get("id")

    # siapkan device jika ada
    if device_id:
        upsert_device(con, agent)

    path = ev.get("path") or ""
    filename = os.path.basename(path)
    ext = (pathlib.Path(filename).suffix[1:]).lower() if filename else None

    row = {
        "ts": ts,
        "type": ev.get("type","fast_event"),
        "source": ev.get("source","agent"),
        "device_id": device_id,
        "path": path,
        "filename": filename,
        "ext": ext,
        "category": ev.get("category"),
        "size": ev.get("size"),
        "sha256": ev.get("sha256"),
        "mime": (ev.get("mime") or ev.get("content_type")),
        "severity": ev.get("severity"),
        "action": ev.get("action"),
        "vt_vendors": (ev.get("vt") or {}).get("vendors"),
        "vt_malicious": (ev.get("vt") or {}).get("malicious"),
        "vt_suspicious": (ev.get("vt") or {}).get("suspicious"),
        "quarantine_path": (ev.get("quarantine") or {}).get("path"),
        "agent_json": json.dumps(agent, ensure_ascii=False),
        "meta_json": json.dumps(ev.get("meta") or {}, ensure_ascii=False),
        "details_json": json.dumps(ev.get("details") or {}, ensure_ascii=False)
    }

    con.execute("""
    INSERT INTO events
    (ts,type,source,device_id,path,filename,ext,category,size,sha256,mime,
     severity,action,vt_vendors,vt_malicious,vt_suspicious,quarantine_path,
     agent_json,meta_json,details_json)
    VALUES
    (:ts,:type,:source,:device_id,:path:,:filename,:ext,:category,:size,:sha256,:mime,
     :severity,:action,:vt_vendors,:vt_malicious,:vt_suspicious,:quarantine_path,
     :agent_json,:meta_json,:details_json)
    """.replace(":path:",":path"), row)  # escape :path: hack utk colon

# ---- VT CACHE ----
def vt_cache_get(con, sha256: str):
    cur = con.execute("SELECT * FROM vt_cache WHERE sha256=?", (sha256,))
    r = cur.fetchone()
    return dict(r) if r else None

def vt_cache_put(con, sha256: str, vt_summary: dict, raw_json: dict|None, now: int|None=None):
    now = now or int(time.time())
    row = {
        "sha256": sha256,
        "vendors": vt_summary.get("vendors"),
        "malicious": vt_summary.get("malicious"),
        "suspicious": vt_summary.get("suspicious"),
        "undetected": vt_summary.get("undetected"),
        "last_checked": now,
        "raw_json": json.dumps(raw_json or {}, ensure_ascii=False)
    }
    con.execute("""
    INSERT INTO vt_cache(sha256,vendors,malicious,suspicious,undetected,last_checked,raw_json)
    VALUES(:sha256,:vendors,:malicious,:suspicious,:undetected,:last_checked,:raw_json)
    ON CONFLICT(sha256) DO UPDATE SET
      vendors=excluded.vendors,
      malicious=excluded.malicious,
      suspicious=excluded.suspicious,
      undetected=excluded.undetected,
      last_checked=excluded.last_checked,
      raw_json=excluded.raw_json
    """, row)

