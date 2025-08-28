# backend/events_db.py
from __future__ import annotations
import sqlite3, json, time
from pathlib import Path
from typing import Any, Dict, List, Optional

class EventsDB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._migrate()

    def _migrate(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts REAL NOT NULL,
          type TEXT NOT NULL,
          path TEXT,
          severity TEXT,
          action TEXT,
          source TEXT,
          device_id TEXT,
          data TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS ix_events_type ON events(type);

        CREATE TABLE IF NOT EXISTS devices(
          id TEXT PRIMARY KEY,
          name TEXT,
          os TEXT,
          arch TEXT,
          version TEXT,
          last_seen REAL,
          meta TEXT
        );
        """)
        self._conn.commit()

    def insert_event(self, e: Dict[str, Any]) -> int:
        ts = float(e.get("ts", time.time()))
        # tarik severity/action bila nested di result/policy
        sev = e.get("severity")
        if sev is None and isinstance(e.get("result"), dict):
            sev = e["result"].get("severity")
        act = e.get("action")
        if act is None and isinstance(e.get("policy"), dict):
            act = e["policy"].get("action")
        row = (
            ts,
            str(e.get("type", "unknown")),
            e.get("path"),
            sev,
            act,
            e.get("source"),
            (e.get("agent") or {}).get("id") if isinstance(e.get("agent"), dict) else e.get("device_id"),
            json.dumps(e, ensure_ascii=False)
        )
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO events(ts,type,path,severity,action,source,device_id,data) VALUES(?,?,?,?,?,?,?,?)",
            row
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def upsert_device(self, agent: Dict[str, Any]) -> str:
        if not isinstance(agent, dict):
            return ""
        dev_id = str(agent.get("id") or agent.get("hostname") or agent.get("name") or "")
        if not dev_id:
            return ""
        name = agent.get("name") or agent.get("hostname") or dev_id
        meta = json.dumps(agent, ensure_ascii=False)
        ts = time.time()
        cur = self._conn.cursor()
        cur.execute("""
          INSERT INTO devices(id,name,os,arch,version,last_seen,meta)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            os=COALESCE(excluded.os, devices.os),
            arch=COALESCE(excluded.arch, devices.arch),
            version=COALESCE(excluded.version, devices.version),
            last_seen=excluded.last_seen,
            meta=excluded.meta
        """, (
            dev_id, name,
            agent.get("os"), agent.get("arch"), agent.get("version"),
            ts, meta
        ))
        self._conn.commit()
        return dev_id

    def recent_events(self, limit:int=200, since: Optional[float]=None, typ: Optional[str]=None) -> List[Dict[str, Any]]:
        sql = "SELECT id,ts,type,path,severity,action,source,device_id,data FROM events"
        wh, args = [], []
        if since is not None:
            wh.append("ts > ?"); args.append(float(since))
        if typ:
            wh.append("type = ?"); args.append(typ)
        if wh:
            sql += " WHERE " + " AND ".join(wh)
        sql += " ORDER BY ts DESC LIMIT ?"; args.append(int(limit))
        out = []
        cur = self._conn.execute(sql, args)
        for r in cur.fetchall():
            try: payload = json.loads(r[8])
            except Exception: payload = {}
            out.append({
                "id": r[0], "ts": r[1], "type": r[2], "path": r[3],
                "severity": r[4], "action": r[5], "source": r[6],
                "device_id": r[7], "payload": payload
            })
        return out

    def timeseries(self, start: float, end: float, bucket_seconds: int = 3600) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT ts, COALESCE(severity,'low') FROM events "
            "WHERE ts BETWEEN ? AND ? AND type IN ('scan_result','fast_event')",
            (start, end)
        ).fetchall()
        n = int((end - start) / bucket_seconds) + 1
        buckets = [{"t": start + i * bucket_seconds, "low":0, "medium":0, "high":0, "critical":0} for i in range(n)]
        for ts, sev in rows:
            idx = int((float(ts) - start) // bucket_seconds)
            if 0 <= idx < n:
                key = str(sev).lower()
                if key not in ("low", "medium", "high", "critical"):
                    key = "low"
                buckets[idx][key] += 1
        return buckets

    def list_devices(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id,name,os,arch,version,last_seen,meta FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        out = []
        for r in rows:
            try: meta = json.loads(r[6])
            except Exception: meta = {}
            out.append({
                "id": r[0], "name": r[1], "os": r[2], "arch": r[3],
                "version": r[4], "last_seen": r[5], "meta": meta
            })
        return out
