# backend/db.py
# FINAL — Kompat scanner_api.py (legacy funcs) + metadata hybrid (SQLAlchemy)
from __future__ import annotations

import os, json, sqlite3
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

# ============================================================
# 1) METADATA HYBRID (Postgres/SQLite via SQLAlchemy) → tabel: scans
# ============================================================
DB_URL = os.getenv("DATABASE_URL") or "sqlite:///backend/data/warnetix.db"
if DB_URL.startswith("sqlite:///"):
    os.makedirs("backend/data", exist_ok=True)

connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite:///") else {}
engine: Engine = create_engine(DB_URL, pool_pre_ping=True, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

DDL_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id TEXT,
  device_id TEXT,
  filename TEXT,
  size_bytes INTEGER,
  sha256 TEXT,
  severity TEXT,
  verdict TEXT,
  policy TEXT,
  s3_bucket TEXT,
  s3_key TEXT
);
"""
DDL_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);",
    "CREATE INDEX IF NOT EXISTS idx_scans_sev ON scans(severity);",
]

def init_schema(apply_external: bool | None = None) -> None:
    # default: JANGAN load schema.sql, kecuali DB_LOAD_EXTERNAL_SCHEMA=1/true
    if apply_external is None:
        apply_external = os.getenv("DB_LOAD_EXTERNAL_SCHEMA", "0").lower() in ("1", "true", "yes")

    with engine.begin() as conn:
        conn.execute(text(DDL_SCANS))
        for idx in DDL_INDEXES:
            conn.execute(text(idx))

    if apply_external and os.path.exists("backend/sql/schema.sql"):
        # panggil loader aman kalau kamu udah pasang helper-nya,
        # atau abaikan block ini kalau kamu belum menambahkan safe loader
        try:
            # _load_external_schema_safely is not defined, skipping its call
            pass
        except Exception as e:
            import logging
            logging.warning(f"skip external schema.sql: {e}")

@dataclass
class ScanMeta:
    id: str
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    filename: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None
    policy: Optional[str] = None
    s3_bucket: Optional[str] = None
    s3_key: Optional[str] = None
    created_at: Optional[datetime] = None

def save_scan_metadata(meta: ScanMeta) -> None:
    payload = asdict(meta)
    payload["created_at"] = payload.get("created_at") or datetime.utcnow()
    if engine.dialect.name == "postgresql":
        sql = text("""
            INSERT INTO scans (id, created_at, user_id, device_id, filename, size_bytes,
                               sha256, severity, verdict, policy, s3_bucket, s3_key)
            VALUES (:id, :created_at, :user_id, :device_id, :filename, :size_bytes,
                    :sha256, :severity, :verdict, :policy, :s3_bucket, :s3_key)
            ON CONFLICT (id) DO UPDATE SET
              user_id=EXCLUDED.user_id, device_id=EXCLUDED.device_id, filename=EXCLUDED.filename,
              size_bytes=EXCLUDED.size_bytes, sha256=EXCLUDED.sha256, severity=EXCLUDED.severity,
              verdict=EXCLUDED.verdict, policy=EXCLUDED.policy,
              s3_bucket=EXCLUDED.s3_bucket, s3_key=EXCLUDED.s3_key
        """)
        with engine.begin() as conn:
            conn.execute(sql, payload)
    else:
        with SessionLocal() as s, s.begin():
            s.execute(text("""
                INSERT OR IGNORE INTO scans (id, created_at, user_id, device_id, filename, size_bytes,
                                             sha256, severity, verdict, policy, s3_bucket, s3_key)
                VALUES (:id, :created_at, :user_id, :device_id, :filename, :size_bytes,
                        :sha256, :severity, :verdict, :policy, :s3_bucket, :s3_key)
            """), payload)
            s.execute(text("""
                UPDATE scans SET user_id=:user_id, device_id=:device_id, filename=:filename,
                                 size_bytes=:size_bytes, sha256=:sha256, severity=:severity,
                                 verdict=:verdict, policy=:policy,
                                 s3_bucket=:s3_bucket, s3_key=:s3_key
                WHERE id=:id
            """), payload)

def persist_scan_meta(report: Dict[str, Any], s3info: Dict[str, Any]) -> None:
    meta = ScanMeta(
        id=report.get("id") or report.get("job_id") or report.get("report_id") or (report.get("sha256") or "nohash"),
        user_id=report.get("user_id"),
        device_id=report.get("device_id"),
        filename=(report.get("file") or {}).get("name") if isinstance(report.get("file"), dict) else report.get("filename"),
        size_bytes=(report.get("file") or {}).get("size") if isinstance(report.get("file"), dict) else report.get("filesize"),
        sha256=(report.get("file") or {}).get("sha256") if isinstance(report.get("file"), dict) else report.get("sha256"),
        severity=report.get("severity") or report.get("status"),
        verdict=report.get("verdict"),
        policy=(report.get("policy") or {}).get("action") if isinstance(report.get("policy"), dict) else report.get("policy"),
        s3_bucket=(s3info or {}).get("bucket"),
        s3_key=(s3info or {}).get("key"),
    )
    save_scan_metadata(meta)

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    q = text("""SELECT id, created_at, user_id, device_id, filename, size_bytes, sha256,
                       severity, verdict, policy, s3_bucket, s3_key
                FROM scans WHERE id=:id""")
    with engine.connect() as conn:
        row = conn.execute(q, {"id": scan_id}).mappings().first()
        return dict(row) if row else None

def list_scans(page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    page = max(1, page); page_size = min(200, max(1, page_size)); off = (page - 1) * page_size
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, created_at, user_id, device_id, filename, size_bytes, sha256,
                   severity, verdict, policy, s3_bucket, s3_key
            FROM scans ORDER BY created_at DESC LIMIT :lim OFFSET :off
        """), {"lim": page_size, "off": off}).mappings().all()
        total = conn.execute(text("SELECT COUNT(1) FROM scans")).scalar_one()
    return {"page": page, "page_size": page_size, "total": int(total), "items": [dict(r) for r in rows]}

def db_healthcheck() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

@contextmanager
def with_session() -> Iterable[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()

# ============================================================
# 2) CORE DB UNTUK scanner_api.py (SQLite langsung) → scan_results, vt_cache, signatures
# ============================================================
CORE_DB_PATH = os.getenv("CORE_DB_PATH", "backend/scanner_core/warnetix_scanner.db")
os.makedirs(os.path.dirname(CORE_DB_PATH), exist_ok=True)

def connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or CORE_DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def migrate(conn: Optional[sqlite3.Connection] = None) -> None:
    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        # hasil scan
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              filename TEXT, path TEXT, sha256 TEXT,
              filesize INTEGER, entropy REAL,
              signature_match INTEGER DEFAULT 0,
              signature_reason TEXT,
              is_anomaly INTEGER DEFAULT 0,
              anomaly_score REAL,
              vt_threat_score REAL,
              vt_engines TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_time ON scan_results(created_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_sha ON scan_results(sha256);")

        # cache VT
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
              sha256 TEXT PRIMARY KEY,
              report_json TEXT,
              updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # signatures (generic, fleksibel)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
              key TEXT PRIMARY KEY,
              kind TEXT,           -- hash|pattern|ext|yara|rule|other
              family TEXT,
              severity TEXT,
              source TEXT,
              data_json TEXT,
              updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_signatures_kind ON signatures(kind);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_signatures_family ON signatures(family);")

        conn.commit()
    finally:
        if close_after:
            conn.close()

def insert_event(data: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> int:
    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        vt_engines = data.get("vt_engines")
        if isinstance(vt_engines, (list, dict)):
            vt_engines = json.dumps(vt_engines, ensure_ascii=False)
        cur.execute("""
            INSERT INTO scan_results
              (filename, path, sha256, filesize, entropy,
               signature_match, signature_reason, is_anomaly, anomaly_score,
               vt_threat_score, vt_engines)
            VALUES
              (:filename, :path, :sha256, :filesize, :entropy,
               :signature_match, :signature_reason, :is_anomaly, :anomaly_score,
               :vt_threat_score, :vt_engines)
        """, {
            "filename": data.get("filename"),
            "path": data.get("path"),
            "sha256": data.get("sha256"),
            "filesize": data.get("filesize"),
            "entropy": data.get("entropy"),
            "signature_match": int(bool(data.get("signature_match"))),
            "signature_reason": data.get("signature_reason"),
            "is_anomaly": int(bool(data.get("is_anomaly"))),
            "anomaly_score": data.get("anomaly_score"),
            "vt_threat_score": data.get("vt_threat_score"),
            "vt_engines": vt_engines,
        })
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        if close_after:
            conn.close()

def vt_cache_get(sha256: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        cur.execute("SELECT report_json, updated_at FROM vt_cache WHERE sha256=?", (sha256,))
        row = cur.fetchone()
        if not row:
            return None
        try:
            report = json.loads(row["report_json"]) if row["report_json"] else None
        except Exception:
            report = row["report_json"]
        return {"sha256": sha256, "report": report, "updated_at": row["updated_at"]}
    finally:
        if close_after:
            conn.close()

def vt_cache_put(sha256: str, report: Any, conn: Optional[sqlite3.Connection] = None) -> None:
    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        payload = json.dumps(report, ensure_ascii=False) if not isinstance(report, str) else report
        cur.execute("""
            INSERT INTO vt_cache (sha256, report_json, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(sha256) DO UPDATE SET
              report_json=excluded.report_json,
              updated_at=CURRENT_TIMESTAMP
        """, (sha256, payload))
        conn.commit()
    finally:
        if close_after:
            conn.close()

# ====== SIGNATURE DB (kompat scanner_api.py) ======
def upsert_signature(sig: Optional[Dict[str, Any]] = None, conn: Optional[sqlite3.Connection] = None, **kwargs) -> str:
    """
    Simpan/replace signature generik. Bisa dipanggil dengan dict 'sig' atau kwargs.
    Prioritas key: sig['key']|sig['pattern']|sig['sha256']|sig['ioc']|sig['ext'].
    Field lain (opsional): kind/type, family, severity, source, data_json / data (objek).
    Return: key yang dipakai.
    """
    data = dict(sig or {})
    data.update(kwargs or {})

    key = data.get("key") or data.get("pattern") or data.get("sha256") or data.get("ioc") or data.get("ext")
    if not key:
        raise ValueError("upsert_signature: 'key'/'pattern'/'sha256'/'ioc'/'ext' diperlukan")

    kind = data.get("kind") or data.get("type") or ("hash" if data.get("sha256") else "pattern")
    family = data.get("family")
    severity = data.get("severity")
    source = data.get("source")
    payload = data.get("data_json")
    if payload is None:
        payload = data.get("data")
    if payload is not None and not isinstance(payload, str):
        payload = json.dumps(payload, ensure_ascii=False)

    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO signatures (key, kind, family, severity, source, data_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
              kind=excluded.kind,
              family=excluded.family,
              severity=excluded.severity,
              source=excluded.source,
              data_json=excluded.data_json,
              updated_at=CURRENT_TIMESTAMP
        """, (key, kind, family, severity, source, payload))
        conn.commit()
        return key
    finally:
        if close_after:
            conn.close()

def signature_lookup(needle: str, kind: Optional[str] = None, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    """
    Cari signature berdasarkan key persis; kalau tidak ketemu dan kind=pattern, coba LIKE.
    Return: dict {key, kind, family, severity, source, data} atau None.
    """
    close_after = False
    if conn is None:
        conn = connect()
        close_after = True
    try:
        cur = conn.cursor()
        cur.execute("SELECT key, kind, family, severity, source, data_json FROM signatures WHERE key=?", (needle,))
        row = cur.fetchone()
        if not row and (kind == "pattern" or kind is None):
            # fallback: cari pattern yang sama persis di data_json (sederhana, tanpa json1)
            cur.execute("SELECT key, kind, family, severity, source, data_json FROM signatures WHERE key LIKE ? LIMIT 1", (needle,))
            row = cur.fetchone()
        if not row:
            return None
        data = None
        if row["data_json"]:
            try:
                data = json.loads(row["data_json"])
            except Exception:
                data = row["data_json"]
        return {
            "key": row["key"],
            "kind": row["kind"],
            "family": row["family"],
            "severity": row["severity"],
            "source": row["source"],
            "data": data,
        }
    finally:
        if close_after:
            conn.close()

__all__ = [
    # Hybrid metadata (SQLAlchemy)
    "engine", "SessionLocal", "init_schema", "ScanMeta",
    "save_scan_metadata", "persist_scan_meta",
    "get_scan_by_id", "list_scans", "db_healthcheck", "with_session",
    # Core legacy untuk scanner_api.py (SQLite)
    "connect", "migrate", "insert_event",
    "vt_cache_get", "vt_cache_put",
    "signature_lookup", "upsert_signature",
]
