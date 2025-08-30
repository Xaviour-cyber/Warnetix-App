# backend/api.py
import os, json, time, uuid, hashlib, importlib, sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import text

from backend.db import SessionLocal, init_schema
from backend.db import scan_file_sync  # pakai scan_file_sync single-file
from . import scanner_api

# ---------------------------------------------------------------------
# Setup umum
# ---------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPLOAD_DIR = PROJECT_ROOT / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("warnetix.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

router = APIRouter()

# ---------------------------------------------------------------------
# Helper: dynamic import boto3 + fallback botocore exceptions
# ---------------------------------------------------------------------
try:
    from botocore.exceptions import BotoCoreError, NoCredentialsError  # type: ignore[reportMissingImports]
except Exception:
    class BotoCoreError(Exception): ...
    class NoCredentialsError(Exception): ...

def _boto3():
    try:
        return importlib.import_module("boto3")
    except Exception:
        return None

# ---------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------
SIG_DIR = Path("signature")
SIG_FILES = ["malware_signatures.json", "phishing_signatures.json", "ransomware_signatures.json"]

def _sig_version() -> str:
    h = hashlib.sha256()
    for name in sorted(SIG_FILES):
        p = SIG_DIR / name
        if p.exists():
            h.update(p.read_bytes())
    return h.hexdigest()[:12]

def _sig_payload():
    data = {}
    for name in SIG_FILES:
        p = SIG_DIR / name
        if p.exists():
            data[name] = json.loads(p.read_text(encoding="utf-8"))
    return data

@router.get("/api/signatures/version")
def get_sig_version():
    return {"version": _sig_version(), "files": SIG_FILES, "updated_at": int(time.time())}

@router.get("/api/signatures/latest")
def get_signatures_latest():
    payload = _sig_payload()
    return {
        "version": _sig_version(),
        "data": payload,
        "count": {k: (len(v) if isinstance(v, list) else 1) for k, v in payload.items()},
    }

# ---------------------------------------------------------------------
# Health-like: /ready (cek model & akses S3)
# (catatan: /health ada di app.py biar tidak duplikat)
# ---------------------------------------------------------------------
def _s3_ready() -> bool:
    b3 = _boto3()
    if not b3:
        return False
    try:
        s3 = b3.client(
            "s3",
            endpoint_url=os.getenv("S3_ENDPOINT"),
            aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY"),
            region_name=os.getenv("S3_REGION"),
        )
        s3.list_buckets()  # ping sederhana
        return True
    except (BotoCoreError, NoCredentialsError, Exception):
        return False

@router.get("/ready")
def ready():
    model_ok = Path("backend/scanner_core/models/anomaly_iforest.joblib").exists()
    s3_ok = _s3_ready()
    return {"ok": bool(model_ok and s3_ok), "model_loaded": model_ok, "s3": s3_ok, "signatures_version": _sig_version()}

# ---------------------------------------------------------------------
# DB util & riwayat hasil (scan_results SQLite milik scanner_api)
# ---------------------------------------------------------------------
def _get_local_conn():
    try:
        return sqlite3.connect(str(PROJECT_ROOT / "backend" / "scanner_core" / "warnetix_scanner.db"), check_same_thread=False)
    except Exception:
        return None

@router.get("/scan-results")
def get_scan_results():
    conn = _get_local_conn()
    if not conn:
        raise HTTPException(status_code=500, detail="DB unavailable")
    cur = conn.cursor()
    cur.execute("""
        SELECT id, filename, path, sha256, filesize, entropy, signature_match, signature_reason,
               is_anomaly, anomaly_score, vt_threat_score, vt_engines, created_at
        FROM scan_results
        ORDER BY id DESC
        LIMIT 200
    """)
    rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r[0], "filename": r[1], "path": r[2], "sha256": r[3],
            "filesize": r[4], "entropy": r[5], "signature_match": bool(r[6]),
            "signature_reason": r[7], "is_anomaly": bool(r[8]), "anomaly_score": r[9],
            "vt_threat_score": r[10], "vt_engines": json.loads(r[11]) if r[11] else None,
            "created_at": r[12],
        })
    return JSONResponse(status_code=200, content=out)

# ---------------------------------------------------------------------
# Single-file upload (versi ringan) → pindah ke path baru agar tidak bentrok
# ---------------------------------------------------------------------
@router.post("/scan/upload-one")
async def scan_upload_one(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    fn = Path(file.filename).name
    save_path = UPLOAD_DIR / f"{int(time.time())}_{fn}"
    try:
        with open(save_path, "wb") as w:
            w.write(await file.read())
    except Exception as e:
        logger.exception("Failed to save upload: %s", e)
        raise HTTPException(status_code=500, detail="Failed to save upload")

    try:
        result = scanner_api.scan_file_sync(str(save_path), wait_for_vt=False)
    except Exception as e:
        logger.exception("scan_file_sync error: %s", e)
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    # respons ringkas
    return {
        "id": result.get("id"),
        "filename": result.get("filename"),
        "sha256": result.get("sha256"),
        "threat_score": result.get("threat_score"),
        "severity": result.get("status"),
        "signature_match": bool(result.get("signature_match")),
        "is_anomaly": bool(result.get("is_anomaly")),
        "anomaly_score": result.get("anomaly_score"),
        "escalated_to_vt": bool(result.get("escalated_to_vt")),
        "vt_threat_score": result.get("vt_threat_score"),
    }

# ---------------------------------------------------------------------
# S3 util + metadata (untuk dipakai endpoint lain kalau perlu)
# ---------------------------------------------------------------------
init_schema()  # pastikan tabel metadata 'scans' ada

def save_report_to_s3(report: dict) -> dict:
    b3 = _boto3()
    if not b3:
        raise RuntimeError("boto3 not available; install or disable S3 save")
    s3 = b3.client(
        "s3",
        endpoint_url=os.getenv("S3_ENDPOINT"),
        aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY"),
        region_name=os.getenv("S3_REGION"),
    )
    rid = report.get("id") or str(uuid.uuid4())
    bucket = os.getenv("S3_BUCKET_REPORTS") or os.getenv("S3_BUCKET_UPLOADS")
    key = f"reports/{rid}.json"
    s3.put_object(Bucket=bucket, Key=key,
                  Body=json.dumps(report, ensure_ascii=False).encode("utf-8"),
                  ContentType="application/json")
    return {"id": rid, "bucket": bucket, "key": key}

def persist_scan_meta(report: dict, s3info: dict):
    with SessionLocal() as s, s.begin():
        s.execute(text("""
            INSERT INTO scans (id, user_id, device_id, filename, size_bytes, sha256,
                               severity, verdict, policy, s3_bucket, s3_key, created_at)
            VALUES (:id, :user_id, :device_id, :filename, :size_bytes, :sha256,
                    :severity, :verdict, :policy, :bucket, :key, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO NOTHING
        """), {
            "id": report.get("id"),
            "user_id": report.get("user_id"),
            "device_id": report.get("device_id"),
            "filename": report.get("file", {}).get("name"),
            "size_bytes": report.get("file", {}).get("size"),
            "sha256": report.get("file", {}).get("sha256"),
            "severity": report.get("severity"),
            "verdict": report.get("verdict"),
            "policy": (report.get("policy") or {}).get("action"),
            "bucket": s3info.get("bucket"),
            "key": s3info.get("key"),
        })
