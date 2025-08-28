# backend/api.py  (UPDATED)
import os
import json
import time
import hashlib
import sqlite3
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from dotenv import load_dotenv
load_dotenv()

# local scanner API
from backend import scanner_api

# config
PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPLOAD_DIR = PROJECT_ROOT / "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("warnetix.api")

app = FastAPI(title="Warnetix Upload & Scan API (updated)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# reuse DB inside scanner_api (scanner_api initialized its own DB). Provide small accessor:
def get_db_conn():
    # scanner_api already created DB connection inside module initialization
    try:
        return sqlite3.connect(str(PROJECT_ROOT / "backend" / "scanner_core" / "warnetix_scanner.db"), check_same_thread=False)
    except Exception:
        return None

@app.post("/scan-file/")
async def scan_file(file: UploadFile = File(...), wait: Optional[bool] = False, background_tasks: BackgroundTasks = None):
    """
    Upload single file, scan using scanner_api.scan_file_sync()
    - wait=true -> blocking VirusTotal check when escalation occurs
    - wait=false -> returns quickly and background VT worker will run
    Response contains complete structured result that frontend can use
    """
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    fn = Path(file.filename).name
    timestamp = int(time.time())
    save_path = UPLOAD_DIR / f"{timestamp}_{fn}"
    try:
        with open(save_path, "wb") as out_f:
            contents = await file.read()
            out_f.write(contents)
    except Exception as e:
        logger.exception("Failed write upload: %s", e)
        raise HTTPException(status_code=500, detail="Failed to save upload")

    # call scanner_api
    try:
        result = scanner_api.scan_file_sync(str(save_path), wait_for_vt=bool(wait))
    except Exception as e:
        logger.exception("scan_file_sync error: %s", e)
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    # If we asked for non-blocking VT and the function scheduled a background worker,
    # scanner_api already starts background thread (if VT client present).
    # Build response shaped for frontend:
    response = {
        "scan": {
            "id": result.get("id"),
            "filename": result.get("filename"),
            "path": result.get("path"),
            "sha256": result.get("sha256"),
            "filesize": result.get("filesize"),
            "entropy": result.get("entropy"),
            "signature_match": bool(result.get("signature_match")),
            "signature_reason": result.get("signature_reason"),
            "is_anomaly": bool(result.get("is_anomaly")),
            "anomaly_score": result.get("anomaly_score"),
            "escalated_to_vt": bool(result.get("escalated_to_vt")),
            "vt_threat_score": result.get("vt_threat_score"),
            "vt_engines": result.get("vt_engines"),
            "threat_score": result.get("threat_score"),
            "status": result.get("status"),
            "explanations": result.get("explanations"),
            "detected_by": result.get("detected_by"),
            # if vt_info contains permalink, include it
            "vt_permalink": None
        }
    }

    # if vt_info includes permalink or analysis id try to form link (VT UI/permalink differs by account)
    vt_info = result.get("vt_info")
    if isinstance(vt_info, dict):
        # best-effort extraction
        try:
            if "summary" in vt_info and isinstance(vt_info["summary"], dict):
                permalink = vt_info["summary"].get("permalink")
                if permalink:
                    response["scan"]["vt_permalink"] = permalink
            elif vt_info.get("status") in ("completed", "found") and vt_info.get("summary", {}).get("permalink"):
                response["scan"]["vt_permalink"] = vt_info["summary"]["permalink"]
        except Exception:
            pass

    return JSONResponse(status_code=200, content=response)

@app.get("/scan-results/")
async def get_scan_results():
    conn = get_db_conn()
    if not conn:
        raise HTTPException(status_code=500, detail="DB unavailable")
    cur = conn.cursor()
    cur.execute("SELECT id, filename, path, sha256, filesize, entropy, signature_match, signature_reason, is_anomaly, anomaly_score, vt_threat_score, vt_engines, created_at FROM scan_results ORDER BY id DESC LIMIT 200")
    rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r[0],
            "filename": r[1],
            "path": r[2],
            "sha256": r[3],
            "filesize": r[4],
            "entropy": r[5],
            "signature_match": bool(r[6]),
            "signature_reason": r[7],
            "is_anomaly": bool(r[8]),
            "anomaly_score": r[9],
            "vt_threat_score": r[10],
            "vt_engines": json.loads(r[11]) if r[11] else None,
            "created_at": r[12]
        })
    return JSONResponse(status_code=200, content=out)
