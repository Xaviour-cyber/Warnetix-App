# backend/app.py
import os, uuid, shutil, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from colorama import init as colorama_init, Fore, Style

# router tambahan (signatures/ready/single-file/scan-results)
from backend.api import router as aux_router, save_report_to_s3, persist_scan_meta
from backend.db import init_schema

# ---- Local engine
from backend.scanner_api import WarnetixScanner, build_threat_summary

# ---------------------------------------------------------------------
# Env & logging
# ---------------------------------------------------------------------
load_dotenv()
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    # fallback tanpa warna (supaya gak crash di server)
    class _No:
        def __getattr__(self, _): return ""
    Fore = _No()
    Style = _No()
    def colorama_init(*_, **__): ...

FRONTEND_ORIGIN = os.getenv("CORS_ORIGINS", "*")
STORAGE_DIR = os.getenv("STORAGE_DIR", "./data/scan_targets")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "6"))
SIMULATION_DEFAULT = os.getenv("SIMULATION", "true").lower() == "true"

os.makedirs(STORAGE_DIR, exist_ok=True)

class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelno, "")
        prefix = f"{level_color}[{record.levelname:<8}]{Style.RESET_ALL}"
        base = super().format(record)
        return f"{prefix} {base}"

logger = logging.getLogger("warnetix")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(ColorFormatter("%(asctime)s | %(name)s | %(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)

# ---------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------
app = FastAPI(
    title="Warnetix Backend",
    description="Hybrid scanning API (signature + NLP + anomaly + VirusTotal) dengan policy engine.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://warnetix-frontend.up.railway.app",  # ganti dgn domain FE kamu
        "http://localhost:5173",                     # biar dev lokal tetap jalan
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# mount router tambahan
app.include_router(aux_router)

@app.on_event("startup")
def _startup():
    try:
        init_schema()
    except Exception as e:
        logger.warning(f"init_schema warning: {e}")

# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------
class ScanOptions(BaseModel):
    vt_enabled: bool = Field(default=True, description="Aktifkan integrasi VirusTotal")
    vt_upload_if_unknown: bool = Field(default=False, description="Upload sample ke VT jika hash belum ada")
    simulation: bool = Field(default=SIMULATION_DEFAULT, description="Mode aman tanpa karantina nyata")
    max_files: Optional[int] = Field(default=None, description="Batas jumlah file diproses (demo)")

class ScanResult(BaseModel):
    job_id: str
    total_files: int
    scanned_files: int
    items: List[Dict[str, Any]]
    summary: Dict[str, Any]

# ---------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------
scanner = WarnetixScanner(logger=logger)

# ---------------------------------------------------------------------
# Routes utama
# ---------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "engine": "warnetix", "version": "1.0.0"}

@app.post("/scan-file", response_model=ScanResult)
async def scan_file(
    files: List[UploadFile] = File(..., description="Multiple files for scanning"),
    vt_enabled: bool = Form(default=True),
    vt_upload_if_unknown: bool = Form(default=False),
    simulation: bool = Form(default=SIMULATION_DEFAULT),
    max_files: Optional[int] = Form(default=None),
):
    """
    Upload multi-file → pindai paralel → hitung threat score → opsional cek VirusTotal.
    """
    job_id = str(uuid.uuid4())
    logger.info(f"Job {job_id}: menerima {len(files)} file.")

    opts = ScanOptions(
        vt_enabled=vt_enabled,
        vt_upload_if_unknown=vt_upload_if_unknown,
        simulation=simulation,
        max_files=max_files,
    )

    saved_paths = []
    try:
        for f in files[: (max_files or len(files))]:
            dst = os.path.join(STORAGE_DIR, f"{job_id}_{f.filename}")
            with open(dst, "wb") as w:
                shutil.copyfileobj(f.file, w)
            saved_paths.append(dst)
    except Exception as e:
        logger.error(f"Job {job_id}: gagal menyimpan upload: {e}")
        raise HTTPException(status_code=500, detail="Gagal menyimpan file upload.")

    items: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scanner.scan_path, p, opts.dict()): p for p in saved_paths}
        for fut in as_completed(futures):
            path = futures[fut]
            try:
                res = fut.result()  # res: dict hasil scan (memuat id/sha256/policy dsb)
                items.append(res)

                # Simpan report lengkap ke S3 + metadata ke DB (hybrid)
                try:
                    s3info = save_report_to_s3(res)
                    persist_scan_meta(res, s3info)
                except Exception as e:
                    logger.warning(f"Job {job_id}: gagal simpan report ke S3/DB: {e}")

            except Exception as e:
                logger.error(f"Job {job_id}: error scan {path}: {e}")
                items.append({
                    "path": path, "error": str(e), "threat_score": 0.0, "status": "ERROR",
                    "engines": {}
                })

    summary = build_threat_summary(items)
    logger.info(f"Job {job_id}: done. scanned={len(items)} "
                f"high={summary.get('high',0)} medium={summary.get('medium',0)} low={summary.get('low',0)}")

    return ScanResult(job_id=job_id, total_files=len(files), scanned_files=len(items), items=items, summary=summary)

@app.post("/scan-path", response_model=ScanResult)
async def scan_path_api(
    root_path: str = Form(..., description="Path direktori **di server** (gunakan hati-hati)"),
    vt_enabled: bool = Form(default=True),
    vt_upload_if_unknown: bool = Form(default=False),
    simulation: bool = Form(default=SIMULATION_DEFAULT),
    max_files: Optional[int] = Form(default=None),
):
    """
    Pindai direktori di sisi server (demo/local). Jangan buka endpoint ini ke publik tanpa auth!
    """
    job_id = str(uuid.uuid4())
    logger.info(f"Job {job_id}: scan path: {root_path}")

    if not os.path.exists(root_path):
        raise HTTPException(status_code=404, detail="Path tidak ditemukan di server.")

    opts = ScanOptions(
        vt_enabled=vt_enabled,
        vt_upload_if_unknown=vt_upload_if_unknown,
        simulation=simulation,
        max_files=max_files,
    )

    # kumpulkan file
    targets: List[str] = []
    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            targets.append(os.path.join(dirpath, name))
            if max_files and len(targets) >= max_files:
                break
        if max_files and len(targets) >= max_files:
            break

    items: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scanner.scan_path, p, opts.dict()): p for p in targets}
        for fut in as_completed(futures):
            path = futures[fut]
            try:
                res = fut.result()
                items.append(res)

                try:
                    s3info = save_report_to_s3(res)
                    persist_scan_meta(res, s3info)
                except Exception as e:
                    logger.warning(f"Job {job_id}: gagal simpan report S3/DB: {e}")

            except Exception as e:
                logger.error(f"Job {job_id}: error scan {path}: {e}")
                items.append({"path": path, "error": str(e), "threat_score": 0.0, "status": "ERROR", "engines": {}})

    summary = build_threat_summary(items)
    logger.info(f"Job {job_id}: selesai path-scan. scanned={len(items)}")

    return ScanResult(job_id=job_id, total_files=len(targets), scanned_files=len(items), items=items, summary=summary)

@app.exception_handler(Exception)
async def all_exception_handler(_, exc: Exception):
    logger.error(f"UNCAUGHT ERROR: {exc}")
    return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc)})
