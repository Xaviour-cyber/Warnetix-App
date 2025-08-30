# scanner_api.py — Warnetix (FINAL w/ offline signature DB lookup + SSE signature_hit + AI loader in startup)
from __future__ import annotations
from typing import Any, Dict, List
from dotenv import load_dotenv
load_dotenv()

# ---- FastAPI + DB bootstrap
from fastapi import FastAPI
from .db import migrate, connect, insert_event, vt_cache_get, vt_cache_put
from .db import signature_lookup, upsert_signature  # helper signature DB (MBZ/Kaggle)

app = FastAPI(title="Warnetix Scanner API", version="3.2.5")
CONN = None

# === [AI BLOCK #1] — lokasi model v2 yang kamu minta ===
from pathlib import Path
ANOM_PATH = Path("backend/scanner_core/models/anomaly_iforest.joblib")  # kamu bisa ganti jalur ini kapan saja

@app.on_event("startup")
async def _startup():
    """
    Startup awal: migrasi + konek DB, dan (BARU) load model anomaly v2 ke app.state.*
    """
    global CONN
    migrate()
    CONN = connect()
    app.state.db = CONN
    print("[DB] EventsDB connected.")

    # === [AI BLOCK #2] — load anomaly model (IsolationForest v2) ===
    # Model bisa berupa:
    # - dict {"model": estimator, "features": [...]} (bundle)
    # - pipeline/estimator joblib dengan attribute feature_names_in_ / steps[-1][1].feature_names_in_
    try:
        from joblib import load as joblib_load  # lazy import biar cepat
        import numpy as np  # untuk _ai_score di bawah
        app.state.np = np  # simpan sekalian (dipakai _ai_score)

        if ANOM_PATH.exists():
            art = joblib_load(ANOM_PATH)
            app.state.anom_model = art
            feats = None

            # cari fitur
            if isinstance(art, dict):
                feats = art.get("features")
                if feats is None:
                    mdl = art.get("model")
                    if hasattr(mdl, "feature_names_in_"):
                        feats = list(mdl.feature_names_in_)
            else:
                if hasattr(art, "feature_names_in_"):
                    feats = list(art.feature_names_in_)
                elif hasattr(art, "steps") and len(art.steps) and hasattr(art.steps[-1][1], "feature_names_in_"):
                    feats = list(art.steps[-1][1].feature_names_in_)

            # default fallback (6 fitur generik)
            app.state.anom_features = feats or [
                "size_kb", "entropy", "string_count", "spec_char_ratio", "import_count", "macro_score"
            ]
            print(f"[AI] Anomaly model loaded: {ANOM_PATH.name} features={app.state.anom_features}")
        else:
            app.state.anom_model = None
            app.state.anom_features = ["size_kb","entropy","string_count","spec_char_ratio","import_count","macro_score"]
            print("[AI] Anomaly model not found, AI disabled.")
    except Exception as e:
        app.state.anom_model = None
        app.state.anom_features = ["size_kb","entropy","string_count","spec_char_ratio","import_count","macro_score"]
        print("[AI] Failed loading anomaly model:", repr(e))

@app.on_event("shutdown")
async def _shutdown():
    global CONN
    try:
        if CONN:
            CONN.close()
            print("[DB] EventsDB closed.")
    except Exception:
        pass

# ===== standard imports =====
import hashlib
import os
import io
import json
import math
import mimetypes
import logging
import time
import asyncio
import queue
import threading
import shutil  # quarantine/move
import sqlite3
import concurrent.futures as futures
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union

import numpy as np
import pandas as pd
from fastapi import File, UploadFile, Form, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

# ---------- optional MIME detector ----------
try:
    import magic  # type: ignore
    HAS_MAGIC = True
except Exception:
    HAS_MAGIC = False

from joblib import load as joblib_load

# ---------- local modules (tahan banting import path) ----------
# VirusTotal client
try:
    from backend.vt_client import VirusTotalClient  # sesuai struktur kamu
except Exception:
    try:
        from vt_client import VirusTotalClient  # fallback
    except Exception:
        VirusTotalClient = None  # type: ignore

# NLP (pakai nlp.py)
try:
    from backend import nlp as _nlp_mod
except Exception:
    try:
        import nlp as _nlp_mod  # type: ignore
    except Exception:
        _nlp_mod = None  # type: ignore

# watcher (folder monitoring)
try:
    from backend.watcher import FileWatcher  # mode paket (uvicorn backend.app:app)
except Exception:
    try:
        from .watcher import FileWatcher  # dipanggil relatif kalau running dari modul yang sama
    except Exception:
        # Fallback stub: server API nggak butuh watcher -> jangan crash
        class FileWatcher:  # type: ignore
            def __init__(self, *args, **kwargs): ...
            def start(self): ...
            def stop(self): ...

# EventsDB (kalau modul eksternal belum ada, fallback minimal SQLite)
try:
    from backend.events_db import EventsDB
except Exception:
    try:
        from events_db import EventsDB  # type: ignore
    except Exception:
        class EventsDB:  # noqa: N801
            def __init__(self, db_path: Path) -> None:
                self.path = Path(db_path)
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.conn = sqlite3.connect(self.path)
                self.conn.row_factory = sqlite3.Row
                c = self.conn.cursor()
                c.execute("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    type TEXT,
                    severity TEXT,
                    source TEXT,
                    data TEXT
                )""")
                c.execute("""
                CREATE TABLE IF NOT EXISTS devices(
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    os TEXT,
                    last_seen REAL
                )""")
                self.conn.commit()

            def insert_event(self, obj: Dict[str, Any]) -> None:
                c = self.conn.cursor()
                c.execute(
                    "INSERT INTO events(ts,type,severity,source,data) VALUES(?,?,?,?,?)",
                    (
                        float(obj.get("ts", time.time())),
                        str(obj.get("type", "")),
                        str(obj.get("severity", "")),
                        str(obj.get("source", "")),
                        json.dumps(obj, ensure_ascii=False),
                    ),
                )
                self.conn.commit()

            def upsert_device(self, d: Dict[str, Any]) -> None:
                c = self.conn.cursor()
                c.execute(
                    "INSERT INTO devices(id,name,os,last_seen) VALUES(?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET name=excluded.name, os=excluded.os, last_seen=excluded.last_seen",
                    (
                        str(d.get("id") or d.get("device_id") or d.get("hostname") or "unknown"),
                        str(d.get("name") or d.get("hostname") or "device"),
                        str(d.get("os") or ""),
                        float(d.get("last_seen", time.time())),
                    ),
                )
                self.conn.commit()

            def recent_events(self, limit: int = 200, since: float | None = None, typ: str | None = None) -> List[Dict[str, Any]]:
                q = "SELECT * FROM events"
                params: list[Any] = []
                cond: list[str] = []
                if since is not None:
                    cond.append("ts >= ?")
                    params.append(float(since))
                if typ:
                    cond.append("type = ?")
                    params.append(typ)
                if cond:
                    q += " WHERE " + " AND ".join(cond)
                q += " ORDER BY ts DESC LIMIT ?"
                params.append(int(limit))
                rows = [dict(r) for r in self.conn.execute(q, params)]
                # parse data JSON
                for r in rows:
                    try:
                        r["data"] = json.loads(r.get("data") or "{}")
                    except Exception:
                        pass
                return rows

            def list_devices(self) -> List[Dict[str, Any]]:
                return [dict(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")]

            def timeseries(self, start: float, end: float, bucket_seconds: int = 3600) -> List[Dict[str, Any]]:
                res: Dict[int, Dict[str, int]] = {}
                for r in self.conn.execute(
                    "SELECT ts, severity FROM events WHERE ts BETWEEN ? AND ?",
                    (float(start), float(end)),
                ):
                    b = int(float(r["ts"]) // bucket_seconds) * bucket_seconds
                    sev = (r["severity"] or "").lower()
                    d = res.setdefault(b, {"count": 0, "high": 0, "critical": 0})
                    d["count"] += 1
                    if sev == "high":
                        d["high"] += 1
                    if sev == "critical":
                        d["critical"] += 1
                return [{"t": k, **res[k]} for k in sorted(res.keys())]

# ===== paths & env =====
ROOT = Path(__file__).resolve().parents[1]   # .../backend
PROJ = ROOT.parent                           # project root
load_dotenv(PROJ / ".env")

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
AGENT_TOKEN = os.getenv("WARNETIX_AGENT_TOKEN", "").strip()  # shared secret untuk C++ agent (opsional)

SIGN_DIR = PROJ / "signature"
SIG_RANSOM = SIGN_DIR / "ransomware_signatures.json"
SIG_MAL = SIGN_DIR / "malware_signatures.json"
SIG_PHISH = SIGN_DIR / "phishing_signatures.json"

# kandidat model lama (AnomalyModel) — tetap dipakai oleh scan_single_file
MODEL_CANDIDATES = [
    ROOT / "scanner_core" / "models" / "anomaly_model_iforest_v2.joblib",
    ROOT / "scanner_core" / "anomaly_model_iforest_v2.joblib",
    PROJ / "backend" / "sample_files" / "anomaly_model_iforest_v2.joblib",
]

UPLOADS_DIR = PROJ / "uploads"
OUTPUT_DIR = PROJ / "data" / "output"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ===== Action Policy =====
QUARANTINE_DIR = PROJ / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
POLICY_MODE = os.getenv("WARNETIX_POLICY", "simulate").lower()          # simulate | rename | quarantine
POLICY_MIN_SEVERITY = os.getenv("WARNETIX_POLICY_MIN", "high").lower()  # low | medium | high | critical
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
def _sev_ge(a: str, b: str) -> bool:
    return _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0)

# ===== logging =====
LOG_FMT = "[%(levelname)-8s] %(asctime)s | warnetix | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT, datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("warnetix")

# ===== CORS =====
app.middleware_stack = None  # reset stack sebelum re-add CORS (aman di reload)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== utils =====
TEXT_EXT = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".md", ".ini", ".conf"}
BIN_READ = 128 * 1024
TXT_READ = 200_000

def sha256_bytes(buf: bytes) -> str:
    h = hashlib.sha256()
    h.update(buf)
    return h.hexdigest()

def sha256_file(path: Path, chunk: int = 1_048_576) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()

# helper MD5 untuk upload/agent push
def _md5_of_file(path: Path, chunk: int = 1_048_576) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()

def _get_sig_conn():
    """Ambil koneksi SQLite untuk signature_lookup: pakai app.state.db kalau ada, fallback connect()."""
    try:
        conn = getattr(app.state, "db", None)
        if conn:
            return conn
    except Exception:
        pass
    try:
        return connect()
    except Exception:
        return None

def calc_entropy(sample: bytes, bins: int = 256) -> float:
    if not sample:
        return 0.0
    counts = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=bins)
    probs = counts / counts.sum()
    nz = probs[probs > 0]
    return float((-nz * np.log2(nz)).sum())

def guess_mime(path: Path, head: Optional[bytes] = None) -> str:
    if HAS_MAGIC:
        try:
            if head is not None:
                return magic.from_buffer(head, mime=True) or "application/octet-stream"
            return magic.from_file(str(path), mime=True) or "application/octet-stream"
        except Exception:
            pass
    g, _ = mimetypes.guess_type(str(path))
    return g or "application/octet-stream"

def is_probably_executable(path: Path, head: Optional[bytes]) -> int:
    if not head:
        return 0
    sigs = [b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"]
    return 1 if any(head.startswith(s) for s in sigs) else 0

# ===== signature JSON (local) =====
def _load_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

class SignatureDB:
    def __init__(self) -> None:
        self.ransom = _load_json(SIG_RANSOM)
        self.malware = _load_json(SIG_MAL)
        self.phishing = _load_json(SIG_PHISH)

        def _list(d: Dict[str, Any], k: str) -> List[str]:
            v = d.get(k, [])
            return v if isinstance(v, list) else []

        self.ransom_hashes = set(_list(self.ransom, "hashes"))
        self.ransom_kw = _list(self.ransom, "keywords")
        self.ransom_ext = set(_list(self.ransom, "suspicious_extensions"))

        self.mal_hashes = set(_list(self.malware, "hashes"))
        self.mal_kw = _list(self.malware, "keywords")
        self.mal_ext = set(_list(self.malware, "suspicious_extensions"))

        self.phish_kw = _list(self.phishing, "keywords")
        self.phish_domains = set(_list(self.phishing, "domains"))
        self.phish_ext = set(_list(self.phishing, "extensions"))

    def match(self, *, sha256: str, ext: str, text: str) -> Dict[str, Any]:
        hits: List[str] = []
        votes: List[str] = []

        if sha256 in self.ransom_hashes:
            hits.append("RANSOM_HASH"); votes.append("ransomware")
        if sha256 in self.mal_hashes:
            hits.append("MALWARE_HASH"); votes.append("malware")
        if ext in self.ransom_ext:
            hits.append("RANSOM_EXT"); votes.append("ransomware")
        if ext in self.mal_ext:
            hits.append("MALWARE_EXT"); votes.append("malware")
        if ext in self.phish_ext:
            hits.append("PHISH_EXT"); votes.append("phishing")

        tl = text.lower()

        def _c(keys: List[str]) -> int:
            return sum(1 for k in keys if k.lower() in tl)

        cr = _c(self.ransom_kw); cm = _c(self.mal_kw); cp = _c(self.phish_kw)
        if cr: hits.append(f"RANSOM_KW({cr})"); votes.append("ransomware")
        if cm: hits.append(f"MALWARE_KW({cm})"); votes.append("malware")
        if cp: hits.append(f"PHISH_KW({cp})"); votes.append("phishing")
        if any(d in tl for d in self.phish_domains):
            hits.append("PHISH_DOMAIN"); votes.append("phishing")

        score = 0.0
        for tag in hits:
            if "HASH" in tag: score += 0.60
            elif "EXT" in tag: score += 0.25
            elif "KW" in tag: score += 0.25
            elif "DOMAIN" in tag: score += 0.30
        return {"hits": hits, "votes": votes, "score": float(min(1.0, score))}

SIG = SignatureDB()

# ===== anomaly model lama (tetap dipertahankan untuk kompatibilitas) =====
class AnomalyModel:
    def __init__(self) -> None:
        self.model = None
        self.features: List[str] = []
        self.scaler_mean: Optional[np.ndarray] = None
        self.scaler_scale: Optional[np.ndarray] = None
        self.path: Optional[Path] = None

        for c in MODEL_CANDIDATES:
            if c.exists():
                try:
                    art = joblib_load(c)
                    self.model = art["model"]
                    self.features = art["features"]
                    self.scaler_mean = np.array(art["scaler_mean"])
                    self.scaler_scale = np.array(art["scaler_scale"])
                    self.path = c
                    log.info(f"Anomaly model loaded: {c}")
                    break
                except Exception as e:
                    log.warning(f"Failed load model {c}: {e}")
        if not self.model:
            log.warning("Anomaly model not found, AI disabled.")

    def available(self) -> bool:
        return self.model is not None

    def predict(self, feat: Dict[str, float]) -> Tuple[int, float]:
        if not self.available():
            return 0, 0.0
        x = np.array([feat.get(f, 0.0) for f in self.features]).reshape(1, -1)
        x = (x - self.scaler_mean) / (self.scaler_scale + 1e-12)
        pred = self.model.predict(x)[0]                  # -1 anomaly, 1 normal
        raw = float(self.model.decision_function(x)[0])  # besar=normal
        return (1 if pred == -1 else 0), raw

ANOM = AnomalyModel()

# === [AI BLOCK #3] — util skor cepat memakai app.state.anom_model (baru)
def _ai_score(app, features: dict) -> tuple[float, str]:
    """
    Gunakan model di app.state.anom_model (kalau ada) untuk kasih skor cepat.
    Return: (score_raw, severity_hint) di mana makin kecil berarti makin anom.
    """
    model = getattr(app.state, "anom_model", None)
    if not model:
        return 0.0, "low"

    np_mod = getattr(app.state, "np", np)
    cols = getattr(app.state, "anom_features",
                   ["size_kb","entropy","string_count","spec_char_ratio","import_count","macro_score"])
    x = np_mod.array([[float(features.get(k, 0.0)) for k in cols]], dtype=float)
    try:
        est = model["model"] if isinstance(model, dict) and "model" in model else model
        if hasattr(est, "decision_function"):
            val = float(est.decision_function(x)[0])
        elif hasattr(est, "score_samples"):
            val = float(est.score_samples(x)[0])
        else:
            val = 0.0
    except Exception:
        val = 0.0

    sev = "low"
    if val < -0.2: sev = "medium"
    if val < -0.6: sev = "high"
    if val < -1.0: sev = "critical"
    return val, sev

# ===== feature extractor =====
def extract_features(path: Path) -> Dict[str, Any]:
    try:
        head = path.read_bytes()[:BIN_READ]
    except Exception:
        head = b""
    try:
        mime = guess_mime(path, head)
    except Exception:
        mime = "application/octet-stream"
    ext = path.suffix.lower()
    size = path.stat().st_size if path.exists() else 0
    entropy = calc_entropy(head)
    is_exec = is_probably_executable(path, head)
    sha = sha256_file(path) if path.exists() else sha256_bytes(head)
    text_snippet = ""
    if ext in TEXT_EXT:
        try:
            text_snippet = path.read_text(errors="ignore")[:TXT_READ]
        except Exception:
            text_snippet = ""
    feat = {
        "entropy": float(entropy),
        "filesize_kb": float(size / 1024.0),
        "is_executable": float(is_exec),
        "is_office_doc": float(ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}),
        "is_archive": float(ext in {".zip", ".rar", ".7z", ".gz", ".bz2"}),
        "is_script": float(ext in {".js", ".vbs", ".bat", ".ps1", ".sh", ".py"}),
        "mime_is_pdf": float(mime == "application/pdf"),
    }
    return {
        "path": str(path),
        "name": path.name,
        "ext": ext,
        "mime": mime,
        "size": size,
        "sha256": sha,
        "text_snippet": text_snippet,
        "features": feat,
    }

# ===== fusion =====
def fuse_threat_score(ai_is_anom: int, ai_raw: float, sig_score: float, vt_engines: int, nlp_score: float) -> Tuple[float, str]:
    ai_comp = 0.0
    if ai_is_anom:
        ai_comp = 1.0 / (1.0 + math.exp(3.0 * ai_raw))
    vt_comp = min(1.0, vt_engines / 8.0) if vt_engines > 0 else 0.0
    score = 0.45 * vt_comp + 0.25 * sig_score + 0.20 * ai_comp + 0.10 * max(0.0, min(1.0, nlp_score))
    score = float(max(0.0, min(1.0, score)))
    if score >= 0.80: sev = "critical"
    elif score >= 0.55: sev = "high"
    elif score >= 0.35: sev = "medium"
    else: sev = "low"
    return score, sev

def vote_category(sig_votes: List[str], vt_tags: List[str], nlp_bias: float) -> str:
    bucket = sig_votes + [t for t in vt_tags if t in {"ransomware", "trojan", "worm", "spyware", "phishing"}]
    if nlp_bias >= 0.65:
        bucket.append("phishing")
    if not bucket:
        return "unknown"
    return pd.Series(bucket).value_counts().index[0]

# ===== scanner core =====
def _nlp_analyze(text: str) -> Dict[str, Any]:
    # adaptif ke modul nlp yang kamu punya
    if _nlp_mod is None:
        return {"lang": "unknown", "nlp_score": 0.0, "suspicious_sentences": [], "email_header": {"risk": 0.0, "flags": []}}
    if hasattr(_nlp_mod, "analyze_text_and_headers"):
        return _nlp_mod.analyze_text_and_headers(text)
    if hasattr(_nlp_mod, "analyze_text"):
        s = float(_nlp_mod.analyze_text(text) or 0.0)
        return {"lang": "unknown", "nlp_score": s, "suspicious_sentences": [], "email_header": {"risk": 0.0, "flags": []}}
    return {"lang": "unknown", "nlp_score": 0.0, "suspicious_sentences": [], "email_header": {"risk": 0.0, "flags": []}}

def scan_single_file(path: Path, vt_client: Optional[Any]) -> Dict[str, Any]:
    meta = extract_features(path)

    sig_res = SIG.match(sha256=meta["sha256"], ext=meta["ext"], text=meta["text_snippet"])
    ai_is_anom, ai_raw = ANOM.predict(meta["features"])

    # juga sediakan skor cepat dari model app.state (opsional)
    try:
        _ai_raw2, _ai_sev_hint = _ai_score(app, {
            "size_kb": meta["size"] / 1024.0,
            "entropy": calc_entropy(path.read_bytes()[:BIN_READ]) if path.exists() else 0.0,
            "string_count": float(len(meta["text_snippet"])),
            "spec_char_ratio": 0.0,
            "import_count": 0.0,
            "macro_score": 0.0,
        })
    except Exception:
        _ai_raw2, _ai_sev_hint = 0.0, "low"

    nlp_res = {"lang": "unknown", "nlp_score": 0.0, "suspicious_sentences": [], "email_header": {"risk": 0.0, "flags": []}}
    txt = meta.get("text_snippet") or ""
    if txt.strip():
        try:
            nlp_res = _nlp_analyze(txt)
        except Exception as e:
            log.debug(f"NLP error on {path}: {e}")

    vt_res = {"detected_by": 0, "vendors": [], "permalink": None, "verdict": None, "tags": []}
    if vt_client and meta["sha256"]:
        try:
            look = vt_client.lookup_hash(meta["sha256"])
            if look.get("status") == "ok":
                vt_res.update({
                    "detected_by": int(look.get("detected_by", 0)),
                    "vendors": look.get("vendors", []),
                    "permalink": look.get("permalink"),
                    "verdict": look.get("verdict"),
                    "tags": look.get("tags", []),
                })
        except Exception as e:
            log.debug(f"VT lookup error on {path}: {e}")

    fused, severity = fuse_threat_score(ai_is_anom, ai_raw, sig_res["score"], vt_res["detected_by"], nlp_res["nlp_score"])
    category = vote_category(sig_res["votes"], vt_res["tags"], nlp_res["nlp_score"])
    if (nlp_res.get("nlp_score", 0.0) >= 0.70) and ("PHISH" in " ".join(sig_res["hits"]) or nlp_res.get("suspicious_sentences")):
        category = "phishing"

    return {
        "path": meta["path"],
        "name": meta["name"],
        "ext": meta["ext"],
        "mime": meta["mime"],
        "size": meta["size"],
        "sha256": meta["sha256"],
        "ai": {"is_anomaly": bool(ai_is_anom), "raw": ai_raw, "alt_raw": _ai_raw2},
        "signature": {"hits": sig_res["hits"], "score": sig_res["score"], "votes": sig_res["votes"]},
        "nlp": {
            "lang": nlp_res.get("lang", "unknown"),
            "score": nlp_res.get("nlp_score", 0.0),
            "suspicious_sentences": nlp_res.get("suspicious_sentences", []),
            "email_header": nlp_res.get("email_header", {"risk": 0.0, "flags": []}),
        },
        "virustotal": vt_res,
        "threat_score": fused,
        "severity": severity,
        "category": category,
    }

# ===== schemas =====
class ScanResponse(BaseModel):
    status: str
    session: str
    scanned: int
    dangerous: int
    summary: Dict[str, Any]
    files: List[Dict[str, Any]]

# ==== SSE + Watch + AutoScan ====
EVENTS_Q: "queue.Queue[str]" = queue.Queue(maxsize=2000)
JOBS_Q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=2000)

# DB init
EDB = EventsDB(PROJ / "data" / "events.db")

def sse_put(obj_or_str: Union[str, Dict[str, Any]]) -> None:
    """Terima dict ATAU string JSON dari watcher/worker, simpan ke DB, teruskan ke SSE queue."""
    try:
        obj: Dict[str, Any]
        if isinstance(obj_or_str, str):
            try:
                obj = json.loads(obj_or_str)
            except Exception:
                obj = {"type": "raw", "payload": obj_or_str, "ts": time.time()}
        else:
            obj = obj_or_str

        # catat DB (best effort)
        try:
            EDB.insert_event(obj)
            if isinstance(obj.get("agent"), dict):
                EDB.upsert_device(obj["agent"])
        except Exception:
            pass

        EVENTS_Q.put_nowait(json.dumps(obj))
    except Exception:
        pass

# FileWatcher butuh publisher berbasis callable
WATCHER = FileWatcher(
    events_put=lambda s: sse_put(s),                  # watcher kirim string JSON
    jobs_put=lambda j: JOBS_Q.put_nowait(j),          # enqueue job dict
    debounce=1.0,
)

# VT client optional
VT_CLIENT = VirusTotalClient(VT_API_KEY) if (VT_API_KEY and VirusTotalClient) else None

class AutoScanWorker:
    def __init__(self, jobs_q: "queue.Queue[Dict[str, Any]]", publisher: callable) -> None:
        self.jobs_q = jobs_q
        self.publisher = publisher
        self._thr: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._loop, name="warnetix-autoscan", daemon=True)
        self._thr.start()

    def stop(self) -> None:
        self._stop.set()

    def _file_stable(self, p: Path, tries: int = 3, wait_s: float = 0.8) -> bool:
        try:
            last = -1
            for _ in range(tries):
                cur = p.stat().st_size
                if cur == last:
                    return True
                last = cur
                time.sleep(wait_s)
            return True
        except Exception:
            return False

    # ==== Action Policy ====
    def _apply_policy(self, p: Path, res: Dict[str, Any]) -> Dict[str, Any]:
        try:
            sev = str(res.get("severity", "low")).lower()
            if not _sev_ge(sev, POLICY_MIN_SEVERITY) or POLICY_MODE == "simulate":
                return {"action": "simulate"}
            if POLICY_MODE == "rename":
                newp = p.with_suffix(p.suffix + ".blocked")
                i = 1
                while newp.exists():
                    newp = p.with_suffix(p.suffix + f".blocked.{i}")
                    i += 1
                p.rename(newp)
                return {"action": "rename", "target": str(newp)}
            if POLICY_MODE == "quarantine":
                dest = QUARANTINE_DIR / p.name
                i = 1
                while dest.exists():
                    dest = QUARANTINE_DIR / f"{p.stem}_{i}{p.suffix}"
                    i += 1
                shutil.move(str(p), str(dest))
                return {"action": "quarantine", "target": str(dest)}
        except Exception as e:
            return {"action": "error", "error": str(e)}
        return {"action": "none"}

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.jobs_q.get(timeout=1)
            except Exception:
                continue
            if not isinstance(job, dict) or job.get("type") != "scan_file":
                continue
            p = Path(job.get("path", ""))
            if not p.exists() or not p.is_file():
                continue
            time.sleep(1.0)
            if not self._file_stable(p):
                continue
            try:
                res = scan_single_file(p, VT_CLIENT)
                policy = self._apply_policy(p, res)
                self.publisher({"type": "scan_result", "ts": time.time(), "result": res, "policy": policy})
            except Exception as e:
                self.publisher({"type": "scan_error", "ts": time.time(), "path": str(p), "error": str(e)})

AUTOSCAN = AutoScanWorker(JOBS_Q, sse_put)

@app.on_event("startup")
def _on_start() -> None:
    AUTOSCAN.start()
    log.info("AutoScan worker started.")

@app.on_event("shutdown")
def _on_stop() -> None:
    AUTOSCAN.stop()
    log.info("AutoScan worker stopped.")

async def sse_event_generator():
    last_hb = time.time()
    loop = asyncio.get_event_loop()
    while True:
        try:
            msg = await loop.run_in_executor(None, EVENTS_Q.get, True, 5)
            yield f"data: {msg}\n\n"
        except Exception:
            pass
        if time.time() - last_hb > 20:
            yield "event: ping\ndata: {}\n\n"
            last_hb = time.time()

# ===== routes =====
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": ANOM.available(),
        "model_path": str(ANOM.path) if ANOM.path else None,
        "vt_enabled": bool(VT_CLIENT),
        "signatures": {"ransomware": True, "malware": True, "phishing": True},
        "watch": WATCHER.status(),
        "autoscan": {"running": True},
        "policy": {"mode": POLICY_MODE, "min_severity": POLICY_MIN_SEVERITY},
        "time": datetime.utcnow().isoformat() + "Z",
    }

@app.get("/events/stream")
async def events_stream():
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive"}
    return StreamingResponse(sse_event_generator(), media_type="text/event-stream", headers=headers)

@app.get("/events/recent")
def events_recent(
    limit: int = Query(200, ge=1, le=2000),
    since: float | None = Query(None),
    typ: str | None = Query(None)
):
    try:
        rows = EDB.recent_events(limit=limit, since=since, typ=typ)
        return {"status": "ok", "items": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

@app.get("/devices")
def list_devices():
    try:
        return {"status": "ok", "items": EDB.list_devices()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

@app.get("/stats/timeseries")
def stats_timeseries(
    start: float = Query(..., description="epoch seconds"),
    end: float = Query(..., description="epoch seconds"),
    bucket: str = Query("hour", regex="^(min|hour|day)$")
):
    size = {"min": 60, "hour": 3600, "day": 86400}[bucket]
    if end <= start:
        raise HTTPException(status_code=400, detail="end must be > start")
    try:
        data = EDB.timeseries(start, end, bucket_seconds=size)
        return {"status": "ok", "bucket_seconds": size, "series": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

# ==== endpoint untuk C++ agent push ====
class AgentFastEvent(BaseModel):
    kind: str = "agent_fast"
    ts: Optional[float] = None
    path: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None
    agent: Optional[Dict[str, Any]] = None
    enqueue_deep_scan: Optional[bool] = True

@app.post("/events/push")
async def events_push(
    ev: AgentFastEvent,
    x_agent_token: Optional[str] = Header(default=None)
):
    # Auth sederhana berbasis shared secret (opsional)
    if AGENT_TOKEN and (x_agent_token != AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid X-Agent-Token")

    ts = ev.ts if ev.ts is not None else time.time()

    # ---- OFFLINE SIGNATURE LOOKUP (MBZ/Kaggle) — sebelum publish/insert_event
    sha256 = ""
    md5 = ""
    meta_in = ev.meta or {}
    if isinstance(meta_in.get("sha256"), str):
        sha256 = meta_in.get("sha256", "").lower()

    p = Path(ev.path) if ev.path else None
    if not sha256 and p and p.exists() and p.is_file():
        try:
            md5 = _md5_of_file(p)
        except Exception:
            md5 = ""

    sig_hit = None
    conn = _get_sig_conn()
    if conn:
        try:
            sig_hit = signature_lookup(conn, sha256=sha256 or None, md5=md5 or None)
        except Exception:
            sig_hit = None

    sev_override = None
    meta_out = dict(meta_in)
    if sig_hit:
        order = ["low", "medium", "high", "critical"]
        sev_override = max(meta_out.get("severity") or "low", sig_hit["severity"], key=order.index)
        sh = meta_out.setdefault("signature_hits", [])
        sh.append({"provider": sig_hit["source"], "family": sig_hit.get("family"), "type": sig_hit.get("type"), "by": "hash"})
        meta_out["signature_offline"] = True

        # SSE khusus signature_hit (biar UI bisa kasih badge)
        sse_put({
            "type": "signature_hit",
            "ts": ts,
            "file": str(ev.path),
            "sha256": sha256 or None,
            "md5": md5 or None,
            "family": sig_hit.get("family"),
            "severity": sev_override,
            "source": sig_hit.get("source", "offline_db"),
            "agent": ev.agent or {}
        })

    # catat device (best effort)
    if ev.agent:
        try:
            EDB.upsert_device(ev.agent)
        except Exception:
            pass

    # publish fast_event (dengan meta yang sudah dilengkapi)
    payload = {
        "type": "fast_event",
        "ts": ts,
        "path": ev.path,
        "meta": meta_out,
        "policy": ev.policy or {},
        "agent": ev.agent or {},
        "source": "agent",
    }
    if sev_override:
        payload["severity"] = sev_override
    sse_put(payload)

    # Enqueue deep scan jika diminta & path valid
    enq = False
    if ev.enqueue_deep_scan and ev.path:
        p = Path(ev.path)
        if p.exists() and p.is_file():
            try:
                JOBS_Q.put_nowait({"type": "scan_file", "path": str(p), "ts": ts})
                enq = True
            except Exception:
                enq = False

    return {"status": "ok", "published": True, "enqueued_deep_scan": enq}

# ==== upload/scan endpoints ====
class _ScanFileList(BaseModel):
    # pembantu untuk schema response
    status: str
    session: str
    scanned: int
    dangerous: int
    summary: Dict[str, Any]
    files: List[Dict[str, Any]]

@app.post("/scan-file", response_model=_ScanFileList)
async def scan_file_endpoint(
    files: List[UploadFile] = File(...),
    vt_upload: bool = Form(False),
):
    """
    Upload beberapa file, lakukan scanning gabungan (Signature+AI+VT+NLP),
    dan kembalikan ringkasan + detail per file. (Dengan wiring ke offline signatures & policy)
    """
    session_id = datetime.utcnow().strftime("session_%Y%m%d_%H%M%S")
    tmpdir = OUTPUT_DIR / session_id
    tmpdir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    dangerous = 0

    for f in files:
        name = f.filename or "file.bin"
        dest = tmpdir / name
        # simpan ke disk
        with dest.open("wb") as out:
            while True:
                chunk = await f.read(1_048_576)
                if not chunk: break
                out.write(chunk)

        # scan single
        res = scan_single_file(dest, VT_CLIENT)

        # ---- offline signature (MD5/sha256) untuk dataset MBZ/Kaggle
        try:
            md5 = _md5_of_file(dest)
        except Exception:
            md5 = ""
        sig_hit = None
        conn = _get_sig_conn()
        if conn:
            try:
                sig_hit = signature_lookup(conn, sha256=res.get("sha256"), md5=md5 or None)
            except Exception:
                sig_hit = None
        if sig_hit:
            order = ["low","medium","high","critical"]
            sev_new = max(res.get("severity") or "low", sig_hit["severity"], key=order.index)
            res["severity"] = sev_new
            meta = res.setdefault("meta", {})
            hits = meta.setdefault("signature_hits", [])
            hits.append({"provider": sig_hit["source"], "family": sig_hit.get("family"), "type": sig_hit.get("type"), "by": "hash"})
            # SSE badge
            sse_put({"type":"signature_hit","ts":time.time(),"file":name,"sha256":res.get("sha256"),"md5":md5,
                     "family":sig_hit.get("family"),"severity":sev_new,"source":sig_hit.get("source","offline_db")})

        # kebijakan tindakan otomatis (rename/quarantine)
        policy = AutoScanWorker(JOBS_Q, sse_put)._apply_policy(dest, res)
        res["policy"] = policy

        if str(res.get("severity")).lower() in {"high", "critical"}:
            dangerous += 1
        results.append(res)

    # ringkas
    summary = {
        "count": len(results),
        "dangerous": dangerous,
        "high": sum(1 for r in results if str(r.get("severity")).lower() == "high"),
        "critical": sum(1 for r in results if str(r.get("severity")).lower() == "critical"),
    }

    # simpan CSV ringkasan
    try:
        import csv
        csv_path = tmpdir / "summary.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["name","size","ext","sha256","severity","category","threat_score","vt_detected_by"])
            for r in results:
                w.writerow([
                    r.get("name"), r.get("size"), r.get("ext"), r.get("sha256"),
                    r.get("severity"), r.get("category"),
                    r.get("threat_score", 0.0), r.get("virustotal",{}).get("detected_by",0)
                ])
    except Exception:
        pass

    return {
        "status": "ok",
        "session": session_id,
        "scanned": len(results),
        "dangerous": dangerous,
        "summary": summary,
        "files": results,
    }

## --- build_threat_summary (kalau belum ada) ---
try:
    build_threat_summary  # type: ignore[name-defined]
except NameError:
    def build_threat_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Ringkas status ancaman dari list hasil scan.
        Menghitung: critical/high/medium/low/clean/error + total.
        """
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0, "error": 0, "total": len(items)}
        for it in items or []:
            # ambil field status/severity seandainya salah satunya ada
            sev = (it.get("status") or it.get("severity") or "").lower()
            if sev in out:
                out[sev] += 1
            elif sev in ("malicious",):
                out["high"] += 1
            elif sev in ("suspicious",):
                out["medium"] += 1
            elif sev in ("ok", "benign"):
                out["clean"] += 1
            elif sev == "error":
                out["error"] += 1
            else:
                # fallback: pakai threat_score jika ada
                ts = it.get("threat_score")
                if isinstance(ts, (int, float)):
                    if ts >= 80:
                        out["high"] += 1
                    elif ts >= 50:
                        out["medium"] += 1
                    elif ts > 0:
                        out["low"] += 1
                    else:
                        out["clean"] += 1
                else:
                    out["low"] += 1
        return out

# --- WarnetixScanner ---
try:
    WarnetixScanner  # type: ignore[name-defined]
except NameError:
    class WarnetixScanner:
        """
        Shim kelas sederhana supaya app.py bisa memanggil .scan_path(path, opts).
        Di dalamnya kita panggil fungsi yang sudah ada: scan_file_sync(...).
        """
        def __init__(self, logger=None):
            self.logger = logger

        def scan_path(self, path: str, opts: Dict[str, Any] | None = None) -> Dict[str, Any]:
            opts = opts or {}
            # flag VT dari opsi
            vt_enabled = bool(opts.get("vt_enabled", True))
            wait_for_vt = bool(opts.get("vt_upload_if_unknown", False)) if vt_enabled else False

            # Pastikan DB core siap (fungsi2 ini sudah dipakai di modul ini)
            try:
                from .db import migrate
                migrate()  # idempotent
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"DB core migrate warning: {e}")

            # Panggil fungsi scan yang sudah ada di modul ini
            if "scan_file_sync" not in globals():
                raise RuntimeError("scanner_api.shim: fungsi scan_file_sync tidak ditemukan di backend/scanner_api.py")
            result = globals()["scan_file_sync"](path, wait_for_vt=wait_for_vt)

            # Pastikan ada beberapa field umum biar konsisten dengan app.py
            result.setdefault("filename", result.get("filename") or (path.split("/")[-1] if "/" in path else path.split("\\")[-1]))
            result.setdefault("status", result.get("status") or result.get("severity") or "low")
            if "filesize" not in result and os.path.exists(path):
                try:
                    result["filesize"] = os.path.getsize(path)
                except Exception:
                    pass
            if "id" not in result:
                # fallback id
                import hashlib
                h = hashlib.sha256(result.get("sha256", "").encode() or path.encode())
                result["id"] = h.hexdigest()[:16]
            return result

# Ekspor simbol agar bisa di-import oleh app.py
__all__ = list(set(list(globals().get("__all__", [])) + ["WarnetixScanner", "build_threat_summary"]))
