# backend/scanner_core/scanner_core.py
import os, time, json, logging, sqlite3, hashlib, math
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional, Dict, Any
import mimetypes
import os, json, uuid
try:
    import boto3  # type: ignore
except Exception:
    boto3 = None


# try optional imports
try:
    import magic as filemagic
except Exception:
    filemagic = None

# for anomaly model
import pickle
import numpy as np

LOG = logging.getLogger("warnetix.scanner")

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    probs = [float(data.count(bytes([i]))) / len(data) for i in range(256)]
    ent = -sum(p * math.log2(p) for p in probs if p > 0)
    return ent

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

class WarnetixScanner:
    def __init__(self,
                 signature_path: Optional[str] = None,
                 anomaly_model_path: Optional[str] = None,
                 vt_client = None,
                 quarantine_dir: str = "data/quarantine",
                 output_db: str = "data/output/scanner_results.db",
                 simulation: bool = True,
                 max_workers: int = 4):
        self.signature_path = signature_path
        self.anomaly_model_path = anomaly_model_path
        self.vt_client = vt_client
        self.quarantine_dir = Path(quarantine_dir)
        self.output_db = output_db
        self.simulation = simulation
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.jobs = {}  # job_id -> status
        self._load_signatures()
        self._load_model()
        self._init_db()
        LOG.info("WarnetixScanner initialized. simulation=%s", self.simulation)

    # -------------------------
    # persistence
    # -------------------------
    def _init_db(self):
        db = sqlite3.connect(self.output_db)
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                sha256 TEXT,
                timestamp TEXT,
                threat_score REAL,
                status TEXT,
                detected_by TEXT,
                details TEXT
            )
        """)
        db.commit()
        db.close()

    # -------------------------
    # signatures and model
    # -------------------------
    def _load_signatures(self):
        self.signatures = {}
        if self.signature_path and os.path.exists(self.signature_path):
            try:
                with open(self.signature_path, "r", encoding="utf-8") as f:
                    self.signatures = json.load(f)
                LOG.info("Loaded signatures from %s", self.signature_path)
            except Exception:
                LOG.exception("Failed load signatures at %s", self.signature_path)
        else:
            LOG.warning("Signatures file not found at %s", self.signature_path)

    def _load_model(self):
        self.anom_artifact = None
        if self.anomaly_model_path and os.path.exists(self.anomaly_model_path):
            try:
                with open(self.anomaly_model_path, "rb") as f:
                    self.anom_artifact = pickle.load(f)
                LOG.info("Loaded anomaly model from %s", self.anomaly_model_path)
            except Exception:
                LOG.exception("Failed to load anomaly model at %s", self.anomaly_model_path)
        else:
            LOG.warning("Anomaly model not found at %s", self.anomaly_model_path)

    # -------------------------
    # public job control
    # -------------------------
    def submit_scan_path(self, path: str) -> str:
        job_id = f"job-{int(time.time()*1000)}"
        self.jobs[job_id] = {"status": "queued", "path": path, "started": None, "finished": None}
        self.executor.submit(self._run_scan_job, job_id, path)
        return job_id

    def get_job_status(self, job_id: str):
        return self.jobs.get(job_id)

    def read_recent(self, limit=50):
        conn = sqlite3.connect(self.output_db)
        cur = conn.cursor()
        cur.execute("SELECT file_path, sha256, timestamp, threat_score, status, detected_by FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                "file_path": r[0], "sha256": r[1], "timestamp": r[2],
                "threat_score": r[3], "status": r[4], "detected_by": json.loads(r[5]) if r[5] else []
            })
        return out

    def shutdown(self):
        LOG.info("Shutting down scanner executor...")
        self.executor.shutdown(wait=True)

    # -------------------------
    # core job
    # -------------------------
    def _run_scan_job(self, job_id, path):
        self.jobs[job_id]["status"] = "running"
        self.jobs[job_id]["started"] = datetime.utcnow().isoformat()
        try:
            p = Path(path)
            if p.is_dir():
                files = list(p.rglob("*"))
                files = [str(x) for x in files if x.is_file()]
            elif p.exists():
                files = [str(p)]
            else:
                LOG.warning("Start path does not exist: %s", path)
                self.jobs[job_id].update({"status": "finished", "finished": datetime.utcnow().isoformat()})
                return

            total = 0
            for fpath in files:
                try:
                    if not Path(fpath).is_file(): continue
                    total += 1
                    LOG.info("[SCAN] Processing: %s", fpath)
                    res = self._scan_file(fpath)
                    # store result
                    self._save_scan_result(res)
                    LOG.info("[SCAN RESULT] %s -> %s (score=%0.2f)", fpath, res["status"], res["threat_score"])
                    # schedule vt checks if needed
                    if self.vt_client and res.get("vt_needed"):
                        future = self.vt_client.submit_file_async(fpath)
                        # attach callback to update DB when vt complete
                        future.add_done_callback(lambda fut, r=res: self._vt_callback(fut, r))
                except Exception:
                    LOG.exception("Error scanning file %s", fpath)
            LOG.info("Scan job %s complete. Total files scanned: %s", job_id, total)
        except Exception:
            LOG.exception("Job runner error for %s", job_id)
        finally:
            self.jobs[job_id].update({"status": "finished", "finished": datetime.utcnow().isoformat()})

    # -------------------------
    # per-file scanning
    # -------------------------
    def _scan_file(self, fpath: str) -> Dict[str, Any]:
        """Return dict with keys: file_path, sha256, timestamp, threat_score, status, detected_by, details, vt_needed"""
        now = datetime.utcnow().isoformat()
        sha = sha256_of_file(fpath)
        size_kb = Path(fpath).stat().st_size / 1024.0
        # read small head for content-based checks
        head = b""
        try:
            with open(fpath, "rb") as fh:
                head = fh.read(32768)
        except Exception:
            LOG.exception("Unable to read file for analysis: %s", fpath)

        ent = entropy(head)
        mime = None
        if filemagic:
            try:
                mime = filemagic.from_file(fpath)
            except Exception:
                mime = None
        else:
            mime, _ = mimetypes.guess_type(fpath)

        # signature checks
        detected_by = []
        status = "clean"
        score = 0.0
        vt_needed = True  # default: ask VT if unknown

        # 1) hash match
        sig_hashes = self.signatures.get("hashes", [])
        if sha in sig_hashes:
            LOG.warning("Signature hash match for %s", fpath)
            detected_by.append("signature:hash")
            status = "critical"
            score += 80

        # 2) keyword match in filename or head bytes
        keywords = self.signatures.get("keywords", [])
        fn = Path(fpath).name.lower()
        for kw in keywords:
            if kw.lower() in fn:
                detected_by.append(f"signature:keyword:{kw}")
                score += 30
                if "encrypt" in kw or "ransom" in kw:
                    status = "critical"
        for kw in keywords:
            try:
                if head and kw.encode('utf-8') in head:
                    detected_by.append(f"signature:content_kw:{kw}")
                    score += 25
            except Exception:
                pass

        # 3) filename patterns / suspicious extensions
        for pat in self.signatures.get("filename_patterns", []):
            if Path(fpath).match(pat):
                detected_by.append(f"signature:pattern:{pat}")
                score += 25
        for ext in self.signatures.get("suspicious_extensions", []):
            if fn.endswith(ext):
                detected_by.append(f"signature:ext:{ext}")
                score += 25

        # 4) entropy heuristic
        ent_threshold = float(self.signatures.get("entropy_threshold", 7.5))
        if ent >= ent_threshold:
            detected_by.append("heuristic:high_entropy")
            score += 35
            if score > 50:
                status = "high"

        # 5) anomaly model (if available)
        anom_flag = False
        if self.anom_artifact:
            try:
                feat_names = self.anom_artifact["features"]
                v = np.array([[ent, size_kb] + [1 if fpath.lower().endswith(x) else 0 for x in []]])  # fallback
                # build vector in order expected
                vec = []
                for fname in feat_names:
                    if fname == "entropy":
                        vec.append(ent)
                    elif fname == "filesize_kb":
                        vec.append(size_kb)
                    elif fname == "is_executable":
                        vec.append(1 if fn.endswith((".exe", ".dll", ".bin")) else 0)
                    elif fname == "keyword_flag":
                        vec.append(1 if any(kw in fn for kw in keywords) else 0)
                    else:
                        vec.append(0)
                arr = np.array(vec).reshape(1, -1)
                mean = np.array(self.anom_artifact.get("scaler_mean", np.zeros(arr.shape[1])))
                scale = np.array(self.anom_artifact.get("scaler_scale", np.ones(arr.shape[1])))
                arr_s = (arr - mean) / scale
                model = self.anom_artifact["model"]
                pred = model.predict(arr_s)
                # IsolationForest predict -> -1 anomaly, 1 normal
                if pred[0] == -1:
                    anom_flag = True
                    detected_by.append("anomaly:iforest")
                    score += 40
                    if score > 60:
                        status = "high"
            except Exception:
                LOG.exception("Anomaly model predict error")

        # 6) compute base threat score clamp
        threat_score = min(100.0, float(score))

        # 7) decide status labels
        if "critical" in status or threat_score >= 90:
            status = "critical"
        elif threat_score >= 70:
            status = "high"
        elif threat_score >= 30:
            status = "medium"
        elif threat_score > 0:
            status = "low"
        else:
            status = "clean"

        # 8) if suspicious and vt client available, we should query VT (worker)
        if status in ("critical", "high", "medium") and self.vt_client:
            vt_needed = True
        else:
            vt_needed = False

        detail = {
            "file_path": fpath,
            "sha256": sha,
            "timestamp": now,
            "entropy": ent,
            "filesize_kb": size_kb,
            "mime": mime,
            "detected_by": detected_by,
            "anomaly_flag": anom_flag
        }

        # handle quarantine simulation (default no move)
        if status in ("critical", "high"):
            if self.simulation:
                LOG.info("SIMULATION: would quarantine %s (status=%s score=%s)", fpath, status, threat_score)
            else:
                try:
                    self._quarantine_file(fpath)
                except Exception:
                    LOG.exception("Failed to quarantine %s", fpath)

        return {
            "file_path": fpath,
            "sha256": sha,
            "timestamp": now,
            "threat_score": threat_score,
            "status": status,
            "detected_by": detected_by,
            "details": detail,
            "vt_needed": vt_needed
        }

    def _vt_callback(self, future, res):
        """Called when vt_client future finishes. Update DB with VT positives and recompute threat score"""
        try:
            vt_out = future.result()
            LOG.info("VT callback result: %s", vt_out.get("status") if isinstance(vt_out, dict) else str(type(vt_out)))
            # recompute threat score: base + vt positives weight
            positives = 0
            if isinstance(vt_out, dict):
                positives = int(vt_out.get("positives", 0) or 0)
            # map positives to score
            add = min(40, positives * 3)  # each positive ~3% up to 40%
            # load DB entry and update
            conn = sqlite3.connect(self.output_db)
            cur = conn.cursor()
            cur.execute("SELECT id, threat_score, detected_by FROM scans WHERE sha256=?", (res["sha256"],))
            row = cur.fetchone()
            if row:
                id_ = row[0]
                base_score = float(row[1] or 0.0)
                new_score = min(100.0, base_score + add)
                detected_by = json.loads(row[2]) if row[2] else []
                detected_by.append({"vt_positives": positives})
                cur.execute("UPDATE scans SET threat_score=?, detected_by=? WHERE id=?", (new_score, json.dumps(detected_by), id_))
                conn.commit()
            conn.close()
            # cache in VT cache occurs inside vt_client
        except Exception:
            LOG.exception("VT callback error")

    def _save_scan_result(self, res: Dict[str, Any]):
        conn = sqlite3.connect(self.output_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scans(file_path, sha256, timestamp, threat_score, status, detected_by, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (res["file_path"], res["sha256"], res["timestamp"], res["threat_score"], res["status"], json.dumps(res["detected_by"]), json.dumps(res["details"])))
        conn.commit()
        conn.close()

    # -------------------------
    # quarantine (safe)
    # -------------------------
    def _quarantine_file(self, fpath):
        """Move file to quarantine directory (dangerous). Only called when simulation=False."""
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        src = Path(fpath)
        dest = self.quarantine_dir / (src.name + f".quarantine.{int(time.time())}")
        LOG.info("Quarantining %s -> %s", src, dest)
        src.rename(dest)

        return dest
    