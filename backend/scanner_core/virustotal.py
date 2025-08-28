#!/usr/bin/env python3
# backend/scanner_core/virustotal.py
"""
Warnetix - VirusTotal integration (robust + verbose)
Features:
 - Read API key from .env
 - SHA256 hashing
 - Local SQLite cache to avoid repeated lookups
 - Rate limiter (requests/minute) with conservative defaults
 - Safe retries with exponential backoff (network/server errors & 429)
 - Auto upload if hash not found (small files flow; large-file flow limited)
 - Poll analysis results until completion or timeout
 - Rich, human-readable prints for every major step (for debugging/demo)
 - compute_threat_score() to normalize VT results into 0-100 scale
"""

import os
import time
import json
import hashlib
import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import requests
from dotenv import load_dotenv
from tqdm import tqdm

# ---------------------------
# Configuration / Constants
# ---------------------------
load_dotenv()  # load .env from current working directory
API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_DB = Path(__file__).parent.parent / "vt_cache.db"  # backend/vt_cache.db
MAX_REQUESTS_PER_MINUTE = int(os.getenv("VT_MAX_RPM", "4"))  # conservative default
POLL_INTERVAL = int(os.getenv("VT_POLL_INTERVAL", "5"))  # seconds
ANALYSIS_TIMEOUT = int(os.getenv("VT_ANALYSIS_TIMEOUT", "300"))  # seconds

# ---------------------------
# Basic validations
# ---------------------------
if not API_KEY:
    raise RuntimeError(
        "VIRUSTOTAL_API_KEY tidak ditemukan di .env. Tambahkan: VIRUSTOTAL_API_KEY=your_key"
    )

# Set up logging (also print-friendly)
logger = logging.getLogger("warnetix.vt")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s"))
    logger.addHandler(ch)

HEADERS = {"x-apikey": API_KEY}

# ---------------------------
# Utility: SQLite Cache
# ---------------------------
class VTCache:
    def __init__(self, path: Path):
        self.path = str(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_table()
        logger.info(f"Cache DB initialized at {self.path}")

    def _init_table(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
              key TEXT PRIMARY KEY,
              ts INTEGER,
              payload TEXT
            )
            """
        )
        self.conn.commit()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT ts, payload FROM vt_cache WHERE key = ?", (key,))
        row = cur.fetchone()
        if not row:
            return None
        ts, payload = row
        try:
            return {"ts": ts, "payload": json.loads(payload)}
        except Exception:
            return None

    def set(self, key: str, payload: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute(
            "REPLACE INTO vt_cache (key, ts, payload) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(payload)),
        )
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ---------------------------
# Utility: Rate limiter
# ---------------------------
class RateLimiter:
    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.timestamps = []

    def wait_if_needed(self):
        now = time.time()
        # keep only timestamps within last 60s
        self.timestamps = [t for t in self.timestamps if now - t < 60]
        if len(self.timestamps) >= self.max:
            earliest = self.timestamps[0]
            sleep_for = 60 - (now - earliest) + 0.1
            logger.info(f"RateLimiter: reached {self.max}/min. Sleeping {sleep_for:.1f}s")
            time.sleep(sleep_for)
        self.timestamps.append(time.time())


# ---------------------------
# Main client
# ---------------------------
class VirusTotalClient:
    def __init__(
        self,
        base_url: str = BASE_URL,
        cache_db: Path = CACHE_DB,
        max_rpm: int = MAX_REQUESTS_PER_MINUTE,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.cache = VTCache(cache_db)
        self.rate_limiter = RateLimiter(max_rpm)
        logger.info(
            "VirusTotalClient initialized with base_url=%s max_rpm=%d cache=%s",
            self.base_url,
            max_rpm,
            cache_db,
        )

    # ---------- helpers ----------
    @staticmethod
    def sha256_of_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        digest = h.hexdigest()
        logger.debug(f"SHA256({path}) = {digest}")
        return digest

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        # rate-limit
        self.rate_limiter.wait_if_needed()

        backoff = 1.0
        for attempt in range(6):
            try:
                resp = self.session.request(method, url, headers=HEADERS, timeout=60, **kwargs)
            except requests.RequestException as e:
                logger.warning(f"Network error (attempt {attempt+1}): {e}. Backing off {backoff}s")
                time.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code in (200, 201):
                try:
                    return resp.json()
                except ValueError:
                    return {"raw_text": resp.text}
            if resp.status_code == 204:
                return {}
            if resp.status_code == 404:
                # not found -> return raw
                return {"status_code": 404, "raw_text": resp.text}
            if resp.status_code == 429:
                # rate-limited by server — honor Retry-After if present
                ra = resp.headers.get("Retry-After")
                wait = int(ra) if ra and ra.isdigit() else backoff
                logger.info(f"Server rate-limited (429). Sleeping {wait}s (attempt {attempt+1})")
                time.sleep(wait)
                backoff *= 2
                continue
            if 500 <= resp.status_code < 600:
                logger.warning(f"Server error {resp.status_code}. Backing off {backoff}s (attempt {attempt+1})")
                time.sleep(backoff)
                backoff *= 2
                continue
            # other client error
            try:
                return resp.json()
            except Exception:
                raise RuntimeError(f"Unhandled VT response {resp.status_code}: {resp.text}")

        raise RuntimeError("Max retries exceeded for VT request")

    # ---------- file/hash ----------
    def get_file_report(self, sha256: str, use_cache: bool = True) -> Dict[str, Any]:
        key = f"file_report:{sha256}"
        if use_cache:
            cached = self.cache.get(key)
            if cached:
                logger.info(f"Cache HIT for {sha256}")
                return cached["payload"]
        logger.info(f"Cache MISS for {sha256} -> querying VirusTotal /files/{sha256}")
        res = self._request("GET", f"/files/{sha256}")
        # VT returns 404 as JSON? we handle via _request
        self.cache.set(key, res)
        return res

    def upload_file(self, path: str, use_cache: bool = True) -> Dict[str, Any]:
        path = str(path)
        sha256 = self.sha256_of_file(path)
        # If already has report, no need to upload
        try:
            existing = self.get_file_report(sha256, use_cache=use_cache)
            # If VT returned data with attributes, consider found
            if existing and existing.get("data"):
                logger.info("Found existing VT report; skipping upload.")
                return {"from_cache": True, "report": existing}
        except Exception:
            # continue to upload
            pass

        filesize_mb = Path(path).stat().st_size / (1024 * 1024)
        logger.info(f"Uploading file {path} (size={filesize_mb:.2f} MB) to VirusTotal")
        # small file flow (<= 32MB)
        if filesize_mb <= 32:
            with open(path, "rb") as fh:
                files = {"file": (Path(path).name, fh)}
                try:
                    resp = self._request("POST", "/files", files=files)
                except Exception as e:
                    logger.error(f"Upload error: {e}")
                    return {"status": "error", "error": str(e)}
            # resp should contain analysis id under data.id or similar
            logger.info("Upload successful (response cached).")
            return {"status": "uploaded", "response": resp}
        else:
            # Large file flow - request upload_url endpoint (if available)
            logger.info("Large file upload requested (>32MB). Requesting upload_url flow.")
            try:
                res = self._request("POST", "/files/upload_url")
            except Exception as e:
                logger.error("Failed to get upload_url: %s", e)
                return {"status": "error", "error": str(e)}
            # extract upload_url
            upload_url = res.get("data", {}).get("attributes", {}).get("upload_url") or res.get("upload_url")
            if not upload_url:
                logger.error("upload_url not returned by VT for large file flow.")
                return {"status": "error", "error": "no_upload_url"}
            # PUT file to upload_url
            with open(path, "rb") as fh:
                put_resp = requests.put(upload_url, data=fh)
            if put_resp.status_code not in (200, 201):
                logger.error("Large file PUT failed: %s - %s", put_resp.status_code, put_resp.text)
                return {"status": "error", "error": "large_put_failed", "code": put_resp.status_code}
            logger.info("Large file uploaded. Response: %s", put_resp.status_code)
            # try to parse id
            try:
                parsed = put_resp.json()
            except Exception:
                parsed = {"raw_text": put_resp.text}
            return {"status": "uploaded_large", "response": parsed}

    # ---------- analysis polling ----------
    def poll_analysis(self, analysis_id: str, timeout: int = ANALYSIS_TIMEOUT, poll_interval: int = POLL_INTERVAL) -> Dict[str, Any]:
        logger.info("Polling analysis id=%s (timeout=%ds, interval=%ds)", analysis_id, timeout, poll_interval)
        start = time.time()
        endpoint = f"/analyses/{analysis_id}"
        while time.time() - start < timeout:
            try:
                res = self._request("GET", endpoint)
            except Exception as e:
                logger.warning("Poll request error: %s - retrying", e)
                time.sleep(poll_interval)
                continue
            # check completion
            status = res.get("data", {}).get("attributes", {}).get("status")
            logger.debug("Analysis status=%s", status)
            if status == "completed":
                logger.info("Analysis completed for %s", analysis_id)
                return {"status": "completed", "data": res}
            logger.info("Analysis not ready yet (status=%s). Waiting %ds...", status, poll_interval)
            time.sleep(poll_interval)
        logger.warning("Polling timed out after %ds", timeout)
        return {"status": "timeout", "analysis_id": analysis_id}

    # ---------- helper: summarize ----------
    @staticmethod
    def summarize_vt_data(vt_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return normalized summary:
        - positives (malicious)
        - suspicious
        - undetected
        - detection_ratio
        - list of engines that flagged
        """
        try:
            attr = vt_json["data"]["attributes"]
            stats = attr.get("last_analysis_stats", {})
            results = attr.get("last_analysis_results", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            undetected = int(stats.get("undetected", 0))
            total = sum(v for v in stats.values() if isinstance(v, int)) or (malicious + suspicious + undetected)
            engines_flagging = [engine for engine, r in results.items() if r.get("category") in ("malicious", "suspicious")]
            ratio = f"{malicious + suspicious}/{total}" if total else "0/0"
            return {
                "positives": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "detection_ratio": ratio,
                "engines_flagging": engines_flagging,
            }
        except Exception as e:
            logger.exception("Error summarizing VT JSON: %s", e)
            return {"error": "failed_to_summarize", "exception": str(e)}

    # ---------- compute threat score ----------
    @staticmethod
    def compute_threat_score(summary: Dict[str, Any]) -> float:
        # Weighted formula: malicious * 3 + suspicious * 1.5 normalized to 0-100
        try:
            malicious = float(summary.get("positives", 0))
            suspicious = float(summary.get("suspicious", 0))
            total_scanners = 0
            ratio = summary.get("detection_ratio", "0/0")
            try:
                left, right = ratio.split("/")
                total_scanners = max(int(right), 1)
            except Exception:
                total_scanners = 1
            raw_score = (malicious * 3.0 + suspicious * 1.5) / (total_scanners * 3.0) * 100.0
            return max(0.0, min(100.0, round(raw_score, 2)))
        except Exception:
            return 0.0

    def close(self):
        self.cache.close()


# ---------------------------
# Standalone demo / example
# ---------------------------
def demo_flow(file_to_check: str):
    print("\n" + "=" * 60)
    print("WARNETIX VT DEMO FLOW")
    print(f"File: {file_to_check}")
    print("=" * 60 + "\n")

    client = VirusTotalClient()

    # 1) Compute hash
    print("[1] Menghitung SHA256...")
    sha = client.sha256_of_file(file_to_check)
    print(f"    SHA256: {sha}")

    # 2) Lookup cache / VT
    print("[2] Memeriksa cache / VirusTotal untuk hash ini...")
    try:
        report = client.get_file_report(sha, use_cache=True)
    except Exception as e:
        print("    ERROR saat lookup hash:", e)
        client.close()
        return

    # The get_file_report returns various shapes; if 404 it returns an object with status_code=404
    if report.get("status_code") == 404 or (isinstance(report, dict) and not report.get("data")):
        print("    Hash tidak ditemukan di VT (response indicates not found). Uploading file for analysis...")
        upload_res = client.upload_file(file_to_check, use_cache=True)
        if upload_res.get("status") in ("uploaded", "uploaded_large"):
            # Try to find analysis id in the response
            # common location: upload_res['response']['data']['id']
            resp = upload_res.get("response") or {}
            analysis_id = None
            try:
                # try multiple common locations
                analysis_id = resp.get("data", {}).get("id") or resp.get("data", {}).get("attributes", {}).get("analysis_id") or resp.get("id")
            except Exception:
                analysis_id = None

            if not analysis_id:
                # some responses include analysis under data->id or return analysis id separately
                print("    Upload succeeded but analysis id not found in upload response; aborting poll.")
                print("    Raw upload response preview:", str(resp)[:1000])
                client.close()
                return

            print(f"    Upload triggered analysis id={analysis_id}. Polling for completion...")
            poll_res = client.poll_analysis(analysis_id)
            if poll_res.get("status") == "completed":
                print("    Analysis completed. Preparing summary...")
                vt_data = poll_res.get("data")
                summary = client.summarize_vt_data(vt_data)
                score = client.compute_threat_score(summary)
                print("    Summary:", json.dumps(summary, indent=2))
                print(f"    Threat score (0-100): {score}")
            else:
                print("    Polling did not complete:", poll_res)
        else:
            print("    Upload failed:", upload_res)
    else:
        # report exists
        print("    Report found in VT cache/API. Summarizing...")
        if isinstance(report, dict) and report.get("data"):
            summary = client.summarize_vt_data(report)
            score = client.compute_threat_score(summary)
            print("    Summary:", json.dumps(summary, indent=2))
            print(f"    Threat score (0-100): {score}")
        else:
            print("    Unexpected report shape:", str(report)[:1000])

    client.close()
    print("\nDEMO FLOW COMPLETE\n")


# ---------------------------
# If run as script, run demo with safe EICAR file
# ---------------------------
if __name__ == "__main__":
    # Create a harmless EICAR test file (recognized by AV vendors)
    demo_file = Path(__file__).parent.parent / "sample_files" / "eicar_test.txt"
    demo_file.parent.mkdir(parents=True, exist_ok=True)
    eicar = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    with open(demo_file, "w", encoding="utf-8") as f:
        f.write(eicar)
    print("EICAR test file created at:", str(demo_file))

    # Run demo flow
    demo_flow(str(demo_file))
