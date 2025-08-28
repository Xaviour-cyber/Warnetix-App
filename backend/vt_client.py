# backend/vt_client.py
"""
VirusTotal v3 integration client for Warnetix
Features:
 - file hash lookup
 - file upload & analysis (handles >32MB via upload_url flow)
 - url submit & analysis
 - domain/ip lookup
 - sqlite caching to reduce API calls
 - rate-limit aware requests + exponential backoff
 - threat score normalization helper
Usage: instantiate VirusTotalClient(api_key=...) OR set VIRUSTOTAL_API_KEY in environment/.env
"""

import os
import time
import json
import logging
import sqlite3
import hashlib
from typing import Optional, Dict, Any
from pathlib import Path

import requests
from requests.exceptions import RequestException

# Optional: vt-py client (higher-level). If installed, we'll use it as an optimization.
try:
    import vt  # type: ignore
    VT_PY_AVAILABLE = True
except Exception:
    VT_PY_AVAILABLE = False

# Configure logging
logger = logging.getLogger("vt_client")
logger.setLevel(logging.INFO)

DEFAULT_BASE = "https://www.virustotal.com/api/v3"
CACHE_DB_DEFAULT = "backend/vt_cache.db"


class SQLiteCache:
    """Small persistent cache for VT results to avoid duplicate queries and save quota."""
    def __init__(self, path: str = CACHE_DB_DEFAULT):
        self.path = path
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_table()

    def _init_table(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                key TEXT PRIMARY KEY,
                timestamp INTEGER,
                payload TEXT
            )
        """)
        self.conn.commit()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT timestamp, payload FROM vt_cache WHERE key = ?", (key,))
        row = cur.fetchone()
        if not row:
            return None
        ts, payload = row
        try:
            return {"timestamp": ts, "payload": json.loads(payload)}
        except Exception:
            return None

    def set(self, key: str, payload: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute("REPLACE INTO vt_cache (key, timestamp, payload) VALUES (?, ?, ?)",
                    (key, int(time.time()), json.dumps(payload)))
        self.conn.commit()

    def close(self):
        self.conn.close()


class RateLimiter:
    """Very small rate limiter (requests per minute)."""
    def __init__(self, max_per_minute: int = 4):
        self.max = max_per_minute
        self.timestamps = []

    def wait(self):
        now = time.time()
        # purge old
        self.timestamps = [t for t in self.timestamps if now - t < 60]
        if len(self.timestamps) >= self.max:
            wait_time = 60 - (now - self.timestamps[0]) + 0.1
            logger.info(f"Rate limit reached, sleeping {wait_time:.1f}s")
            time.sleep(wait_time)
        self.timestamps.append(time.time())


class VirusTotalClient:
    def __init__(self,
                 api_key: Optional[str] = None,
                 base_url: str = DEFAULT_BASE,
                 cache_db: str = CACHE_DB_DEFAULT,
                 max_rpm: int = 4,
                 use_vtpy: bool = True):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not provided (env or constructor).")
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.rate_limiter = RateLimiter(max_per_minute=max_rpm)
        self.cache = SQLiteCache(cache_db)
        self.use_vtpy = use_vtpy and VT_PY_AVAILABLE
        if self.use_vtpy:
            try:
                self.vt_client = vt.Client(self.api_key)  # vt-py
            except Exception:
                self.vt_client = None
                self.use_vtpy = False

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        # rate limiting (local conservative)
        self.rate_limiter.wait()

        backoff = 1.0
        for attempt in range(6):
            try:
                resp = self.session.request(method, url, headers=self._headers(), timeout=60, **kwargs)
            except RequestException as e:
                logger.warning(f"VT request error: {e} (attempt {attempt+1})")
                time.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code == 200 or resp.status_code == 201:
                try:
                    return resp.json()
                except ValueError:
                    return {"raw_text": resp.text}
            elif resp.status_code == 204:
                return {}
            elif resp.status_code == 429:
                # rate limit - check Retry-After
                ra = resp.headers.get("Retry-After")
                sleep_for = int(ra) if ra and ra.isdigit() else backoff
                logger.info(f"VT rate-limited (429). Sleeping {sleep_for}s (attempt {attempt+1})")
                time.sleep(sleep_for)
                backoff *= 2
                continue
            elif 500 <= resp.status_code < 600:
                logger.warning(f"VT server error {resp.status_code}. Backing off {backoff}s (attempt {attempt+1})")
                time.sleep(backoff)
                backoff *= 2
                continue
            else:
                # other client error: return JSON or raise
                try:
                    return resp.json()
                except Exception:
                    raise RuntimeError(f"VT request failed: {resp.status_code} {resp.text}")
        raise RuntimeError("VT request failed after retrying")

    # ---------- FILE / HASH ----------
    def get_file_report(self, file_hash: str, use_cache: bool = True) -> Dict[str, Any]:
        key = f"file_report:{file_hash}"
        if use_cache:
            cached = self.cache.get(key)
            if cached:
                return cached["payload"]

        endpoint = f"/files/{file_hash}"
        res = self._request("GET", endpoint)
        if use_cache:
            self.cache.set(key, res)
        return res

    def scan_file(self, path: str, wait: bool = True, poll_interval: int = 5, use_cache: bool = True) -> Dict[str, Any]:
        """
        Uploads a file for analysis.
        - Files <= 32MB: POST /files
        - Larger: request upload URL /files/upload_url then PUT file to that URL (private scanning flow)
        Returns final analysis JSON (if wait=True) or immediate response.
        """
        p = Path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(path)

        # compute sha256 to check prior report
        h = self._sha256_of_file(path)
        # try to reuse existing report
        try:
            report = self.get_file_report(h, use_cache=use_cache)
            # If there's an analysis with stats present, return it early
            if report and isinstance(report, dict) and report.get("data"):
                return {"from_cache": True, "report": report}
        except Exception:
            pass  # not found, continue to upload

        filesize = p.stat().st_size
        filesize_mb = filesize / (1024 * 1024)

        # if vt-py available, use convenience API
        if self.use_vtpy and self.vt_client:
            logger.info("Using vt-py client to scan file (blocking)")
            with open(path, "rb") as fh:
                analysis = self.vt_client.scan_file(fh, wait_for_completion=wait)
                return {"vtpy": True, "analysis": analysis.data}

        if filesize_mb <= 32:
            files = {"file": open(path, "rb")}
            res = self._request("POST", "/files", files=files)
            # res usually contains data.id -> analysis id. Poll analysis
            analysis_id = None
            try:
                analysis_id = res["data"]["id"]
            except Exception:
                # some endpoints might return differently
                logger.debug("Unexpected POST /files response: %s", res)
            if wait and analysis_id:
                return self._poll_analysis(analysis_id, poll_interval=poll_interval, timeout=300)
            return res
        else:
            # large file flow: get upload url
            logger.info("Large file (>32MB) -> requesting upload url")
            res = self._request("POST", "/files/upload_url")
            upload_url = None
            try:
                upload_url = res["data"]["attributes"]["upload_url"]
            except Exception:
                # for private scanning endpoints it may differ
                upload_url = res.get("upload_url") or res.get("data", {}).get("upload_url")
            if not upload_url:
                raise RuntimeError("Could not obtain upload_url from VT response.")
            # Put file to upload_url
            # chunked upload
            with open(path, "rb") as fh:
                put_resp = requests.put(upload_url, data=fh)
            if put_resp.status_code not in (200, 201):
                raise RuntimeError(f"Large file upload failed: {put_resp.status_code} {put_resp.text}")
            # the response should include an analysis id (in some private flows). Try to find it
            put_json = {}
            try:
                put_json = put_resp.json()
            except Exception:
                put_json = {"raw_text": put_resp.text}
            analysis_id = put_json.get("data", {}).get("id") or put_json.get("id")
            if wait and analysis_id:
                return self._poll_analysis(analysis_id, poll_interval=poll_interval, timeout=600)
            return put_json

    def _poll_analysis(self, analysis_id: str, poll_interval: int = 5, timeout: int = 300) -> Dict[str, Any]:
        start = time.time()
        while True:
            res = self._request("GET", f"/analyses/{analysis_id}")
            status = res.get("data", {}).get("attributes", {}).get("status")
            if status == "completed" or status == "completed_with_errors" or status is None:
                return res
            if time.time() - start > timeout:
                raise TimeoutError("Timeout while waiting for analysis to finish.")
            time.sleep(poll_interval)

    # ---------- URL ----------
    def scan_url(self, target_url: str, wait: bool = True, poll_interval: int = 5) -> Dict[str, Any]:
        payload = {"url": target_url}
        res = self._request("POST", "/urls", data=payload)
        # API returns data.id (analysis id) or location header
        analysis_id = None
        try:
            analysis_id = res["data"]["id"]
        except Exception:
            # sometimes the response is different
            pass
        if wait and analysis_id:
            return self._poll_analysis(analysis_id, poll_interval=poll_interval)
        return res

    # ---------- DOMAIN / IP ----------
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        return self._request("GET", f"/domains/{domain}")

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        return self._request("GET", f"/ip_addresses/{ip}")

    # ---------- Helpers ----------
    @staticmethod
    def _sha256_of_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def compute_threat_score(self, vt_report: Dict[str, Any]) -> float:
        """
        Normalize a 'threat' score from VirusTotal report:
        - Uses last_analysis_stats (malicious/suspicious/etc.) when available.
        Score range 0.0 - 100.0 (100 = most dangerous)
        """
        try:
            stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = sum(v for v in stats.values() if isinstance(v, int))
            engines = max(total, 1)
            # weighted score
            score = (malicious * 3.0 + suspicious * 1.5) / (engines * 3.0) * 100.0
            # clamp
            return float(max(0.0, min(100.0, score)))
        except Exception:
            return 0.0

    def close(self):
        try:
            self.cache.close()
        except Exception:
            pass
        if self.use_vtpy and getattr(self, "vt_client", None) is not None:
            try:
                self.vt_client.close()
            except Exception:
                pass


# ---------- Usage examples (to be called from scanner.py) ----------
if __name__ == "__main__":
    # simple demo (replace with real key in env or pass api_key)
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "<PUT_YOUR_KEY_IN_.env>")
    client = VirusTotalClient(api_key=vt_key, max_rpm=4, use_vtpy=False)

    # 1) check a hash
    try:
        h = "e3b0c44298fc1c149afbf4c8996fb924..."  # example sha256
        r = client.get_file_report(h)
        print("report:", json.dumps(r, indent=2)[:800])
    except Exception as e:
        print("hash lookup error:", e)

    # 2) scan small file (blocking)
    # print(client.scan_file("/path/to/suspect.exe", wait=True))

    client.close()
