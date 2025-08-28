# backend/scanner_core/vt_client.py
import os, time, hashlib, sqlite3, logging, requests
from concurrent.futures import ThreadPoolExecutor, Future

LOG = logging.getLogger("warnetix.vt")

VT_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    def __init__(self, api_key: str=None, cache_db: str = None, max_workers: int = 3):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key} if self.api_key else None
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.cache_db = cache_db or os.path.join(os.path.dirname(__file__), "..", "vt_cache.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.cache_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result_json TEXT,
                positives INTEGER,
                last_checked TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def _sha256(self, file_path):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def lookup_cache(self, sha256):
        conn = sqlite3.connect(self.cache_db)
        cur = conn.cursor()
        cur.execute("SELECT result_json, positives, last_checked FROM vt_cache WHERE sha256=?", (sha256,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {"result_json": row[0], "positives": row[1], "last_checked": row[2]}
        return None

    def cache_result(self, sha256, json_text, positives):
        conn = sqlite3.connect(self.cache_db)
        cur = conn.cursor()
        cur.execute("REPLACE INTO vt_cache(sha256,result_json,positives,last_checked) VALUES (?,?,?,CURRENT_TIMESTAMP)",
                    (sha256, json_text, positives))
        conn.commit()
        conn.close()

    # Public async submit function
    def submit_file_async(self, file_path: str) -> Future:
        """Schedule a worker to check file on VirusTotal (upload if absent). Returns Future."""
        if not self.api_key:
            LOG.warning("VT API key not configured. Skipping VirusTotal check.")
            f = Future()
            f.set_result({"status": "no_api_key"})
            return f
        return self.executor.submit(self._submit_and_get, file_path)

    # Internal worker
    def _submit_and_get(self, file_path: str):
        try:
            sha = self._sha256(file_path)
            LOG.info("VT: checking cache for sha256=%s", sha)
            cached = self.lookup_cache(sha)
            if cached:
                LOG.info("VT: cache HIT for %s positives=%s", sha, cached["positives"])
                return {"status": "cache", "sha256": sha, "positives": cached["positives"], "raw": cached["result_json"]}

            # 1) try GET by hash
            url = f"{VT_BASE}/files/{sha}"
            r = requests.get(url, headers=self.headers, timeout=30)
            if r.status_code == 200:
                data = r.json()
                positives = self._extract_positives(data)
                self.cache_result(sha, r.text, positives)
                return {"status": "found", "sha256": sha, "positives": positives, "raw": data}

            # 2) Upload file for analysis (if not found)
            LOG.info("VT: file not found remotely, uploading for analysis: %s", file_path)
            upload_url = f"{VT_BASE}/files"
            with open(file_path, "rb") as fh:
                files = {"file": (file_path, fh)}
                r2 = requests.post(upload_url, headers=self.headers, files=files, timeout=60)
            if r2.status_code in (200, 201):
                j = r2.json()
                # there may be an analysis id — try to poll analysis later
                # fallback: treat as submitted
                self.cache_result(sha, r2.text, 0)
                return {"status": "uploaded", "sha256": sha, "positives": 0, "raw": j}
            else:
                LOG.warning("VT upload failed: %s %s", r2.status_code, r2.text)
                return {"status": "error", "code": r2.status_code, "response": r2.text}
        except Exception as e:
            LOG.exception("VT worker error: %s", e)
            return {"status": "exception", "error": str(e)}

    def _extract_positives(self, vt_json):
        # robust extractor from VT file report structure
        try:
            stats = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = sum([v for k, v in stats.items() if isinstance(v, int) and k != "undetected"])
            # sometimes positives is directly sum of engines flagged count; approximate
            return int(stats.get("malicious", 0)) or sum(stats.values())
        except Exception:
            return 0
