import os, pathlib, hashlib
import requests
import joblib

MODEL_PATH = os.getenv("ANOMALY_MODEL_PATH", "backend/scanner_core/models/anomaly_iforest.joblib")
MODEL_URL = os.getenv("ANOMALY_MODEL_URL", "")
MODEL_SHA256 = os.getenv("ANOMALY_MODEL_SHA256", "")

def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_model_file() -> pathlib.Path | None:
    p = pathlib.Path(MODEL_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)

    if p.exists():
        return p

    if not MODEL_URL:
        return None

    r = requests.get(MODEL_URL, timeout=120)
    r.raise_for_status()
    p.write_bytes(r.content)

    if MODEL_SHA256:
        if _sha256(p).lower() != MODEL_SHA256.lower():
            p.unlink(missing_ok=True)
            raise RuntimeError("Anomaly model checksum mismatch")

    return p

def load_model():
    p = ensure_model_file()
    if not p:
        return None
    return joblib.load(p)
