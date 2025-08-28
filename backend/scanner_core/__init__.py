# backend/scanner_core/__init__.py
import os, math, re, joblib, numpy as np
from collections import Counter

FEATURE_ORDER = ["ext_office","ext_script","size_mb","hour","entropy","has_macro"]

def _entropy(b: bytes) -> float:
    if not b: return 0.0
    cnt = Counter(b); n = len(b)
    return float(-sum((c/n) * math.log2(c/n) for c in cnt.values()))

class AnomalyEngine:
    def __init__(self, model_dir, threshold=-0.2):
        self.model = None
        self.threshold = threshold
        cands = [
            os.path.join(model_dir, "anomaly_model.pkl"),
            os.path.join(model_dir, "anomaly_model_iforest_v1.joblib"),
        ]
        for p in cands:
            if os.path.exists(p):
                try:
                    self.model = joblib.load(p)
                    break
                except Exception:
                    pass

    def ready(self) -> bool:
        return self.model is not None

    def _feat(self, ev: dict, file_path: str|None):
        path = (ev.get("path") or ev.get("filename") or "")
        ext  = (ev.get("extension") or os.path.splitext(path)[1][1:]).lower()
        size = float(ev.get("size") or 0.0) / (1024*1024)

        hour = 12
        ts = ev.get("ts")
        if isinstance(ts, (int, float)) and ts > 0:
            hour = int((ts % 86400) // 3600)

        ent = 0.0; macro = 0
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    b = f.read(4096)
                ent = _entropy(b)
                txt = re.sub(r"[^a-zA-Z0-9_]+", " ", b.decode("utf-8","ignore")).lower()
                macro = int(any(k in txt for k in ("autoopen","document_open","powershell","wscript","cscript")))
            except Exception:
                pass

        feats = {
            "ext_office": int(ext in ("doc","docx","xls","xlsx","xlsm","ppt","pptm","rtf")),
            "ext_script": int(ext in ("js","vbs","ps1","bat","cmd","hta","wsf","psm1")),
            "size_mb":    size,
            "hour":       float(hour),
            "entropy":    ent,
            "has_macro":  macro,
        }
        X = np.array([feats[k] for k in FEATURE_ORDER], dtype=float).reshape(1, -1)
        return X

    def score(self, ev: dict, file_path: str|None):
        if not self.ready(): return None
        X = self._feat(ev, file_path)
        # IsolationForest kompatibel: score_samples / decision_function
        try:    s = float(self.model.score_samples(X)[0])
        except: s = float(self.model.decision_function(X)[0])
        return s

    def is_anomaly(self, score: float) -> bool:
        return score is not None and score < self.threshold
