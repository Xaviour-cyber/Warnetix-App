# tools/train_runtime_iforest.py
import json, pathlib, random
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
import joblib

RNG = np.random.default_rng(42)

FEATURES = ["ext_office","ext_script","size_mb","hour","entropy","has_macro"]

def synth_rows(n=5000, anomaly_ratio=0.03):
    rows = []
    for _ in range(n):
        # mayoritas "normal"
        ext_office = int(RNG.random() < 0.15)
        ext_script = int(RNG.random() < 0.08)
        size_mb    = max(0.0, RNG.normal(8.0, 6.0))     # mayoritas kecil-menengah
        hour       = float(int(RNG.integers(7, 20)))     # jam kerja
        entropy    = float(np.clip(RNG.normal(4.6, 0.8), 0, 8))  # rendah-menengah
        has_macro  = int(ext_office and RNG.random() < 0.02)

        rows.append([ext_office, ext_script, size_mb, hour, entropy, has_macro])

    # tambahkan outlier/anomali
    k = int(n * anomaly_ratio)
    for _ in range(k):
        ext_office = int(RNG.random() < 0.05)
        ext_script = int(RNG.random() < 0.40)
        size_mb    = float(np.clip(RNG.normal(60.0, 40.0), 0, 512))  # besar
        # jam tidak lazim
        hour       = float(int(RNG.choice([0,1,2,3,4,23])))
        entropy    = float(np.clip(RNG.normal(7.2, 0.5), 0, 8))      # tinggi
        has_macro  = int(ext_office and RNG.random() < 0.5)

        rows.append([ext_office, ext_script, size_mb, hour, entropy, has_macro])

    RNG.shuffle(rows)
    return pd.DataFrame(rows, columns=FEATURES)

def main():
    out_dir = pathlib.Path("backend/scanner_core/models")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_model = out_dir / "anomaly_iforest.joblib"
    out_schema = out_dir / "anomaly_iforest.schema.json"

    df = synth_rows()
    X = df[FEATURES].values

    pipe = make_pipeline(
        StandardScaler(with_mean=False),
        IsolationForest(n_estimators=300, contamination=0.03, random_state=42, n_jobs=-1),
    )
    pipe.fit(X)

    joblib.dump(pipe, out_model)
    out_schema.write_text(json.dumps({"feature_columns": FEATURES}, indent=2), encoding="utf-8")

    print("[OK] saved model:", out_model)
    print("[OK] saved schema:", out_schema)
    print("[Info] features:", FEATURES)

if __name__ == "__main__":
    main()
