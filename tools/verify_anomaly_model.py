# tools/verify_anomaly_model.py
import sys, json, pickle, warnings, pathlib
from typing import Optional

def _load(path: pathlib.Path):
    try:
        import joblib
        return joblib.load(path)
    except Exception as e1:
        try:
            with path.open("rb") as f:
                return pickle.load(f)
        except Exception as e2:
            raise RuntimeError(f"Failed to load {path} with joblib ({e1}) and pickle ({e2})")

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/verify_anomaly_model.py <model_path> [feature_schema.json]")
        sys.exit(1)

    model_path = pathlib.Path(sys.argv[1])
    schema_path: Optional[pathlib.Path] = pathlib.Path(sys.argv[2]) if len(sys.argv) >= 3 else None

    print(f"[i] Loading model: {model_path}")
    model = _load(model_path)
    print(f"[ok] Loaded type: {type(model)}")

    # versi lib
    try:
        import sklearn, joblib
        print(f"[i] sklearn={sklearn.__version__} joblib={joblib.__version__}")
    except Exception:
        pass

    # atribut umum scikit-learn
    for attr in ("n_features_in_", "feature_names_in_", "offset_",
                 "estimators_", "contamination", "n_estimators"):
        if hasattr(model, attr):
            val = getattr(model, attr)
            val = list(val)[:3] if isinstance(val, (list, tuple)) else val
            print(f"[i] {attr} = {val}")

    # uji skor 1 sampel dummy (jumlah fitur harus cocok)
    import numpy as np
    n = getattr(model, "n_features_in_", None)
    if n:
        x = np.zeros((1, n))
        try:
            s = None
            if hasattr(model, "decision_function"):
                s = model.decision_function(x)
            elif hasattr(model, "score_samples"):
                s = model.score_samples(x)
            print(f"[ok] score on zero sample: {s}")
        except Exception as e:
            print(f"[warn] scoring failed: {e}")

    # cek schema kalau ada
    if schema_path and schema_path.exists():
        try:
            js = json.loads(schema_path.read_text(encoding="utf-8"))
            cols = js.get("feature_columns") or js.get("columns")
            if isinstance(cols, list):
                print(f"[i] feature_schema columns ({len(cols)}): {cols[:8]}{' ...' if len(cols)>8 else ''}")
                if hasattr(model, "feature_names_in_"):
                    model_cols = list(getattr(model, "feature_names_in_"))
                    mismatch = [c for c in cols if c not in model_cols]
                    if mismatch:
                        print(f"[warn] schema/model mismatch (example): {mismatch[:8]}")
        except Exception as e:
            print(f"[warn] failed to read schema: {e}")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    main()
