import sys, os, numpy as np, joblib
from sklearn.ensemble import IsolationForest

out = sys.argv[1]
os.makedirs(os.path.dirname(out), exist_ok=True)
features = ["size_kb","entropy","string_count","spec_char_ratio","import_count","macro_score"]
rng = np.random.RandomState(42)
X = rng.normal(0, 1, size=(4000, len(features))).astype("float64")
clf = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
clf.fit(X)

bundle = {"model": clf, "features": features}  # loader kamu support dict bundle
joblib.dump(bundle, out)
print("[OK] wrote:", out, "size=", os.path.getsize(out))
