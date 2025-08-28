import os

PARTS = [
    "anomaly_model_iforest_v2.joblib.part1",
    "anomaly_model_iforest_v2.joblib.part2",
    "anomaly_model_iforest_v2.joblib.part3",
    "anomaly_model_iforest_v2.joblib.part4",
    "anomaly_model_iforest_v2.joblib.part5",
    "anomaly_model_iforest_v2.joblib.part6",
]

OUT = "anomaly_model_iforest_v2.joblib"

def merge(parts=PARTS, out=OUT):
    with open(out, "wb") as w:
        for p in parts:
            with open(p, "rb") as r:
                w.write(r.read())
    print(f"[OK] Merged {len(parts)} parts -> {out}")

if __name__ == "__main__":
    merge()