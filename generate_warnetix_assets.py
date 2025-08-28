"""
Generate initial Warnetix assets:
1. ransomware_signatures.json  -> signature/
2. anomaly_model.pkl           -> backend/scanner_core/
3. anomaly_train_sample.csv    -> backend/scanner_core/
4. WARNETIX_MODEL_README.txt   -> root project

This script should be run once to bootstrap the AI detection system.
"""

import os
import json
import hashlib
import pickle
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# =====================
# PATH CONFIG
# =====================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_DIR = os.path.join(ROOT_DIR, "signature")
MODEL_DIR = os.path.join(ROOT_DIR, "backend", "scanner_core")

os.makedirs(SIG_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# =====================
# STEP 1: SIGNATURES JSON
# =====================
sample_malicious_bytes = [
    b"SAMPLE_RANSOMWARE_1: DO NOT EXECUTE - Warnetix test pattern only.",
    b"SAMPLE_RANSOMWARE_2: encryptor signature simulation for testing.",
    b"SAMPLE_RANSOMWARE_3: fake encrypted payload data for hash fingerprint."
]

sample_hashes = [hashlib.sha256(b).hexdigest() for b in sample_malicious_bytes]

ransomware_signatures = {
    "name": "warnetix_ransomware_signatures_v1",
    "version": datetime.utcnow().strftime("%Y-%m-%d"),
    "description": "Initial ransomware signature database for Warnetix AI scanner.",
    "created_at": datetime.utcnow().isoformat() + "Z",
    "hashes": sample_hashes,
    "keywords": [
        "_encrypted", ".locked", "_encrypt", "ransom", "decrypt_instructions",
        "readme_decrypt", "HOW_TO_DECRYPT", "ENCRYPTED_BY", "PAYMENT_INSTRUCTIONS"
    ],
    "filename_patterns": [
        "*readme.txt", "*HOW_TO_DECRYPT*", "*_HELP_*", "*DECRYPT*"
    ],
    "suspicious_extensions": [
        ".encrypted", ".locked", ".crypt", ".enc", ".cry", ".pay", ".cryp", ".crypted"
    ],
    "entropy_threshold": 7.5,
    "notes": "This is a demo signature set. Replace/add real threat intel data for production."
}

sig_path = os.path.join(SIG_DIR, "ransomware_signatures.json")
with open(sig_path, "w", encoding="utf-8") as f:
    json.dump(ransomware_signatures, f, indent=2)
print(f"[+] Wrote ransomware signatures -> {sig_path}")

# =====================
# STEP 2: TRAIN ANOMALY MODEL
# =====================
rng = np.random.default_rng(42)

N_BENIGN = 1200
N_ANOM = 80

benign_entropy = rng.normal(4.0, 0.6, N_BENIGN).clip(0.5, 8.0)
benign_filesize = np.exp(rng.normal(np.log(50), 1.0, N_BENIGN))
benign_exec = rng.choice([0, 1], size=N_BENIGN, p=[0.9, 0.1])
benign_kw = rng.choice([0, 1], size=N_BENIGN, p=[0.995, 0.005])

anom_entropy = rng.normal(7.8, 0.5, N_ANOM).clip(5.0, 8.9)
anom_filesize = np.exp(rng.normal(np.log(1200), 1.1, N_ANOM))
anom_exec = rng.choice([0, 1], size=N_ANOM, p=[0.4, 0.6])
anom_kw = rng.choice([0, 1], size=N_ANOM, p=[0.2, 0.8])

entropy = np.concatenate([benign_entropy, anom_entropy])
filesize_kb = np.concatenate([benign_filesize, anom_filesize])
is_executable = np.concatenate([benign_exec, anom_exec])
keyword_flag = np.concatenate([benign_kw, anom_kw])

df_train = pd.DataFrame({
    "entropy": entropy,
    "filesize_kb": filesize_kb,
    "is_executable": is_executable,
    "keyword_flag": keyword_flag
})

features = ["entropy", "filesize_kb", "is_executable", "keyword_flag"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(df_train[features])

model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    random_state=42
)
model.fit(X_scaled)

model_artifact = {
    "model_type": "IsolationForest",
    "features": features,
    "scaler_mean": scaler.mean_.tolist(),
    "scaler_scale": scaler.scale_.tolist(),
    "model": model
}

model_path = os.path.join(MODEL_DIR, "anomaly_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model_artifact, f, protocol=pickle.HIGHEST_PROTOCOL)
print(f"[+] Wrote anomaly model -> {model_path}")

# Save sample CSV
train_csv_path = os.path.join(MODEL_DIR, "anomaly_train_sample.csv")
df_train.sample(200, random_state=42).to_csv(train_csv_path, index=False)
print(f"[+] Wrote training sample CSV -> {train_csv_path}")

# =====================
# STEP 3: README FILE
# =====================
readme_content = f"""
WARNETIX AI Scanner Assets
Generated: {datetime.utcnow().isoformat()}Z

FILES:
1. signature/ransomware_signatures.json
   - Contains initial ransomware detection rules:
     * Known SHA256 hashes (demo only)
     * Common ransomware keywords
     * Suspicious filename patterns
     * Dangerous extensions
     * Entropy threshold for encryption detection

2. backend/scanner_core/anomaly_model.pkl
   - Pre-trained IsolationForest model for anomaly detection.
   - Includes StandardScaler parameters and feature list:
     {features}

3. backend/scanner_core/anomaly_train_sample.csv
   - Random sample of training data used to build the model.

USAGE:
- Load ransomware_signatures.json in your scanner's signature-based detection module.
- Load anomaly_model.pkl in anomaly detection stage:
    import pickle, numpy as np
    with open("backend/scanner_core/anomaly_model.pkl", "rb") as f:
        artifact = pickle.load(f)
    model = artifact['model']
    feats = artifact['features']
    mean = np.array(artifact['scaler_mean'])
    scale = np.array(artifact['scaler_scale'])

SECURITY:
- This dataset is SAFE for testing (no live malware).
- Replace demo hashes/keywords with real threat intel before production use.
"""

readme_path = os.path.join(ROOT_DIR, "WARNETIX_MODEL_README.txt")
with open(readme_path, "w", encoding="utf-8") as f:
    f.write(readme_content.strip())

print(f"[+] Wrote README -> {readme_path}")
print("[✓] Asset generation complete.")
