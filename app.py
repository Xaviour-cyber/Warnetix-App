# Struktur Folder (secara virtual untuk sekarang)
# ├─ warnetix/
# │   ├─ app.py
# │   ├─ requirements.txt
# │   ├─ backend/
# │   │   ├─ nlp.py
# │   │   ├─ anomaly.py
# │   ├─ frontend/
# │   │   ├─ dashboard.py
# │   ├─ utils/
# │   │   ├─ parser.py
# │   ├─ data/
# │   │   ├─ logs/     (tempat log yang diupload)
# │   │   └─ output/   (hasil ekspor)

import uvicorn
from fastapi import FastAPI, File, UploadFile
import os
import shutil
from backend import nlp, anomaly
from utils import parser

app = FastAPI()

UPLOAD_DIR = "data/logs"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload")
async def upload_log(file: UploadFile = File(...)):
    file_location = f"{UPLOAD_DIR}/{file.filename}"
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Parsing log
    log_df = parser.parse_log(file_location)

    # Deteksi kebocoran data (NLP)
    log_df = nlp.detect_leakage(log_df)

    # Deteksi anomali aktivitas (AI)
    log_df = anomaly.detect_anomaly(log_df)

    # Simpan hasil analisis ke CSV
    output_path = f"data/output/{file.filename}.csv"
    log_df.to_csv(output_path, index=False)

    return {"message": "File processed successfully", "output": output_path}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
