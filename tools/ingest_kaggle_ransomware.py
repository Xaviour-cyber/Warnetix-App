# tools/ingest_kaggle_ransomware.py
import zipfile, sqlite3, pathlib, time, json, sys
import pandas as pd

DB  = pathlib.Path("backend/data/warnetix.db")
SRC = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("backend/intel/kaggle_ransomware.zip")

def load_df(src: pathlib.Path) -> pd.DataFrame:
    if src.suffix.lower() == ".csv":
        return pd.read_csv(src)
    # ZIP mode: ambil CSV pertama
    with zipfile.ZipFile(src, "r") as z:
        name = [n for n in z.namelist() if n.lower().endswith(".csv")][0]
        with z.open(name) as f:
            return pd.read_csv(f)

def main():
    con = sqlite3.connect(DB); con.execute("PRAGMA journal_mode=WAL")
    cur = con.cursor()

    df = load_df(SRC)

    # deteksi nama kolom fleksibel
    cols = {c.lower(): c for c in df.columns}
    md5col = cols.get("md5hash") or cols.get("md5")
    bencol = cols.get("benign")
    btccol = cols.get("bitcoinaddresses")  # opsional

    if not md5col or not bencol:
        raise SystemExit("CSV Kaggle harus punya kolom md5/md5Hash dan Benign.")

    keep = [md5col, bencol] + ([btccol] if btccol else [])
    df = df[keep].copy()

    df["md5"] = df[md5col].astype(str).str.lower()
    # Asumsi: Benign = 1 (aman), 0 (malicious)
    df["is_mal"] = 1 - df[bencol].astype(int)
    df["btc"] = df[btccol].fillna(0).astype(int) if btccol else 0

    rows = 0
    t_now = int(time.time())
    UPSERT = """
    INSERT INTO signatures (sha256, md5, threat_family, threat_type, severity, source, first_seen, last_seen, meta_json)
    VALUES (NULL, ?, ?, 'ransomware', ?, 'kaggle', ?, ?, ?)
    ON CONFLICT(md5) DO UPDATE SET
      threat_family=COALESCE(excluded.threat_family, signatures.threat_family),
      threat_type=COALESCE(excluded.threat_type, signatures.threat_type),
      severity=CASE WHEN excluded.severity IN ('critical','high') THEN excluded.severity ELSE signatures.severity END,
      first_seen=COALESCE(signatures.first_seen, excluded.first_seen),
      last_seen=MAX(COALESCE(signatures.last_seen,0), COALESCE(excluded.last_seen,0)),
      meta_json=excluded.meta_json
    """

    for _, r in df[df["is_mal"] == 1].iterrows():
        md5 = r["md5"]
        sev = "critical" if int(r["btc"]) > 0 else "high"
        meta = {"kaggle": True, "bitcoin_addr_count": int(r["btc"])}
        cur.execute(UPSERT, (md5, "ransomware", sev, t_now, t_now, json.dumps(meta)))
        rows += 1

    con.commit()
    print(f"[OK] Kaggle ingested {rows} ransomware md5 -> signatures from {SRC}")

if __name__ == "__main__":
    main()