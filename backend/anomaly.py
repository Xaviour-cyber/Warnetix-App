# File: backend/anomaly.py
import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomaly(df):
    """
    Deteksi anomali dari data log menggunakan Isolation Forest.
    Input: df (DataFrame hasil dari parser dan NLP)
    Output: df dengan kolom 'anomaly_score' dan 'is_anomaly'
    """
    fitur = ['timestamp', 'user', 'activity']

    # Ubah kolom timestamp menjadi angka
    if 'timestamp' in df.columns:
        df['timestamp_num'] = pd.to_datetime(df['timestamp'], errors='coerce').astype('int64') // 10**9
    else:
        df['timestamp_num'] = 0  # fallback jika tidak ada timestamp

    # Encode kolom user dan activity
    df['user_enc'] = df['user'].astype('category').cat.codes
    df['activity_enc'] = df['activity'].astype('category').cat.codes

    # Siapkan fitur untuk model
    X = df[['timestamp_num', 'user_enc', 'activity_enc']]

    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    df['anomaly_score'] = model.fit_predict(X)
    df['is_anomaly'] = df['anomaly_score'].apply(lambda x: True if x == -1 else False)

    return df
