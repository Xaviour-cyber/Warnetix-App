# File: backend/nlp.py

import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import numpy as np

# Contoh data latih sederhana (bisa diganti model yang lebih canggih nanti)
leak_keywords = ["password", "username", "token", "login", "key", "auth", "credentials"]

# Buat model dummy untuk mendeteksi kebocoran berbasis keyword
vectorizer = TfidfVectorizer()
classifier = LogisticRegression()

# Data latih dummy
X_train = [
    "user login success",
    "token expired",
    "password leak attempt",
    "normal connection",
    "heartbeat ok",
    "service running",
]
y_train = [1, 1, 1, 0, 0, 0]  # 1 = kemungkinan bocor, 0 = normal

X_vect = vectorizer.fit_transform(X_train)
classifier.fit(X_vect, y_train)

def detect_leakage(df: pd.DataFrame) -> pd.DataFrame:
    if 'log' not in df.columns:
        df['log'] = df.apply(lambda row: ' '.join(str(v) for v in row.values), axis=1)

    logs = df['log'].astype(str).fillna("").tolist()
    X_input = vectorizer.transform(logs)
    preds = classifier.predict(X_input)

    df['possible_leak'] = preds
    df['leak_label'] = df['possible_leak'].map({1: "⚠️ Kemungkinan Kebocoran", 0: "✅ Aman"})

    return df
