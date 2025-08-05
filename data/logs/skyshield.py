# SkyShield - Aplikasi Prediksi Cuaca Ekstrem Versi Lengkap
# Termasuk: Input API, Clustering, Enkripsi, Database, UI Dinamis

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from cryptography.fernet import Fernet
import requests
import sqlite3
import json

# --- KONFIGURASI AWAL ---
st.set_page_config(page_title="SkyShield", layout="wide")
st.title("☁️ SkyShield")
st.caption("Prediksi Cuaca Ekstrem + Pengamanan Lokasi + Database")

# --- DATABASE (SQLite) ---
conn = sqlite3.connect("skyshield.db")
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS cuaca (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    suhu REAL,
    kelembapan REAL,
    curah_hujan REAL,
    cluster INTEGER,
    rekomendasi TEXT,
    waktu TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')
conn.commit()

# --- ENKRIPSI ---
st.sidebar.header("🔐 Enkripsi Lokasi")
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
cipher = Fernet(st.session_state.key)
lokasi = st.sidebar.text_input("Lokasi (Lat,Lon)", value="-5.13,119.41")
if lokasi:
    lokasi_enkrip = cipher.encrypt(lokasi.encode()).decode()
    st.sidebar.success("Lokasi terenkripsi")
    st.sidebar.code(lokasi_enkrip)

# --- PENGAMBILAN DATA CUACA ---
st.subheader("🌦️ Ambil Data Cuaca dari OpenWeatherMap")
import streamlit as st

API_KEY = st.secrets["OPENWEATHER_API_KEY"]  # Ambil dari secrets.toml

if not API_KEY:
    st.warning("Ganti API Key terlebih dahulu.")
if 'lokasi_enkrip' in st.session_state:
    lokasi_enkrip = st.session_state.lokasi_enkrip
if st.button("Ambil Data API"):
    lat, lon = lokasi.split(',')
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={API_KEY}&units=metric"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        suhu = data['main']['temp']
        kelembapan = data['main']['humidity']
        curah_hujan = data.get('rain', {}).get('1h', 0.0)
        df_api = pd.DataFrame({
            'suhu': [suhu],
            'kelembapan': [kelembapan],
            'curah_hujan': [curah_hujan]
        })
        st.success("Data berhasil diambil")
        st.dataframe(df_api)
    else:
        st.error("Gagal ambil data dari API")

# --- INPUT DATA MANUAL ---
st.subheader("🧾 Input / Simulasi Data Cuaca")
data_default = {
    'suhu': [32, 34, 36, 29, 33, 31],
    'kelembapan': [65, 70, 80, 60, 75, 68],
    'curah_hujan': [2.1, 3.4, 6.5, 0.8, 5.2, 1.0]
}
df = pd.DataFrame(data_default)
df = st.data_editor(df, num_rows="dynamic", use_container_width=True)

# --- CLUSTERING DAN VISUALISASI ---
st.subheader("📊 Proses Clustering Cuaca")
if st.button("🔎 Jalankan Clustering"):
    kmeans = KMeans(n_clusters=3, random_state=42)
    cluster = kmeans.fit_predict(df)
    df['cluster'] = cluster
    rekomendasi = []
    for c in cluster:
        if c == 2:
            rekomendasi.append("⚠️ Cuaca Ekstrem - Hindari aktivitas luar")
        elif c == 1:
            rekomendasi.append("🔶 Cuaca Moderat - Waspadai hujan")
        else:
            rekomendasi.append("✅ Cuaca Normal - Aman")
    df['rekomendasi'] = rekomendasi

    # Simpan ke database
    for i, row in df.iterrows():
        c.execute("INSERT INTO cuaca (suhu, kelembapan, curah_hujan, cluster, rekomendasi) VALUES (?,?,?,?,?)",
                  (row['suhu'], row['kelembapan'], row['curah_hujan'], row['cluster'], row['rekomendasi']))
    conn.commit()

    st.success("Clustering selesai dan data disimpan")
    st.dataframe(df)

    fig, ax = plt.subplots()
    warna = ['green', 'orange', 'red']
    for i in range(3):
        clus = df[df['cluster'] == i]
        ax.scatter(clus['suhu'], clus['curah_hujan'], color=warna[i], label=f'Cluster {i}')
    ax.set_xlabel('Suhu (°C)')
    ax.set_ylabel('Curah Hujan (mm)')
    ax.set_title('Visualisasi Cluster')
    ax.legend()
    st.pyplot(fig)

# --- HISTORI DATABASE ---
st.subheader("🕒 Riwayat Cuaca Tersimpan")
db_df = pd.read_sql_query("SELECT * FROM cuaca ORDER BY waktu DESC LIMIT 50", conn)
st.dataframe(db_df)

# --- DOWNLOAD ---
st.download_button("⬇️ Unduh CSV", df.to_csv(index=False), file_name="hasil_skyshield.csv")
