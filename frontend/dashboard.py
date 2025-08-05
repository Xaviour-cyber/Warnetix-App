# File: frontend/dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import os
import base64

# Set page config
st.set_page_config(page_title="Warnetix Dashboard", layout="wide")
st.markdown("""
    <style>
        body {
            background-color: #1f1f1f;
        }
        .main {
            background-color: #1f1f1f;
        }
        .css-1v0mbdj, .css-1d391kg, .st-bx, .st-e3, .st-cz {
            background-color: #1f1f1f !important;
            color: white;
        }
        .css-18ni7ap {
            background-color: #8B0000 !important;
            color: white;
        }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Warnetix: Data Leak & Anomaly Detection")

# Upload CSV hasil analisis
uploaded_file = st.file_uploader("Upload hasil log analisis (.csv):", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success("File berhasil dimuat!")

    with st.expander("🔍 Tampilkan Data Mentah"):
        st.dataframe(df, use_container_width=True)

    # Visualisasi aktivitas vs waktu
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        fig_time = px.histogram(df, x='timestamp', color='user', nbins=50,
                                title="📊 Aktivitas User dari Waktu ke Waktu")
        st.plotly_chart(fig_time, use_container_width=True)

    # Visualisasi kebocoran data
    if 'leak_detected' in df.columns:
        st.subheader("🔥 Deteksi Kebocoran Data")
        leak_df = df[df['leak_detected'] == True]
        st.metric("Jumlah Potensi Kebocoran", len(leak_df))
        st.dataframe(leak_df[['timestamp', 'user', 'activity', 'leak_detected']])

    # Visualisasi anomali
    if 'is_anomaly' in df.columns:
        st.subheader("🚨 Deteksi Anomali Aktivitas")
        fig_anomali = px.scatter(df, x='timestamp', y='activity', color='is_anomaly',
                                 symbol='is_anomaly', title="Pola Aktivitas yang Tidak Biasa")
        st.plotly_chart(fig_anomali, use_container_width=True)

    # Fitur ekspor hasil
    csv = df.to_csv(index=False).encode()
    b64 = base64.b64encode(csv).decode()
    st.markdown(f"""
        <a href="data:file/csv;base64,{b64}" download="hasil_warnetix.csv">
            📥 <button style='background-color:#8B0000;color:white;padding:8px 16px;border:none;border-radius:5px;'>Download Hasil</button>
        </a>
    """, unsafe_allow_html=True)
else:
    st.info("Silakan upload file log hasil analisis untuk melihat dashboard.")
