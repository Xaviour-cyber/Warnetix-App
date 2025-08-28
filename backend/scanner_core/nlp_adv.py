# backend/scanner_core/nlp_adv.py
from __future__ import annotations
import re, json
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional
from email.parser import Parser
from email.policy import default as default_policy

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# ==========
# 1) Mini-corpus untuk model ringan (ID + EN) -> phishing/social-engineering
# ==========
SUSPICIOUS_ID = [
    "klik tautan ini untuk verifikasi akun anda",
    "akun anda dibatasi segera perbarui data",
    "transfer biaya administrasi untuk aktivasi",
    "unduh lampiran penting segera rahasia",
    "konfirmasi pembayaran dalam 24 jam",
    "anda terpilih mendapatkan hadiah besar",
    "mohon kirimkan kode otp anda sekarang",
    "reset password dengan mengisi formulir di tautan",
    "cek mutasi bank dengan login di sini",
    "tagihan tidak dibayar klik untuk bayar",
]
BENIGN_ID = [
    "terlampir notulen rapat mingguan",
    "jadwal ujian dan pengumuman kelas",
    "laporan keuangan bulanan tersedia",
    "silakan cek dokumen tugas sekolah",
    "pembaruan perangkat lunak internal",
    "terima kasih atas kerja samanya",
    "catatan pertemuan besok pagi",
    "pengingat pengumpulan tugas",
    "dokumen panduan penggunaan",
    "konfirmasi kehadiran acara",
]

SUSPICIOUS_EN = [
    "verify your account by clicking this link",
    "your account has been limited update now",
    "urgent payment required within 24 hours",
    "download the attachment confidential",
    "reset your password using this form",
    "you won a prize click here",
    "send your otp code immediately",
    "bank login required to view statement",
    "invoice overdue pay via link",
    "security alert unusual sign in click",
]
BENIGN_EN = [
    "attached is the weekly meeting minutes",
    "please review the class schedule",
    "the monthly financial report is available",
    "check the project documentation",
    "internal software update notice",
    "thank you for your cooperation",
    "notes for tomorrow morning meeting",
    "gentle reminder to submit assignment",
    "user guide documentation attached",
    "rsvp for the upcoming event",
]

CORPUS = SUSPICIOUS_ID + SUSPICIOUS_EN + BENIGN_ID + BENIGN_EN
LABELS = [1]*len(SUSPICIOUS_ID+SUSPICIOUS_EN) + [0]*len(BENIGN_ID+BENIGN_EN)

# TF-IDF + Logistic Regression (kecil, cepat)
VEC = TfidfVectorizer(ngram_range=(1,2), min_df=1, lowercase=True)
X = VEC.fit_transform(CORPUS)
CLF = LogisticRegression(max_iter=400, class_weight="balanced")
CLF.fit(X, LABELS)

# ==========
# 2) Regex/pola & keyword untuk rule-based boost
# ==========
RE_URL = re.compile(r'https?://[^\s)>\"]+', re.I)
RE_CARD = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
RE_OTP  = re.compile(r'\b(otp|one[-\s]?time\s?password)\b', re.I)
RE_BANK = re.compile(r'\b(bri|bca|bni|mandiri|cimb|permata|bank|rekening)\b', re.I)
RE_URG  = re.compile(r'\b(urgent|segera|immediately|now|24\s*hours|penting)\b', re.I)
RE_LOGIN= re.compile(r'\b(login|masuk|verify|verifikasi|confirm|konfirmasi)\b', re.I)
RE_BITC = re.compile(r'\b(bitcoin|crypto|usdt|wallet|transfer)\b', re.I)

PHISH_KW_ID = ["tautan", "verifikasi", "akun", "rekening", "hadiah", "transfer", "otp", "password", "masuk", "bank"]
PHISH_KW_EN = ["verify", "account", "login", "bank", "invoice", "payment", "urgent", "password", "update", "confirm"]

def _lang_hint(text: str) -> str:
    t = text.lower()
    id_hits = sum(kw in t for kw in PHISH_KW_ID)
    en_hits = sum(kw in t for kw in PHISH_KW_EN)
    if id_hits > en_hits and id_hits >= 2: return "id"
    if en_hits > id_hits and en_hits >= 2: return "en"
    return "unknown"

def _rule_score(text: str) -> float:
    score = 0.0
    if RE_URL.search(text):  score += 0.2
    if RE_OTP.search(text):  score += 0.2
    if RE_BANK.search(text): score += 0.1
    if RE_URG.search(text):  score += 0.1
    if RE_LOGIN.search(text):score += 0.2
    if RE_BITC.search(text): score += 0.2
    if RE_CARD.search(text): score += 0.3
    return min(1.0, score)

def _model_score(text: str) -> float:
    # Probabilitas phishing menurut model (0..1)
    v = VEC.transform([text])
    proba = CLF.predict_proba(v)[0,1]
    return float(proba)

# ==========
# 3) Analisis header email
# ==========
def analyze_email_headers(raw: str) -> Dict[str, Any]:
    res = {"risk": 0.0, "flags": [], "parsed": {}}
    try:
        msg = Parser(policy=default_policy).parsestr(raw)
    except Exception:
        return res

    headers = {k.lower(): str(v) for k,v in msg.items()}
    res["parsed"] = {k: headers.get(k,"") for k in [
        "from","reply-to","return-path","subject","received","authentication-results"
    ]}

    fr = headers.get("from","")
    rp = headers.get("reply-to","")
    auth = headers.get("authentication-results","")
    subj = headers.get("subject","")
    received_all = msg.get_all("received", []) or []

    # domain mismatch From vs Reply-To
    def _domain(s: str) -> str:
        m = re.search(r'@([A-Za-z0-9\.\-]+)', s)
        return m.group(1).lower() if m else ""

    dom_from = _domain(fr)
    dom_rply = _domain(rp)
    if dom_from and dom_rply and dom_from != dom_rply:
        res["flags"].append(f"reply_to_mismatch:{dom_from}->{dom_rply}")
        res["risk"] += 0.25

    # SPF/DKIM/DMARC fail
    auth_low = auth.lower()
    if "spf=fail" in auth_low or "dkim=fail" in auth_low or "dmarc=fail" in auth_low:
        res["flags"].append("auth_fail")
        res["risk"] += 0.4

    # Subject mendesak
    if RE_URG.search(subj):
        res["flags"].append("urgent_subject")
        res["risk"] += 0.15

    # Rantai received terlalu panjang
    if len(received_all) >= 8:
        res["flags"].append("too_many_received")
        res["risk"] += 0.1

    res["risk"] = float(min(1.0, res["risk"]))
    return res

# ==========
# 4) API utama modul NLP
# ==========
def analyze_text_and_headers(text: str) -> Dict[str, Any]:
    """
    Return:
      {
        lang: 'id'|'en'|'unknown',
        nlp_score: 0..1 (phishing/social-engineering likelihood),
        rule_boost: 0..1,
        suspicious_sentences: [... top 3 ...],
        email_header: { risk:0..1, flags:[...] }
      }
    """
    text = text or ""
    lang = _lang_hint(text)
    # potong jadi kalimat sederhana
    sentences = re.split(r'[.\n\r;:!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) >= 6]

    scored = []
    for s in sentences:
        pm = _model_score(s)
        pr = _rule_score(s)
        scored.append((s, pm, pr, 0.6*pm + 0.4*pr))
    scored.sort(key=lambda x: x[3], reverse=True)
    top3 = [s for s,_,_,_ in scored[:3]]

    # skor keseluruhan (agregat)
    if scored:
        avg_pm = float(np.mean([pm for _,pm,_,_ in scored[:min(10,len(scored))]]))
        avg_pr = float(np.mean([pr for _,_,pr,_ in scored[:min(10,len(scored))]]))
        nlp_score = float(min(1.0, 0.6*avg_pm + 0.4*avg_pr))
        rule_boost = avg_pr
    else:
        nlp_score = 0.0
        rule_boost = 0.0

    # coba analisis header email (kalau ada struktur header di awal teks)
    header_block = "\n".join(sentences[:30])  # kasar: pakai bagian awal
    email_res = analyze_email_headers(header_block)

    # gabung risiko dengan header
    nlp_score = float(min(1.0, nlp_score*0.85 + email_res["risk"]*0.15))

    return {
        "lang": lang,
        "nlp_score": nlp_score,
        "rule_boost": rule_boost,
        "suspicious_sentences": top3,
        "email_header": email_res
    }
