# TODO: Implementasi Bahasa Indonesia untuk Warnetix

## Phase 1: Frontend React (Prioritas)
- [ ] Install dependencies: npm install react-i18next i18next i18next-browser-languagedetector
- [ ] Buat file konfigurasi i18n di frontend/public/src/i18n.js
- [ ] Buat folder translations dengan file id.json
- [ ] Update main.jsx untuk import konfigurasi i18n
- [ ] Update komponen berikut untuk menggunakan useTranslation():
  - [ ] Navbar.jsx
  - [ ] Dashboard.jsx
  - [ ] ScanStatus.jsx
  - [ ] UploadDropzone.jsx
  - [ ] ThreatTable.jsx
  - [ ] Settings.jsx
  - [ ] Logs.jsx
  - [ ] ScanControl.jsx
  - [ ] RealtimeWatch.jsx
  - [ ] Toast.jsx
  - [ ] ChartActivity.jsx

## Phase 2: Backend Flask
- [ ] Install Flask-Babel: pip install Flask-Babel
- [ ] Buat folder translations di backend/
- [ ] Setup Babel di app.py
- [ ] Buat file messages.po untuk bahasa Indonesia
- [ ] Update response messages di api.py dan scanner_api.py

## Phase 3: Agent C++
- [ ] Tambahkan field std::wstring language di AgentConfig
- [ ] Buat file string resource bahasa Indonesia
- [ ] Update log dan output messages untuk support multi-bahasa

## Phase 4: Testing & Dokumentasi
- [ ] Test perubahan bahasa di semua modul
- [ ] Buat panduan konfigurasi bahasa
- [ ] Update README.md dengan instruksi penggunaan bahasa Indonesia
