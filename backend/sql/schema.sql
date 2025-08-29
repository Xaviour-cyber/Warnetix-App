-- ===== SQLite baseline =====
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

-- ===== Tabel perangkat (agent) =====
CREATE TABLE IF NOT EXISTS devices (
  id          TEXT PRIMARY KEY,            -- "dev-xav", UUID, dsb
  name        TEXT,                        -- hostname tampilan
  os          TEXT,                        -- "Windows", "Linux", "macOS"
  arch        TEXT,                        -- "x64", "arm64", ...
  version     TEXT,                        -- versi agent (opsional)
  last_seen   INTEGER,                     -- epoch seconds
  meta_json   TEXT                         -- JSON bebas (info tambahan)
);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);

-- ===== Tabel events (hasil scan / push) =====
-- Catatan:
--  - Simpan sebagian kolom eksplisit agar query cepat (path, size, sha256, severity, action)
--  - Simpan juga JSON mentah (agent_json, meta_json, details_json) untuk fleksibilitas
CREATE TABLE IF NOT EXISTS events (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,                 -- epoch seconds
  type         TEXT NOT NULL,                    -- 'fast_event' | 'scan_result' | 'vt_update' (ringkas)
  source       TEXT NOT NULL,                    -- 'agent' | 'api'
  device_id    TEXT,                             -- FK -> devices.id (boleh NULL kalau upload manual)
  path         TEXT,                             -- path/nama file (as-sent)
  filename     TEXT,                             -- basename dari path
  ext          TEXT,                             -- ekstensi lower (tanpa titik)
  category     TEXT,                             -- 'document' | 'image' | 'archive' | 'executable' | ...
  size         INTEGER,                          -- bytes (as seen by agent/back)
  sha256       TEXT,                             -- hash konten (kalau ada)
  mime         TEXT,                             -- mime guess (opsional)
  severity     TEXT CHECK (severity IN ('low','medium','high','critical') OR severity IS NULL),
  action       TEXT CHECK (action IN ('simulate','allow','quarantine','delete','ignore') OR action IS NULL),
  vt_vendors   INTEGER,                          -- berapa engine total (opsional ringkasan VT)
  vt_malicious INTEGER,                          -- vendor yang flag malicious
  vt_suspicious INTEGER,                         -- vendor yang flag suspicious
  quarantine_path TEXT,                          -- kalau di-quarantine
  agent_json   TEXT,                             -- JSON: {id,hostname,os, ...} as-sent
  meta_json    TEXT,                             -- JSON: {reason, ...} atau info tambahan lain
  details_json TEXT,                             -- JSON: hasil heuristik/parser, dsb
  CONSTRAINT fk_events_device
    FOREIGN KEY (device_id) REFERENCES devices(id) ON UPDATE CASCADE ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_device    ON events(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sha256    ON events(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity) WHERE severity IS NOT NULL;

-- ===== Cache VirusTotal (hash-only) =====
CREATE TABLE IF NOT EXISTS vt_cache (
  sha256        TEXT PRIMARY KEY,
  vendors       INTEGER,
  malicious     INTEGER,
  suspicious    INTEGER,
  undetected    INTEGER,
  last_checked  INTEGER,                 -- epoch seconds
  raw_json      TEXT                     -- respons mentah (opsional, untuk audit)
);

-- ===== View util =====

-- Recent (kolom umum untuk tabel UI)
CREATE VIEW IF NOT EXISTS v_events_recent AS
SELECT
  id, ts, type, source, device_id,
  filename, ext, category, size, sha256,
  severity, action, vt_malicious, vt_vendors,
  json_extract(agent_json,'$.hostname') AS hostname,
  json_extract(agent_json,'$.os')       AS os,
  path
FROM events
ORDER BY ts DESC;

-- Timeseries per menit (bucket 60s)
CREATE VIEW IF NOT EXISTS v_events_minute AS
SELECT
  strftime('%Y-%m-%d %H:%M:00', datetime(ts, 'unixepoch')) AS bucket_minute,
  COUNT(*) AS total,
  SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) AS high_or_critical,
  SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
  SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high,
  SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) AS medium
FROM events
GROUP BY 1
ORDER BY 1 DESC;

-- ===== Trigger util =====
-- Update last_seen device setiap insert event
CREATE TRIGGER IF NOT EXISTS trg_events_touch_device
AFTER INSERT ON events
WHEN NEW.device_id IS NOT NULL
BEGIN
  UPDATE devices SET last_seen = NEW.ts WHERE id = NEW.device_id;
END;

-- SIGNATURE STORE (hash blacklist offline; sha256 ATAU md5 boleh)
CREATE TABLE IF NOT EXISTS signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT,                 -- boleh NULL
  md5    TEXT,                 -- boleh NULL
  threat_family TEXT,          -- ex: "LockBit", "AgentTesla", ...
  threat_type   TEXT,          -- ex: "ransomware" | "malware" | "phishing"
  severity      TEXT CHECK (severity IN ('low','medium','high','critical')) DEFAULT 'high',
  source        TEXT,          -- "malwarebazaar" | "kaggle" | "manual"
  first_seen    INTEGER,       -- epoch (optional)
  last_seen     INTEGER,       -- epoch (optional)
  meta_json     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sig_sha256 ON signatures(sha256);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sig_md5    ON signatures(md5);
CREATE INDEX IF NOT EXISTS idx_sig_family       ON signatures(threat_family);
