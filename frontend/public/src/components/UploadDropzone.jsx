import React, { useCallback, useMemo, useRef, useState } from "react";
import axios from "axios";
import clsx from "clsx";
// Jika react-icons sudah terpasang, ini aktif.
// Kalau belum, komponen tetap jalan—ikon akan fallback ke emoji.
let Icons = {};
try {
  // Feather + Simple Icons
  Icons = {
    FiUpload: (await import("react-icons/fi")).FiUpload,
    FiFile: (await import("react-icons/fi")).FiFile,
    FiShield: (await import("react-icons/fi")).FiShield,
    FiLink: (await import("react-icons/fi")).FiLink,
    FiTrash2: (await import("react-icons/fi")).FiTrash2,
    FiClock: (await import("react-icons/fi")).FiClock,
    SiVirustotal: (await import("react-icons/si")).SiVirustotal,
    FiActivity: (await import("react-icons/fi")).FiActivity,
    FiCpu: (await import("react-icons/fi")).FiCpu,
    FiAlertTriangle: (await import("react-icons/fi")).FiAlertTriangle,
    FiCheckCircle: (await import("react-icons/fi")).FiCheckCircle,
    FiXCircle: (await import("react-icons/fi")).FiXCircle,
  };
} catch { /* fallback emoji will be used */ }

// ---- API BASE ----
// Pastikan file ini sesuai dengan yang kamu pakai.
// Kalau sudah ada helper, kamu bisa impor dari ../api/api
const API_BASE =
  import.meta.env.VITE_API_BASE ||
  (window.__WARNETIX_API_BASE__ ?? "http://localhost:8000");

// ---- Helpers ----
const fmtBytes = (b = 0) => {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return `${(b / Math.pow(1024, i)).toFixed(2)} ${u[i]}`;
};

const severityToBadge = (sev) => {
  switch ((sev || "").toLowerCase()) {
    case "high":
      return "badge badge-high";
    case "medium":
      return "badge badge-mid";
    default:
      return "badge badge-low";
  }
};

const gradientFromScore = (score /* 0..100 */) => {
  // 0-35 green, 35-70 yellow/orange, 70-100 red
  let c1 = "#1fd65f";
  let c2 = "#7adf8d";
  if (score >= 35 && score < 70) {
    c1 = "#f3c221";
    c2 = "#ff9e2a";
  }
  if (score >= 70) {
    c1 = "#ff4d4d";
    c2 = "#cc0033";
  }
  return `linear-gradient(90deg, ${c1}, ${c2})`;
};

const vendorIcon = (vendor) => {
  const v = (vendor || "").toLowerCase();
  const I = Icons;
  if (v.includes("virustotal") || v === "vt") return I.SiVirustotal ? <I.SiVirustotal /> : "🧪";
  if (v.includes("ai") || v.includes("iforest")) return I.FiCpu ? <I.FiCpu /> : "🤖";
  if (v.includes("signature") || v.includes("sig")) return I.FiShield ? <I.FiShield /> : "🛡️";
  if (v.includes("entropy")) return I.FiActivity ? <I.FiActivity /> : "📈";
  if (v.includes("behavior")) return I.FiAlertTriangle ? <I.FiAlertTriangle /> : "⚠️";
  return I.FiFile ? <I.FiFile /> : "📄";
};

const ScoreChip = ({ score = 0, severity = "low" }) => {
  const style = { backgroundImage: gradientFromScore(score) };
  return (
    <div className="score-chip" style={style} title={`Threat Score: ${score}`}>
      <span className="score-chip__value">{score}</span>
      <span className={clsx("score-chip__sev", severityToBadge(severity))}>
        {severity.toUpperCase()}
      </span>
    </div>
  );
};

const VendorBadges = ({ detectedBy = [] }) => {
  if (!detectedBy || detectedBy.length === 0) return <span className="muted">—</span>;
  return (
    <div className="vendor-badges">
      {detectedBy.map((v, i) => (
        <div key={`${v.name}-${i}`} className={clsx("vendor-badge", v.positive ? "pos" : "neg")}>
          <span className="vendor-badge__icon">{vendorIcon(v.name)}</span>
          <span className="vendor-badge__name">{v.name}</span>
          <span className="vendor-badge__sig">{v.signature || "-"}</span>
        </div>
      ))}
    </div>
  );
};

const LoadingOverlay = ({ show = false, text = "Scanning…" }) => {
  if (!show) return null;
  const I = Icons;
  return (
    <div className="loading-overlay">
      <div className="loading-card">
        <div className="spinner-ctr">
          <div className="spinner-ring" />
        </div>
        <div className="loading-text">{text}</div>
        <div className="loading-sub">
          {I.FiClock ? <I.FiClock /> : "⏳"} Real‑time analysis • AI • VirusTotal • Signatures
        </div>
      </div>
    </div>
  );
};

const ResultRow = ({ r, onClear }) => {
  const I = Icons;
  const sev = (r?.severity || "low").toLowerCase();
  const statusIcon =
    sev === "high" ? (I.FiXCircle ? <I.FiXCircle /> : "❌")
      : sev === "medium" ? (I.FiAlertTriangle ? <I.FiAlertTriangle /> : "⚠️")
      : (I.FiCheckCircle ? <I.FiCheckCircle /> : "✅");

  return (
    <div className="result-row">
      <div className="result-meta">
        <div className="result-title">
          {Icons.FiFile ? <Icons.FiFile /> : "📄"} {r?.filename || r?.url || "Unknown"}
        </div>
        <div className="result-sub">
          {r?.file_size ? `${fmtBytes(r.file_size)} • ` : ""}
          {r?.mimetype || r?.content_type || "—"}
        </div>
      </div>

      <div className="result-score">
        <ScoreChip score={Math.round(r?.threat_score ?? 0)} severity={r?.severity || "low"} />
      </div>

      <div className="result-status">
        <span className={clsx("status", `sev-${sev}`)}>
          <span className="ico">{statusIcon}</span>
          <span className="txt">{(r?.status_label ?? "CLEAN").toUpperCase()}</span>
        </span>
      </div>

      <div className="result-vendors">
        <VendorBadges detectedBy={r?.detected_by || []} />
      </div>

      <div className="result-actions">
        <button className="btn ghost" onClick={onClear} title="Hapus hasil ini">
          {I.FiTrash2 ? <I.FiTrash2 /> : "🗑️"}
        </button>
      </div>
    </div>
  );
};

export default function UploadDropzone() {
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState([]);
  const [urlText, setUrlText] = useState("");
  const fileRef = useRef(null);

  const onBrowse = () => fileRef.current?.click();

  const onDrop = useCallback(async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const files = Array.from(e.dataTransfer?.files || []);
    if (!files.length) return;
    await scanFiles(files);
  }, []);

  const onDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") setDragOver(true);
    else setDragOver(false);
  };

  const scanFiles = async (files) => {
    setBusy(true);
    setProgress(0);
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const form = new FormData();
        form.append("file", f);
        const { data } = await axios.post(`${API_BASE}/scan-file?wait=true`, form, {
          headers: { "Content-Type": "multipart/form-data" },
          onUploadProgress: (pe) => {
            if (pe?.total) {
              const pct = Math.round((pe.loaded / pe.total) * 100);
              setProgress(pct);
            }
          },
        });

        const normalized = normalizeScanResponse(data, f.name, f.size);
        setResults((prev) => [normalized, ...prev]);
      }
    } catch (err) {
      console.error(err);
      alert(`Upload/scan gagal: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setBusy(false);
      setProgress(0);
    }
  };

  const scanURL = async () => {
    const url = urlText.trim();
    if (!url) return;
    setBusy(true);
    setProgress(0);
    try {
      const { data } = await axios.post(`${API_BASE}/scan-url`, { url });
      const normalized = normalizeScanResponse(data, url, 0, true);
      setResults((prev) => [normalized, ...prev]);
    } catch (err) {
      console.error(err);
      alert(`Scan URL gagal: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setBusy(false);
      setProgress(0);
    }
  };

  const clearOne = (idx) => setResults((prev) => prev.filter((_, i) => i !== idx));
  const clearAll = () => setResults([]);

  return (
    <div className="ud-root">
      <LoadingOverlay show={busy} text={progress ? `Uploading ${progress}%…` : "Scanning…"} />

      <div
        className={clsx("dropzone", dragOver && "over")}
        onDrop={onDrop}
        onDragEnter={onDrag}
        onDragOver={onDrag}
        onDragLeave={onDrag}
      >
        <div className="dz-inner">
          <div className="dz-icon">{Icons.FiUpload ? <Icons.FiUpload /> : "📤"}</div>
          <div className="dz-title">Drag & Drop file kamu di sini</div>
          <div className="dz-sub">atau</div>
          <button className="btn primary" onClick={onBrowse}>
            Pilih File
          </button>
          <input
            ref={fileRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              const files = Array.from(e.target.files || []);
              if (files.length) scanFiles(files);
              e.target.value = "";
            }}
          />
        </div>
      </div>

      <div className="or-divider">
        <span>ATAU SCAN URL</span>
      </div>

      <div className="url-box">
        <div className="url-ico">{Icons.FiLink ? <Icons.FiLink /> : "🔗"}</div>
        <input
          type="text"
          placeholder="https://contoh-domain.com/unduhan.exe"
          value={urlText}
          onChange={(e) => setUrlText(e.target.value)}
        />
        <button className="btn" onClick={scanURL}>
          Scan URL
        </button>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div className="panel-title">
            {Icons.FiShield ? <Icons.FiShield /> : "🛡️"} Hasil Pemindaian
          </div>
          <div className="panel-actions">
            <button className="btn ghost" onClick={clearAll} title="Bersihkan semua hasil">Bersihkan</button>
          </div>
        </div>

        {results.length === 0 ? (
          <div className="empty">
            Belum ada hasil. Unggah file atau masukkan URL untuk memulai scan.
          </div>
        ) : (
          <div className="result-list">
            {results.map((r, idx) => (
              <ResultRow key={idx} r={r} onClear={() => clearOne(idx)} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---- Normalisasi respons backend agar UI konsisten ----
function normalizeScanResponse(data, name, size, isURL = false) {
  // Backend (api.py / scanner_api.py) kita sudah format begini:
  // {
  //   item_type: "file"|"url",
  //   filename/url, file_size, mimetype/content_type,
  //   threat_score: 0..100, severity: "low|medium|high", status_label,
  //   detected_by: [{name, signature, positive, score}],
  //   vt_link (opsional)
  // }
  const d = data?.data || data || {};
  const base = {
    filename: isURL ? undefined : (d.filename || name),
    url: isURL ? (d.url || name) : undefined,
    file_size: d.file_size ?? size,
    mimetype: d.mimetype,
    content_type: d.content_type,
    threat_score: d.threat_score ?? 0,
    severity: d.severity ?? "low",
    status_label: d.status_label ?? (d.severity === "high" ? "BLOCKED" : "CLEAN"),
    detected_by: d.detected_by || [],
    vt_link: d.vt_link,
  };

  // Safety net: kalau backend kasih fields lain (entropy, etc) bisa ikut dipakai nanti.
  return { ...base, ...d };
}
