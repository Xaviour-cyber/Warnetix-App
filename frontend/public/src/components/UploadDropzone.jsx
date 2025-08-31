import React, { useCallback, useRef, useState } from "react";
import { API_BASE, uploadFile } from "../api/api";
import { toast } from "./Toast";
import { FiUpload, FiLink, FiCheckCircle, FiAlertTriangle, FiX } from "react-icons/fi";

function prettyBytes(b){
  if (b === 0) return "0 B";
  if (!b && b !== 0) return "-";
  const u = ["B","KB","MB","GB","TB"];
  let i = 0; while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(1)} ${u[i]}`;
}
function sevNorm(s){
  const v = String(s || "low").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v.startsWith("hi"))   return "high";
  if (v.startsWith("med"))  return "medium";
  return "low";
}
function sevLabel(s){ const v = sevNorm(s); return v.charAt(0).toUpperCase()+v.slice(1); }
function sevClass(s){
  const v = sevNorm(s);
  if (v === "critical") return "sev sev-critical";
  if (v === "high")     return "sev sev-high";
  if (v === "medium")   return "sev sev-medium";
  return "sev sev-low";
}
function scoreClass(score){
  const n = Number(score ?? 0);
  if (n >= 80) return "score-chip badge-high";
  if (n >= 50) return "score-chip badge-mid";
  return "score-chip badge-low";
}

async function scanUrlApi(url){
  const endpoints = ["/scan-url", "/api/scan-url"];
  let lastErr;
  for (const p of endpoints){
    try{
      const r = await fetch((API_BASE || "") + p, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const ct = r.headers.get("content-type") || "";
      const data = ct.includes("application/json") ? await r.json() : await r.text();
      if (!r.ok) throw new Error(typeof data === "string" ? data : (data?.error || r.statusText));
      return data;
    }catch(e){ lastErr = e; }
  }
  throw lastErr || new Error("scan-url endpoint not available");
}

export default function UploadDropzone({
  accept = "*",
  multiple = false,
  onUploaded,
  maxItems = 50
}){
  const inputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);
  const [progress, setProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState("");
  const [results, setResults] = useState([]);

  const addResult = useCallback((res)=>{
    setResults(prev => [res, ...prev].slice(0, maxItems));
  }, [maxItems]);

  const doUploadOne = useCallback(async (file)=>{
    if (!file) return;
    setBusy(true);
    setProgress(5);
    try{
      const res = await uploadFile(file); // api.js: fallback /api/scan | /scan-file | /scan | /api/scan-file
      setProgress(100);
      addResult({
        kind: "file",
        name: file.name,
        size: file.size,
        sha256: res?.target?.sha256 || res?.sha256,
        severity: res?.severity || res?.data?.severity,
        score: res?.score,
        vendor_results: res?.vendor_results || res?.vendors || [],
        raw: res
      });
      toast.success("File uploaded & scanned");
      onUploaded?.(res);
    }catch(e){
      toast.error("Upload gagal: " + (e?.message || "unknown"));
    }finally{
      setTimeout(()=> setProgress(0), 300);
      setBusy(false);
    }
  }, [addResult, onUploaded]);

  const doUploadInput = useCallback(async (e)=>{
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    if (!multiple) return doUploadOne(files[0]);
    for (const f of files) { // sequential biar progress jelas
      /* eslint-disable no-await-in-loop */
      await doUploadOne(f);
    }
  }, [multiple, doUploadOne]);

  const onDrop = useCallback(async (e)=>{
    e.preventDefault(); setDragOver(false);
    const files = Array.from(e.dataTransfer.files || []);
    if (!files.length) return toast.info("Gak ada file.");
    if (!multiple) return doUploadOne(files[0]);
    for (const f of files) { await doUploadOne(f); }
  }, [multiple, doUploadOne]);

  const onDrag = useCallback((e)=>{
    e.preventDefault();
    if (e.type === "dragenter" || e.type === "dragover") setDragOver(true);
    if (e.type === "dragleave") setDragOver(false);
  }, []);

  const handleScanUrl = useCallback(async ()=>{
    if (!url.trim()) return toast.info("Masukkan URL dulu.");
    setBusy(true);
    try{
      const res = await scanUrlApi(url.trim());
      addResult({
        kind: "url",
        url: url.trim(),
        severity: res?.severity || res?.data?.severity,
        score: res?.score,
        vendor_results: res?.vendor_results || res?.vendors || [],
        raw: res
      });
      toast.success("URL scanned");
      onUploaded?.(res);
    }catch(e){
      toast.error("Scan URL gagal: " + (e?.message || "unknown"));
    }finally{
      setBusy(false);
    }
  }, [url, addResult, onUploaded]);

  return (
    <div className="ud-root">
      {/* Dropzone */}
      <div
        className={`dropzone ${dragOver ? "over" : ""}`}
        onDragEnter={onDrag}
        onDragOver={onDrag}
        onDragLeave={onDrag}
        onDrop={onDrop}
      >
        <div className="dz-inner">
          <div className="dz-title"><FiUpload/> Tarik & letakkan file di sini</div>
          <div className="dim">atau</div>
          <div>
            <button
              className="ghost"
              onClick={()=> inputRef.current?.click()}
              disabled={busy}
            >
              Pilih File
            </button>
            <input
              ref={inputRef}
              className="hidden"
              type="file"
              accept={accept}
              multiple={multiple}
              onChange={doUploadInput}
            />
          </div>
          {progress > 0 && (
            <div style={{width:"100%", marginTop: 8}}>
              <progress value={progress} max={100} style={{width:"100%"}} />
            </div>
          )}
        </div>
      </div>

      {/* URL Scan */}
      <div className="url-box">
        <FiLink/>
        <input
          type="text"
          placeholder="https://contoh.com/sample.exe"
          value={url}
          onChange={(e)=>setUrl(e.target.value)}
        />
        <button onClick={handleScanUrl} disabled={busy}>Scan URL</button>
      </div>

      {/* Hasil */}
      <div className="panel">
        <div className="panel-head">
          <div className="panel-title">
            <FiCheckCircle/> Hasil Scan
          </div>
          <div className="panel-actions">
            <button className="ghost" onClick={()=>setResults([])} disabled={!results.length}>
              <FiX/> Bersihkan
            </button>
          </div>
        </div>

        <div className="result-list">
          {!results.length && <div className="dim">Belum ada hasil.</div>}

          {results.map((r, idx)=>{
            const title = r.kind === "url" ? (r.url || "URL") : (r.name || "File");
            const sub = r.kind === "url"
              ? "URL"
              : `${prettyBytes(r.size)}${r.sha256 ? ` • ${r.sha256.slice(0,12)}…` : ""}`;
            const sev = sevNorm(r.severity);
            const vendors = Array.isArray(r.vendor_results) ? r.vendor_results : [];
            const s = Number(r.score ?? 0);

            return (
              <div className="result-row" key={idx}>
                <div>
                  <div className="result-title">{title}</div>
                  <div className="result-sub">{sub}</div>
                </div>

                <div className={sevClass(sev)}>{sevLabel(sev)}</div>

                <div className={scoreClass(s)}>
                  <span className="score-chip__value">{isNaN(s)? "-" : s}</span>
                  <span className="score-chip__sev">{sevLabel(sev)}</span>
                </div>

                <div className="vendor-badges">
                  {vendors.length === 0 && <span className="dim">No vendor data</span>}
                  {vendors.map((v,i)=>{
                    const mal = v.malicious || /(mal|trojan|virus|risk|suspect|danger)/i.test(String(v.result||""));
                    return (
                      <span className={`vendor-badge ${mal ? "neg" : "pos"}`} key={i} title={v.result || ""}>
                        {mal ? <FiAlertTriangle/> : <FiCheckCircle/>}
                        <span>{v.engine || v.name || "engine"}</span>
                      </span>
                    );
                  })}
                </div>

                <div style={{justifySelf:"end"}}>
                  {r.raw?.created_event_id && (
                    <span className="badge">evt: {String(r.raw.created_event_id).slice(0,8)}…</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Overlay loading kecil (ketika busy upload/scan) */}
      {busy && (
        <div className="loading-overlay">
          <div className="loading-card">
            <div className="spinner-ctr"><div className="spinner-ring"/></div>
            Memproses…
          </div>
        </div>
      )}
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
