const BASE = (import.meta?.env?.VITE_API_BASE || "").replace(/\/+$/,"");

// Helper HTTP
async function _req(method, path, { json=null, file=null, headers={} } = {}) {
  const url = (BASE || "") + path;
  let body; const h = { ...headers };

  if (file) {
    const form = new FormData();
    form.append("file", file);
    body = form; // biarin boundary di-set otomatis
  } else if (json !== null) {
    h["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  const res = await fetch(url, { method, headers: h, body });
  if (!res.ok) {
    // coba baca pesan error dari server
    let msg = res.status + " " + res.statusText;
    try { const t = await res.text(); if (t) msg += " :: " + t.slice(0,400); } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}
const _get = (p)=>_req("GET", p);
const _post = (p,o)=>_req("POST", p, o);

// ==== SIGNATURES ====
export const getSignaturesVersion = ()=>_get("/api/signatures/version");
export const getSignaturesLatest  = ()=>_get("/api/signatures/latest");

// ==== HEALTH ====
export const health = ()=>_get("/health");
export const ready  = ()=>_get("/ready");

// ==== EVENTS / DASHBOARD ====
// Kompat: beberapa komponen mungkin pakai nama berbeda. Kita sediakan alias.
export async function getRecent(limit=100) {
  const paths = [
    `/api/events/recent?limit=${limit}`,
    `/api/events/latest?limit=${limit}`,
    `/api/events?limit=${limit}&sort=desc`
  ];
  let lastErr;
  for (const p of paths) {
    try { return await _get(p); } catch(e) { lastErr = e; }
  }
  throw lastErr || new Error("No recent events endpoint");
}

// Ringkasan severity (fallback multi endpoint)
export async function getSeveritySummary(period="24h") {
  const paths = [
    `/api/events/summary?bucket=severity&period=${period}`,
    `/api/events/severity?period=${period}`,
    `/api/summary/severity?period=${period}`
  ];
  for (const p of paths) { try { return await _get(p); } catch{} }
  // fallback: derive dari getRecent
  const rec = await getRecent(200);
  const agg = { critical:0, high:0, medium:0, low:0, info:0, unknown:0 };
  for (const ev of (rec?.items || rec || [])) {
    const s = String(ev.severity || "unknown").toLowerCase();
    agg[s] = (agg[s]||0)+1;
  }
  return agg;
}

export async function getKpis() {
  const paths = ["/api/kpis","/api/summary/kpis","/api/stats/kpis"];
  for (const p of paths) { try { return await _get(p); } catch{} }
  // fallback minimal
  const rec = await getRecent(200);
  return { total: (rec?.items?.length || rec?.length || 0) };
}

export async function getTimeSeries(granularity="minute", period="24h") {
  const paths = [
    `/api/events/timeseries?bucket=&period=${period}`,
    `/api/timeseries?bucket=&period=${period}`
  ];
  for (const p of paths) { try { return await _get(p); } catch{} }
  // fallback kosong
  return [];
}

export async function getThreats(limit=100) {
  const paths = [
    `/api/threats?limit=${limit}`,
    `/api/events/recent?limit=${limit}`
  ];
  for (const p of paths) { try { return await _get(p); } catch{} }
  return [];
}

// ==== SCAN ====
export async function uploadFile(file) {
  return _post("/api/scan", { file });
}
export const getScanStatus = ()=>_get("/api/scan/status");

// ==== Devices/Logs (opsional; biar komponen lain yang butuh nggak error) ====
export const getDevices = ()=>_get("/api/devices").catch(()=>[]);
export const getLogs    = (limit=200)=>_get(`/api/logs?limit=${limit}`).catch(()=>[]);

// ==== Alias (jaga kompatibilitas nama fungsi di komponen lain) ====
export const fetchRecent   = getRecent;
export const getEvents     = getRecent;
export const getActivity   = getTimeSeries;
export const getSeverity   = getSeveritySummary;
export const getRecentThreats = getThreats;

const api = {
  BASE, _req, _get, _post,
  health, ready,
  getSignaturesVersion, getSignaturesLatest,
  getRecent, fetchRecent, getEvents,
  getSeveritySummary, getSeverity,
  getKpis, getTimeSeries, getActivity,
  getThreats, getRecentThreats,
  uploadFile, getScanStatus,
  getDevices, getLogs
};
export default api;
