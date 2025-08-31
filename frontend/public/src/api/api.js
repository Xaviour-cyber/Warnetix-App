// ==== Base URL (Vite) ====
// dukung 2 nama env biar fleksibel
export const API_BASE =
  (import.meta?.env?.VITE_API_BASE ||
   import.meta?.env?.VITE_API_BASE_URL ||
   "").replace(/\/+$/,"");

// ---- core fetchers ----
async function _req(method, path, { json=null, file=null, headers={}, signal } = {}) {
  const url = (API_BASE || "") + path;
  const h = { ...headers }; let body;

  if (file) { const fd = new FormData(); fd.append("file", file); body = fd; }
  else if (json !== null) { h["Content-Type"] = "application/json"; body = JSON.stringify(json); }

  const res = await fetch(url, { method, headers: h, body, signal, cache:"no-store" });
  const ct = res.headers.get("content-type") || "";
  const parse = async () => ct.includes("application/json") ? res.json() : res.text();

  if (!res.ok) {
    let payload; try { payload = await parse(); } catch { payload = await res.text().catch(()=> ""); }
    const e = new Error(`${res.status} ${res.statusText}`);
    e.status = res.status; e.data = payload; throw e;
  }
  return parse();
}
const _get  = (p, o)=>_req("GET",  p, o);
const _post = (p, o)=>_req("POST", p, o);

// ---- public API ----
export const health = () => _get("/health");
export const ready  = () => _get("/ready").catch(()=>({ready:false}));

export async function scanText(text){
  const paths = ["/scan-text", "/api/scan-text", "/scan"];
  let lastErr;
  for (const p of paths){ try { return await _post(p, { json:{ text } }); } catch(e){ lastErr = e; } }
  throw lastErr || new Error("scanText endpoints not available");
}

export async function uploadFile(file){
  const paths = ["/api/scan", "/scan-file", "/scan", "/api/scan-file"];
  let lastErr;
  for (const p of paths){ try { return await _post(p, { file }); } catch(e){ lastErr = e; } }
  throw lastErr || new Error("upload endpoints not available");
}

// getRecent → selalu pulang {items:[...]}
export async function getRecent(limit=100){
  const paths = [
    `/api/events/recent?limit=${limit}`,
    `/api/events/latest?limit=${limit}`,
    `/api/events?limit=${limit}&sort=desc`
  ];
  let lastErr;
  for (const p of paths){
    try {
      const j = await _get(p);
      if (Array.isArray(j)) return { items: j };
      if (j && Array.isArray(j.items)) return j;
      if (j && Array.isArray(j.data))  return { items: j.data };
      return { items: [] };
    } catch(e){ lastErr = e; }
  }
  if (lastErr) throw lastErr;
  return { items: [] };
}

// fetchRecentEvents({limit}) → dipakai RecentTable.jsx
export async function fetchRecentEvents({ limit=500 } = {}) {
  return getRecent(limit);
}

export async function getDevices(){
  const j = await _get("/api/devices").catch(()=>({}));
  if (Array.isArray(j)) return { items: j };
  return j?.items ? j : { items: [] };
}

export async function getLogs(limit=200){
  const j = await _get(`/api/logs?limit=${limit}`).catch(()=>({}));
  if (Array.isArray(j)) return { items: j };
  return j?.items ? j : { items: [] };
}

// timeseries (native kalau ada, fallback derive dari recent)
export async function getTimeseries(startSec, endSec, bucket="hour"){
  const qs = `start=${startSec}&end=${endSec}&bucket=${bucket}`;
  const paths = [`/api/events/timeseries?${qs}`, `/api/timeseries?${qs}`];
  for (const p of paths){
    try {
      const j = await _get(p);
      if (j?.series) return j;
      if (Array.isArray(j)) return { series: j };
    } catch {}
  }
  // derive fallback
  const { items } = await getRecent(1000);
  const bucketSec = bucket==="min" ? 60 : bucket==="day" ? 86400 : 3600;
  const seriesMap = new Map();
  for (const ev of items) {
    const ts = ev.ts || ev.data?.ts || Math.floor(Date.now()/1000);
    if (ts < startSec || ts > endSec) continue;
    const bin = Math.floor(ts / bucketSec) * bucketSec;
    const cur = seriesMap.get(bin) || { t: bin, count:0, high:0, critical:0 };
    const sev = String(ev.data?.severity || ev.severity || "low").toLowerCase();
    cur.count += 1;
    if (sev === "high") cur.high += 1;
    if (sev === "critical") cur.critical += 1;
    seriesMap.set(bin, cur);
  }
  const series = [...seriesMap.values()].sort((a,b)=>a.t-b.t);
  return { series };
}

// SSE realtime + fallback polling
export function openEventStream(onMessage){
  if (typeof EventSource !== "undefined" && API_BASE) {
    const paths = ["/api/events/stream", "/events/stream", "/events/sse", "/api/sse"];
    for (const p of paths){
      try {
        const es = new EventSource(API_BASE + p);
        es.onmessage = (ev)=>{
          if (!ev?.data) return;
          let payload; try { payload = JSON.parse(ev.data); } catch { payload = { type:"text", data: ev.data }; }
          onMessage?.(payload);
        };
        es.onerror = ()=>{ /* biarin browser reconnect */ };
        return ()=> es.close();
      } catch {}
    }
  }
  // polling fallback
  let stopped = false; let lastTs = 0;
  const tick = async()=>{
    if (stopped) return;
    try{
      const { items } = await getRecent(50);
      const fresh = items.filter(i => (i.ts||0) > lastTs).sort((a,b)=>(a.ts||0)-(b.ts||0));
      fresh.forEach(onMessage);
      lastTs = Math.max(lastTs, ...items.map(i=>i.ts||0));
    } catch {}
    setTimeout(tick, 3000);
  };
  tick();
  return ()=>{ stopped = true; };
}

// ===== helpers =====
export function severityNorm(s){
  const v = String(s||"low").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v.startsWith("hi"))   return "high";
  if (v.startsWith("med"))  return "medium";
  return "low";
}
export function classForSeverity(s){
  const v = severityNorm(s);
  return `sev sev-${v}`;
}
export function actionNorm(a){
  const v = String(a||"").toLowerCase();
  if (["block","blocked","deny","drop"].includes(v)) return "blocked";
  if (["quarantine","isolate"].includes(v)) return "quarantine";
  if (["delete","removed"].includes(v)) return "delete";
  if (["allow","permit"].includes(v)) return "allow";
  return v || "simulate";
}
export function formatRelTime(ts){
  const t = Number(ts||0)*1000;
  if (!t) return "-";
  const d = Date.now() - t;
  const m = Math.round(d/60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m/60);
  if (h < 24) return `${h}h ago`;
  const dd = Math.round(h/24);
  return `${dd}d ago`;
}
export function extFromPath(p){
  if (!p) return "";
  const name = String(p).split(/[\\/]/).pop() || "";
  const m = /\.([A-Za-z0-9]+)$/.exec(name);
  return m ? m[1].toLowerCase() : "";
}

// ---- aliases supaya cocok dengan pages yang sudah ada ----
export const getEvents = getRecent;
export const fetchRecent = getRecent;
export const fetchDevices = getDevices;

// Wrapper: { window:"24h", bucket:"1h" } -> panggil getTimeseries(...)
export async function fetchTimeSeries({ window = "24h", bucket = "1h" } = {}) {
  const nowSec = Math.floor(Date.now() / 1000);
  const win = String(window).toLowerCase();
  const durSec =
    win.endsWith("h") ? parseInt(win) * 3600 :
    win.endsWith("d") ? parseInt(win) * 86400 : 24 * 3600; // default 24h
  const start = nowSec - durSec;
  const end = nowSec;
  const b = String(bucket).toLowerCase();
  const normBucket =
    /^(1m|min|minute|minutes)$/.test(b) ? "min" :
    /^(1h|hour|hours|60m)$/.test(b) ? "hour" : "day";

  const ts = await getTimeseries(start, end, normBucket);
  const items = (ts?.series || []).map(p => ({
    label: p.label ? p.label : fmtLabel(p.t),
    total: p.total ?? p.count ?? 0,
    high:  p.high  ?? 0,
    critical: p.critical ?? 0,
    ts: p.t ?? null
  }));
  return { items };
}
function fmtLabel(t){ const ms = (t>1e12?t:t*1000); const d=new Date(ms);
  const hh=String(d.getHours()).padStart(2,"0"); const mm=String(d.getMinutes()).padStart(2,"0");
  return `${hh}:${mm}`; }

export default {
  API_BASE, _req, _get, _post,
  health, ready, scanText, uploadFile,
  getRecent, getEvents, fetchRecent, fetchRecentEvents,
  getDevices, fetchDevices, getLogs, getTimeseries, fetchTimeSeries,
  openEventStream,
  severityNorm, classForSeverity, actionNorm, formatRelTime, extFromPath
};
