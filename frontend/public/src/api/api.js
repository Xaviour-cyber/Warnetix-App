// Lightweight API wrapper utk Warnetix Frontend
const API_BASE = import.meta.env.VITE_API_BASE || window.__API_BASE__ || '';
export const api = (path) => `${API_BASE}${path}`;   // contoh pemakaian

function qs(params = {}) {
  const s = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    s.set(k, String(v));
  });
  const q = s.toString();
  return q ? `?${q}` : "";
}

async function getJSON(path, params) {
  const res = await fetch(`${API_BASE}${path}${qs(params)}`);
  if (!res.ok) throw new Error(`GET ${path} ${res.status}`);
  return res.json();
}

async function postJSON(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error(`POST ${path} ${res.status}`);
  return res.json();
}

export function fetchRecentEvents({ limit = 200, offset = 0 } = {}) {
  return getJSON("/events/recent", { limit, offset });
}
export function fetchTimeSeries({ window = "24h", bucket = "1h" } = {}) {
  return getJSON("/stats/timeseries", { window, bucket });
}
export function fetchDevices() {
  return getJSON("/devices");
}
export function pushEvent(ev) {
  return postJSON("/events/push", ev);
}
export function scanPath(path) {
  return postJSON("/scan-path", { path });
}
export function scanFileForm(file) {
  const fd = new FormData();
  fd.append("file", file);
  return fetch(`${API_BASE}/scan-file`, { method: "POST", body: fd }).then(r => r.json());
}

// SSE stream helper
export function openEventStream(onEvent) {
  const es = new EventSource(`${API_BASE}/events/stream`);
  es.addEventListener("ping", () => onEvent?.({ type: "ping" }));
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      onEvent?.(data);
    } catch { /* ignore */ }
  };
  es.onerror = () => { /* auto-reconnect by browser */ };
  return () => es.close();
}

// ===== utils formatting =====
export function formatRelTime(tsSec) {
  const ms = (typeof tsSec === "number" ? tsSec * 1000 : Date.parse(tsSec));
  const diff = Date.now() - ms;
  const abs = Math.max(0, diff);
  const m = Math.floor(abs / 60000);
  if (m < 1) return "baru saja";
  if (m < 60) return `${m}m lalu`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}j lalu`;
  const d = Math.floor(h / 24);
  return `${d}h lalu`;
}
export function bytesHuman(n) {
  if (!n && n !== 0) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, x = n;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(1)} ${u[i]}`;
}
export function severityNorm(s) {
  const v = String(s || "low").toLowerCase();
  return ["low", "medium", "high", "critical"].includes(v) ? v : "low";
}
export function actionNorm(a) {
  return (a || "simulate").toLowerCase();
}
export function extFromPath(p = "") {
  const i = p.lastIndexOf(".");
  return i >= 0 ? p.slice(i + 1).toLowerCase() : "";
}
export function classForSeverity(s) {
  return `pill ${severityNorm(s)}`;
}
