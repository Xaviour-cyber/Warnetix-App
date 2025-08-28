import React, { useEffect, useMemo, useState } from "react";
import { fetchRecentEvents, fetchDevices, fetchTimeSeries, severityNorm } from "../api/api";
import SeverityDonut from "../components/SeverityDonut";
import TimeSeries from "../components/TimeSeries";

export default function Dashboard() {
  const [recent, setRecent] = useState([]);
  const [devices, setDevices] = useState([]);
  const [series, setSeries] = useState([]);

  useEffect(() => {
    (async () => {
      const r = await fetchRecentEvents({ limit: 1000 });
      setRecent(r.items || []);
      const d = await fetchDevices();
      setDevices(d.items || []);
      const ts = await fetchTimeSeries({ window: "24h", bucket: "1h" });
      // backend mengembalikan bins; adapt jadi {label,total,high,critical}
      const mapped = (ts.items || ts.bins || []).map(b => ({
        label: b.label || new Date((b.ts||0)*1000).toLocaleTimeString(),
        total: b.total || (b.count || 0),
        high: b.high || 0,
        critical: b.critical || 0
      }));
      setSeries(mapped);
    })();
  }, []);

  const kpi = useMemo(() => {
    const last24 = recent;
    const sevCounts = { low:0, medium:0, high:0, critical:0 };
    let sigHits = 0;
    last24.forEach(e=>{
      sevCounts[severityNorm(e.severity)]++;
      if (e.meta?.signature_hits?.length) sigHits += e.meta.signature_hits.length;
    });
    const highCrit = sevCounts.high + sevCounts.critical;
    const activeDevices = new Set(last24.map(e => e.device_id || e.agent?.hostname)).size;
    return { sevCounts, sigHits, highCrit, activeDevices, total:last24.length };
  }, [recent]);

  // top extensions
  const topExt = useMemo(() => {
    const map = new Map();
    recent.forEach(e=>{
      const p = e.path || "";
      const i = p.lastIndexOf(".");
      const ext = i>=0 ? p.slice(i+1).toLowerCase() : "";
      if (!ext) return;
      map.set(ext, (map.get(ext)||0)+1);
    });
    return [...map.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8);
  }, [recent]);

  return (
    <div className="page">
      <div className="grid cols-3">
        <div className="card kpi">
          <div>
            <div className="hint">Events (24h)</div>
            <div className="num">{kpi.total}</div>
          </div>
        </div>
        <div className="card kpi">
          <div>
            <div className="hint">High / Critical (24h)</div>
            <div className="num" style={{color:"var(--crit)"}}>{kpi.highCrit}</div>
          </div>
        </div>
        <div className="card kpi">
          <div>
            <div className="hint">Devices Aktif</div>
            <div className="num">{kpi.activeDevices}</div>
          </div>
        </div>
      </div>

      <div className="space-lg" />

      <div className="grid cols-2">
        <SeverityDonut counts={kpi.sevCounts} />
        <TimeSeries series={series} />
      </div>

      <div className="space-lg" />

      <div className="card">
        <h3>Top Extensions (24h)</h3>
        <div className="row" style={{gap:8,flexWrap:"wrap"}}>
          {topExt.map(([ext, n])=>(
            <span key={ext} className="badge">{ext} • {n}</span>
          ))}
          {topExt.length===0 && <div className="muted">Belum ada data</div>}
        </div>
      </div>
    </div>
  );
}
