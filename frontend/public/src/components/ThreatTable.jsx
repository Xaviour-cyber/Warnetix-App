import { useEffect, useState } from "react";
import { getRecent } from "../api/api";

function SevPill({ sev }) {
  const color = sev === "critical" ? "#e11d48"
    : sev === "high" ? "#f59e0b"
    : sev === "medium" ? "#3b82f6"
    : "#10b981";
  return <span style={{background: color, color:"#fff", padding:"2px 8px", borderRadius:12, fontSize:12}}>{sev||"low"}</span>;
}

export default function ThreatTable() {
  const [rows, setRows] = useState([]);

  async function load() {
    const j = await getRecent(200);
    setRows(j.items || []);
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="card">
      <h3>Recent Events</h3>
      <table style={{width:"100%", fontSize:13}}>
        <thead>
          <tr><th style={{textAlign:"left"}}>Time</th><th>Type</th><th>Severity</th><th>Path/Name</th><th>Source</th></tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const d = r.data || r; // fallback kalau DB wrapper udah parse
            const sev = (d.severity || "low").toLowerCase();
            const name = d.result?.name || d.path || d.meta?.name || "-";
            const ts = new Date((r.ts||d.ts||Date.now())*1000).toLocaleString();
            return (
              <tr key={r.id || `${d.type}-${ts}-${name}`}>
                <td>{ts}</td>
                <td>{d.type || r.type}</td>
                <td><SevPill sev={sev} /></td>
                <td style={{maxWidth:380, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}} title={name}>{name}</td>
                <td>{d.source || "backend"}</td>
              </tr>
            );
          })}
          {rows.length===0 && <tr><td colSpan={5}>Belum ada data</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
