import React, { useEffect, useMemo, useState } from "react";
import { fetchRecentEvents, formatRelTime, classForSeverity, severityNorm, actionNorm, extFromPath } from "../api/api";

export default function RecentTable() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [src, setSrc] = useState("all");
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    (async () => {
      const { items } = await fetchRecentEvents({ limit: 500 });
      setItems(items || []);
    })();
  }, []);

  const filtered = useMemo(() => {
    return (items || []).filter(ev => {
      const okQ = !q || (ev.path?.toLowerCase().includes(q.toLowerCase()) || ev.device_id?.toLowerCase().includes(q.toLowerCase()));
      const okSev = sev === "all" || severityNorm(ev.severity) === sev;
      const okSrc = src === "all" || (ev.source || "agent") === src;
      return okQ && okSev && okSrc;
    });
  }, [items, q, sev, src]);

  return (
    <div className="card">
      <div className="toolbar">
        <h3>Recent Events</h3>
        <div className="filters">
          <input className="input" placeholder="Cari nama file / device..." value={q} onChange={e=>setQ(e.target.value)} />
          <select className="select" value={sev} onChange={e=>setSev(e.target.value)}>
            <option value="all">All severity</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <select className="select" value={src} onChange={e=>setSrc(e.target.value)}>
            <option value="all">All source</option>
            <option value="agent">Agent</option>
            <option value="upload">Upload</option>
          </select>
        </div>
      </div>

      <div style={{maxHeight:480, overflow:"auto", borderRadius:12}}>
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>File</th>
              <th>Ext</th>
              <th>Device</th>
              <th>Severity</th>
              <th>Action</th>
              <th>Signatures</th>
            </tr>
          </thead>
          <tbody>
            {(filtered || []).map(ev => {
              const filename = (ev.path || "").split(/[\\/]/).pop();
              const ext = extFromPath(ev.path);
              const hits = ev.meta?.signature_hits?.length || 0;
              return (
                <tr key={ev.id} onClick={()=>setDetail(ev)} style={{cursor:"pointer"}}>
                  <td title={new Date((ev.ts||0)*1000).toISOString()}>{formatRelTime(ev.ts)}</td>
                  <td title={ev.path}>{filename || "-"}</td>
                  <td>{ext || "-"}</td>
                  <td>{ev.agent?.hostname || ev.device_id || "-"}</td>
                  <td><span className={classForSeverity(ev.severity)}>{severityNorm(ev.severity)}</span></td>
                  <td>{actionNorm(ev.action)}</td>
                  <td>{hits ? <span className="badge red">{hits} hit</span> : "-"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {detail && (
        <>
          <div className="drawer-backdrop" onClick={()=>setDetail(null)} />
          <div className="drawer">
            <div className="toolbar">
              <h3>Event Detail</h3>
              <button className="btn" onClick={()=>setDetail(null)}>Close</button>
            </div>
            <div className="space" />
            <div className="row" style={{gap:8}}>
              <span className={classForSeverity(detail.severity)}>{severityNorm(detail.severity)}</span>
              <span className="badge">{detail.source || "agent"}</span>
              {(detail.meta?.signature_hits?.length||0) > 0 && <span className="badge red">Signature Hit</span>}
            </div>
            <div className="space" />
            <div className="muted">Path</div>
            <div className="code">{detail.path}</div>
            <div className="space" />
            <div className="grid cols-2">
              <div>
                <div className="muted">Device</div>
                <div>{detail.agent?.hostname || detail.device_id || "-"}</div>
              </div>
              <div>
                <div className="muted">Action</div>
                <div>{actionNorm(detail.action)}</div>
              </div>
            </div>
            <div className="space" />
            <div className="muted">Hashes</div>
            <div className="code">MD5: {detail.md5 || "-"}</div>
            <div className="code">SHA-256: {detail.sha256 || "-"}</div>
            {(detail.meta?.signature_hits?.length||0) > 0 && (
              <>
                <div className="space" />
                <div className="muted">Signatures</div>
                <ul>
                  {detail.meta.signature_hits.map((h,i)=>(
                    <li key={i}><span className="badge red">Hit</span> {h.provider || "db"} — {h.family || h.type || "-"}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
