import React, { useEffect, useMemo, useRef, useState } from "react";
import { openEventStream, formatRelTime, classForSeverity, severityNorm, actionNorm } from "../api/api";

function Row({ ev, onClick }) {
  return (
    <tr onClick={() => onClick?.(ev)} style={{cursor:"pointer"}}>
      <td>{formatRelTime(ev.ts)}</td>
      <td title={ev.path}>{ev.filename}</td>
      <td>{ev.device || "-"}</td>
      <td><span className={classForSeverity(ev.severity)}>{severityNorm(ev.severity)}</span></td>
      <td>{actionNorm(ev.action)}</td>
      <td className="row" style={{gap:6}}>
        {ev.signature_hits?.length ? <span className="badge red">Signature Hit</span> : null}
        <span className="badge">{ev.source || "agent"}</span>
      </td>
    </tr>
  );
}

export default function RealtimeWatch() {
  const [items, setItems] = useState([]);
  const [paused, setPaused] = useState(false);
  const [detail, setDetail] = useState(null);
  const unsubRef = useRef(null);

  useEffect(() => {
    unsubRef.current = openEventStream((payload) => {
      if (payload?.type === "ping") return;

      if (paused) return;

      // payload dari /events/push, /scan-file, seed, dll → normalisasi minimal
      const ev = {
        id: payload.id || Math.random().toString(36).slice(2),
        ts: payload.ts || (Date.now()/1000),
        path: payload.path || payload.file || payload.filename || "-",
        filename: (payload.path || "").split(/[\\/]/).pop(),
        device: payload.agent?.hostname || payload.device_id || "",
        source: payload.source || (payload.agent ? "agent" : "upload"),
        severity: payload.severity || "low",
        action: payload.action || "simulate",
        signature_hits: payload.meta?.signature_hits || (payload.type === "signature_hit" ? [payload] : []),
        meta: payload.meta || {},
        sha256: payload.sha256,
        md5: payload.md5,
      };

      setItems(prev => {
        const next = [ev, ...prev];
        return next.slice(0, 200);
      });
    });

    return () => unsubRef.current?.();
  }, [paused]);

  return (
    <div className="card">
      <div className="toolbar">
        <h3>Realtime Watch</h3>
        <div className="row" style={{gap:8}}>
          <button className="btn" onClick={() => setPaused(p => !p)}>{paused ? "Resume" : "Pause"}</button>
          <button className="btn" onClick={() => setItems([])}>Clear</button>
        </div>
      </div>

      <div style={{maxHeight:420, overflow:"auto", borderRadius:12}}>
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>File</th>
              <th>Device</th>
              <th>Severity</th>
              <th>Action</th>
              <th>Tags</th>
            </tr>
          </thead>
          <tbody>
            {items.map(ev => <Row key={ev.id} ev={ev} onClick={setDetail}/>)}
          </tbody>
        </table>
      </div>

      {detail && (
        <>
          <div className="drawer-backdrop" onClick={()=>setDetail(null)} />
          <div className="drawer">
            <div className="toolbar">
              <h3>Detail</h3>
              <button className="btn" onClick={()=>setDetail(null)}>Close</button>
            </div>
            <div className="space" />
            <div className="row" style={{gap:8}}>
              <span className={classForSeverity(detail.severity)}>{severityNorm(detail.severity)}</span>
              <span className="badge">{detail.source}</span>
              {detail.signature_hits?.length ? <span className="badge red">Signature Hit</span> : null}
            </div>
            <div className="space" />
            <div className="muted">Path</div>
            <div className="code">{detail.path}</div>
            <div className="space" />
            <div className="grid cols-2">
              <div>
                <div className="muted">Device</div>
                <div>{detail.device || "-"}</div>
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

            {detail.signature_hits?.length ? (
              <>
                <div className="space" />
                <div className="muted">Signatures</div>
                <ul>
                  {detail.signature_hits.map((h, i) => (
                    <li key={i}>
                      <span className="badge red">Hit</span>&nbsp;
                      {h.provider || "db"} — {h.family || h.type || "unknown"}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </>
      )}
    </div>
  );
}
