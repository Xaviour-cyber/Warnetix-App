import React from "react";

export default function ScanControl({onStart, onStop, scanning}){
  return (
    <div style={{display:"flex",gap:12,alignItems:"center"}}>
      <button className="btn" onClick={onStart} disabled={scanning}>🚀 Start Scan</button>
      <button className="btn ghost" onClick={onStop} disabled={!scanning}>⛔ Stop</button>
      <div style={{marginLeft:12,color:"var(--muted)"}}>
        Status: <strong style={{color:scanning?"var(--red)":"var(--muted)"}}>{scanning ? "Scanning" : "Idle"}</strong>
      </div>
    </div>
  );
}