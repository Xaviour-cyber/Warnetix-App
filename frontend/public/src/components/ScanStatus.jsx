import React from "react";

export default function ScanStatus({stats}){
  return (
    <div className="card">
      <h3>Scan Summary</h3>
      <div style={{display:"flex",gap:20,marginTop:12}}>
        <div>
          <div style={{fontSize:24,fontWeight:700}}>{stats.scanned || 0}</div>
          <div style={{color:"var(--muted)"}}>Files scanned</div>
        </div>
        <div>
          <div style={{fontSize:24,fontWeight:700,color:"var(--red)"}}>{stats.threats || 0}</div>
          <div style={{color:"var(--muted)"}}>Threats found</div>
        </div>
        <div>
          <div style={{fontSize:24,fontWeight:700}}>{stats.speed || "—"}</div>
          <div style={{color:"var(--muted)"}}>Files/s</div>
        </div>
      </div>
    </div>
  )
}
