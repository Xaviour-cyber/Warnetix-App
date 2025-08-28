import { useEffect, useState } from "react";
import { getRecent, getDevices } from "../api/api";

function Kpi({ label, value, tone }) {
  const clr = tone==="danger"?"#ef4444":tone==="warn"?"#f59e0b":tone==="ok"?"#10b981":"#e5e5e5";
  return (
    <div className="card" style={{padding:"14px 16px"}}>
      <div className="dim" style={{fontSize:12}}>{label}</div>
      <div style={{fontSize:28, fontWeight:800, color:clr}}>{value}</div>
    </div>
  );
}

export default function KpiStrip(){
  const [total, setTotal] = useState(0);
  const [hi, setHi] = useState(0);
  const [crit, setCrit] = useState(0);
  const [devs, setDevs] = useState(0);

  async function load(){
    const [r, d] = await Promise.all([getRecent(400), getDevices()]);
    const items = r.items || [];
    setTotal(items.length);
    setCrit(items.filter(x => (x.data?.severity||x.severity||"low").toLowerCase()==="critical").length);
    setHi(items.filter(x => (x.data?.severity||x.severity||"low").toLowerCase()==="high").length);
    setDevs((d.items||[]).length);
  }

  useEffect(()=>{ load(); const t=setInterval(load, 5000); return ()=>clearInterval(t); },[]);

  return (
    <div className="grid grid-4" style={{display:"grid", gridTemplateColumns:"repeat(4, 1fr)", gap:16}}>
      <Kpi label="Events (last 400)" value={total} />
      <Kpi label="High" value={hi} tone="warn" />
      <Kpi label="Critical" value={crit} tone="danger" />
      <Kpi label="Active Devices" value={devs} tone="ok" />
    </div>
  );
}
