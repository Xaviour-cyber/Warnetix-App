import { useEffect, useMemo, useState } from "react";
import { getTimeseries } from "../api/api";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend, BarChart, Bar } from "recharts";

function fmtTime(t){
  const d = new Date(t*1000);
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
}

export default function ChartActivityPro(){
  const [series, setSeries] = useState([]);

  async function load(){
    const end = Math.floor(Date.now()/1000);
    const start = end - 3600*6; // 6 jam terakhir
    const j = await getTimeseries(start,end,"hour");
    setSeries(j.series||[]);
  }
  useEffect(()=>{ load(); const t=setInterval(load,15000); return ()=>clearInterval(t);},[]);

  const data = useMemo(()=> (series||[]).map(b=>({
    t: b.t, label: fmtTime(b.t),
    total: b.count||0, high: b.high||0, critical: b.critical||0,
    medium: Math.max(0,(b.count||0)-(b.high||0)-(b.critical||0))
  })), [series]);

  return (
    <div className="card">
      <h3>Activity – 6 Hours</h3>
      <div style={{height:260}}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{left:8,right:8,top:8,bottom:8}}>
            <defs>
              <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#8884d8" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#8884d8" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.7}/>
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false}/>
            <XAxis dataKey="label" tick={{fill:"#a3a3a3"}}/>
            <YAxis allowDecimals={false} tick={{fill:"#a3a3a3"}}/>
            <Tooltip contentStyle={{background:"#151515", border:"1px solid #2a2a2a", borderRadius:8}}/>
            <Legend />
            <Area type="monotone" dataKey="total" name="Total" stroke="#8884d8" fillOpacity={1} fill="url(#gTotal)"/>
            <Area type="monotone" dataKey="high" name="High" stroke="#f59e0b" fill="url(#gHigh)"/>
            <Area type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" fill="url(#gCritical)"/>
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div style={{height:220, marginTop:12}}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{left:8,right:8,top:8,bottom:8}}>
            <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false}/>
            <XAxis dataKey="label" tick={{fill:"#a3a3a3"}}/>
            <YAxis allowDecimals={false} tick={{fill:"#a3a3a3"}}/>
            <Tooltip contentStyle={{background:"#151515", border:"1px solid #2a2a2a", borderRadius:8}}/>
            <Legend />
            <Bar dataKey="critical" name="Critical" stackId="a" fill="#ef4444"/>
            <Bar dataKey="high" name="High" stackId="a" fill="#f59e0b"/>
            <Bar dataKey="medium" name="Medium" stackId="a" fill="#3b82f6"/>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
