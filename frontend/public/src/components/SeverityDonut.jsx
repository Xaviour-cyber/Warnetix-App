import { useEffect, useMemo, useState } from "react";
import { getRecent } from "../api/api";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

const COLORS = {critical:"#ef4444", high:"#f59e0b", medium:"#3b82f6", low:"#10b981"};

export default function SeverityDonut(){
  const [rows, setRows] = useState([]);

  async function load(){
    const j = await getRecent(400);
    setRows(j.items || []);
  }
  useEffect(()=>{ load(); const t=setInterval(load,7000); return ()=>clearInterval(t); },[]);

  const dist = useMemo(()=>{
    const c = {critical:0, high:0, medium:0, low:0};
    for(const r of rows){
      const d = r.data || r; c[(d.severity||"low").toLowerCase()]++;
    }
    return Object.entries(c).map(([k,v])=>({name:k, value:v}));
  }, [rows]);

  return (
    <div className="card">
      <h3>Severity Distribution</h3>
      <div style={{height:260}}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie dataKey="value" data={dist} innerRadius={60} outerRadius={100} paddingAngle={3}>
              {dist.map((e, i)=> <Cell key={i} fill={COLORS[e.name] || "#999"} />)}
            </Pie>
            <Legend />
            <Tooltip contentStyle={{background:"#151515", border:"1px solid #2a2a2a", borderRadius:8}}/>
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
