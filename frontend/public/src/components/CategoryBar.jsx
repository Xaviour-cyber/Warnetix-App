import { useEffect, useMemo, useState } from "react";
import { getRecent } from "../api/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function CategoryBar(){
  const [rows, setRows] = useState([]);

  async function load(){
    const j = await getRecent(400);
    setRows(j.items || []);
  }
  useEffect(()=>{ load(); const t=setInterval(load,8000); return ()=>clearInterval(t); },[]);

  const data = useMemo(()=>{
    const map = {};
    for(const r of rows){
      const d = r.data || r;
      const cat = (d.category || "unknown").toLowerCase();
      map[cat] = (map[cat]||0) + 1;
    }
    return Object.entries(map).map(([k,v])=>({name:k, count:v}));
  }, [rows]);

  return (
    <div className="card">
      <h3>Top Categories</h3>
      <div style={{height:220}}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false}/>
            <XAxis dataKey="name" tick={{fill:"#a3a3a3"}} />
            <YAxis allowDecimals={false} tick={{fill:"#a3a3a3"}} />
            <Tooltip contentStyle={{background:"#151515", border:"1px solid #2a2a2a", borderRadius:8}}/>
            <Bar dataKey="count" fill="#E50914" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
