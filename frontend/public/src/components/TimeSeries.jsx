import React from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, CartesianGrid } from "recharts";

export default function TimeSeries({ series }) {
  // series: [{ ts, total, high, critical }]
  return (
    <div className="card">
      <h3>Trend 24 Jam</h3>
      <div style={{height:260}}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series}>
            <defs>
              <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ffffff" stopOpacity={0.35}/>
                <stop offset="95%" stopColor="#ffffff" stopOpacity={0.05}/>
              </linearGradient>
              <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#FB8C00" stopOpacity={0.5}/>
                <stop offset="95%" stopColor="#FB8C00" stopOpacity={0.05}/>
              </linearGradient>
              <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#E50914" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#E50914" stopOpacity={0.05}/>
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#222" vertical={false}/>
            <XAxis dataKey="label" stroke="#888" />
            <YAxis stroke="#888" allowDecimals={false} />
            <Tooltip />
            <Legend />
            <Area type="monotone" dataKey="total" stroke="#ddd" fill="url(#gTotal)" name="Total"/>
            <Area type="monotone" dataKey="high" stroke="#FB8C00" fill="url(#gHigh)" name="High"/>
            <Area type="monotone" dataKey="critical" stroke="#E50914" fill="url(#gCrit)" name="Critical"/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
