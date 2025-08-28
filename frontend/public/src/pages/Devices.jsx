import Navbar from "../components/Navbar";
import { useEffect, useState } from "react";
import { getDevices } from "../api/api";

export default function Devices(){
  const [items,setItems]=useState([]);
  useEffect(()=>{(async()=>{const j=await getDevices(); setItems(j.items||[]);})();},[]);
  return (
    <>
      <Navbar/>
      <div className="container card">
        <h3>Devices</h3>
        <table className="table">
          <thead><tr><th>ID</th><th>Name</th><th>OS</th><th>Last Seen</th></tr></thead>
          <tbody>
            {items.length===0 && <tr><td colSpan="4" className="dim">Belum ada device</td></tr>}
            {items.map((d,i)=>(
              <tr key={i}><td>{d.id}</td><td>{d.name||d.hostname||"-"}</td><td>{d.os||"-"}</td>
              <td className="dim">{d.last_seen?new Date(d.last_seen*1000).toLocaleString():"-"}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
