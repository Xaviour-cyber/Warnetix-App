import { useEffect, useState } from "react";
import { api } from "./api/api";

export default function App() {
  const [ready, setReady] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        // race dengan timeout ekstra di sisi App (cadangan)
        const h = await Promise.race([
          api.health(),
          new Promise((_, r) => setTimeout(() => r(new Error("Timeout")), 9000)),
        ]);
        if (!alive) return;
        setReady(true);
      } catch (e) {
        if (!alive) return;
        setErr(e?.message || "Gagal load backend");
      }
    })();
    return () => { alive = false; };
  }, []);

  if (!ready && !err) {
    return <div style={{color:"#e6e6e6",textAlign:"center",marginTop:80}}>Warnetix memuat …</div>;
  }
  if (err) {
    const base = import.meta.env.VITE_API_BASE || "(belum diset)";
    return (
      <div style={{color:"#ff6666",textAlign:"center",marginTop:80}}>
        Gagal hubungi backend.<br/>
        <small>VITE_API_BASE = {base}</small><br/>
        <a href={`${import.meta.env.VITE_API_BASE || ""}/health`} target="_blank" rel="noreferrer">Coba buka /health</a>
      </div>
    );
  }
  return <YourRealApp />; // halaman utama kamu
}
