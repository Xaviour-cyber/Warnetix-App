export default function Navbar(){
  return (
    <div className="header">
      <div className="container" style={{display:"flex",alignItems:"center",justifyContent:"space-between",height:64}}>
        <div className="brand">
          <span className="dot"></span>
          <span style={{color:"#fff", fontSize:18}}>WARNETIX</span>
          <span className="badge" style={{marginLeft:8}}>Scanner</span>
        </div>
        <div style={{display:"flex", gap:14, alignItems:"center"}}>
          <a href="/" className="dim">Dashboard</a>
          <a href="/devices" className="dim">Devices</a>
          <a href="/logs" className="dim">Logs</a>
        </div>
      </div>
    </div>
  );
}
