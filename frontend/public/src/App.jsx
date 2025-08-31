import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Dashboard from "./pages/Dashboard.jsx";
import Logs from "./pages/Logs.jsx";
import Devices from "./pages/Devices.jsx";
import { MountToasts } from "./components/Toast.jsx";

export default function App(){
  return (
    <BrowserRouter>
      <MountToasts />
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard/>} />
        <Route path="/logs" element={<Logs/>} />
        <Route path="/devices" element={<Devices/>} />
        <Route path="*" element={<div className="card">404</div>} />
      </Routes>
    </BrowserRouter>
  );
}
import "./styles/theme.css";
