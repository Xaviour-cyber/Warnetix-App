import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard.jsx";
import Logs from "./pages/Logs.jsx";
import Devices from "./pages/Devices.jsx";

export default function App(){
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard/>} />
        <Route path="/logs" element={<Logs/>} />
        <Route path="/devices" element={<Devices/>} />
      </Routes>
    </BrowserRouter>
  );
}
import './styles/theme.css'