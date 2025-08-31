import React, { useEffect, useState } from "react";
import { createPortal } from "react-dom";

let _add = null, _remove = null;

function ToastContainer(){
  const [items, setItems] = useState([]);

  useEffect(()=>{
    _add = (t)=> setItems(prev => [t, ...prev].slice(0,4));
    _remove = (id)=> setItems(prev => prev.filter(x => x.id !== id));
    return ()=>{ _add = null; _remove = null; };
  }, []);

  const close = (id)=> _remove?.(id);

  return createPortal(
    <div className="toast-stack">
      {items.map(t=>(
        <div key={t.id} className={`toast-item ${t.type}`} onClick={()=>close(t.id)} role="status">
          <div className="toast-msg">{t.msg}</div>
        </div>
      ))}
    </div>,
    document.body
  );
}

function pushWith(type, msg, ms=3500){
  const id = Math.random().toString(36).slice(2);
  _add?.({ id, type, msg });
  setTimeout(()=> _remove?.(id), ms);
}

export const toast = {
  success: (m,ms)=>pushWith("success", m, ms),
  error:   (m,ms)=>pushWith("error",   m, ms),
  info:    (m,ms)=>pushWith("info",    m, ms),
};

// Helper buat dipanggil sekali di App.jsx
export function MountToasts(){ return <ToastContainer/>; }
export default ToastContainer;
