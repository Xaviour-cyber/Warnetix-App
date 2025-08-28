import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
    proxy: {
      // supaya call ke /events/**, /scan-file dll nembak backend 8000
      "/events": "http://127.0.0.1:8000",
      "/devices": "http://127.0.0.1:8000",
      "/scan-file": "http://127.0.0.1:8000",
      "/scan-path": "http://127.0.0.1:8000",
      "/watch": "http://127.0.0.1:8000"
    }
  }
});
