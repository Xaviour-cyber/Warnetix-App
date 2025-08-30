import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  // root = folder ini (frontend/public/src) -> Vite bakal ketemu index.html
  root: fileURLToPath(new URL(".", import.meta.url)),
  publicDir: fileURLToPath(new URL("./public", import.meta.url)),
  build: { outDir: "dist", sourcemap: false },
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_DEV_PROXY_TARGET || "http://127.0.0.1:8000",
        changeOrigin: true
      }
    }
  }
});
