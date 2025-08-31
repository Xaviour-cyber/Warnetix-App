import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// ABSOLUTE PATH helper
const r = (...p) => resolve(process.cwd(), ...p);

export default defineConfig({
  plugins: [react()],

  // >>>> Penting: root kita adalah 'public/src' karena index.html ada di situ
  root: r("public/src"),

  // Multi-page build: ikutkan simple_upload.html juga
  build: {
    outDir: r("dist"),       // output ke frontend/dist
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: r("public/src/index.html"),
        upload: r("public/simple_upload.html"), // ==> akan jadi /simple_upload.html
      },
    },
  },

  // Dev server (opsional)
  server: {
    port: 5173,
    strictPort: true,
  },

  // Karena root = public/src, kita matikan publicDir default
  // (kita eksplisit daftarkan simple_upload lewat rollupOptions.input)
  publicDir: false,
});
