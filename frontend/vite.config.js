import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

const r = (...p) => resolve(process.cwd(), ...p);

export default defineConfig({
  plugins: [react()],

  // Entry html ada di sini
  root: r("public/src"),

  build: {
    outDir: r("dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main:   r("public/src/index.html"),
        upload: r("public/simple_upload.html"), // -> /simple_upload.html
      },
    },
  },

  server: { port: 5173, strictPort: true },

  // Matikan pencarian PostCSS config eksternal: gunakan config kosong
  css: {
    postcss: {
      plugins: [],   // ⬅⬅⬅ ini bikin Vite berhenti nyari .postcssrc di luar
    },
  },

  publicDir: false,
});
