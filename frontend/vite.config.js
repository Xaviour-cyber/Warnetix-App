import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

const r = (...p) => resolve(process.cwd(), ...p);

export default defineConfig({
  plugins: [react()],

  // root Vite = folder yang berisi index.html kamu
  root: r("public/src"),

  build: {
    outDir: r("dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main:   r("public/src/index.html"),
        upload: r("public/src/simple_upload.html"), // ⬅ pindah ke dalam root
      },
    },
  },

  server: { port: 5173, strictPort: true },

  // Matikan scanning PostCSS eksternal biar ga nyari2 config nyasar
  css: {
    postcss: { plugins: [] },
  },

  // Karena root sudah di 'public/src', kita ga pakai publicDir default
  publicDir: false,
});
