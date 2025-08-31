import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

const r = (...p) => resolve(process.cwd(), ...p);

export default defineConfig({
  plugins: [react()],

  // Entry html kamu ada di sini
  root: r("public/src"),

  build: {
    outDir: r("dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main:   r("public/src/index.html"),
        upload: r("public/simple_upload.html"), // -> /simple_upload.html di produksi
      },
    },
  },

  server: { port: 5173, strictPort: true },

  // Karena root = public/src, kita matiin publicDir default (kita deklarasi manual di atas)
  publicDir: false,
});
