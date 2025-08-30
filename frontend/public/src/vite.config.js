import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Untuk dev: kalau mau proxy ke backend lokal, isi VITE_DEV_PROXY_TARGET
const devProxy = process.env.VITE_DEV_PROXY_TARGET || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: devProxy,
        changeOrigin: true
      }
    }
  }
});
