# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps di root frontend
COPY package*.json ./
# pakai install (lebih toleran kalau lockfile gak ada/beda)
RUN npm install --no-audit --no-fund

# bawa seluruh source frontend
COPY . .

# inject ENV untuk Vite saat build (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# === DETEKSI LOKASI PROYEK VITE ===
# - Kalau Vite config ada di public/src → build di sana,
#   lalu pindahkan output ke /app/dist
# - Kalau Vite config ada di root frontend → build biasa
RUN set -e; \
  if [ -f public/src/vite.config.js ] || [ -f public/src/vite.config.ts ]; then \
    echo '>> Build from public/src'; \
    npx vite build -c public/src/vite.config.js || npx vite build -c public/src/vite.config.ts; \
    mkdir -p /app/dist && mv public/src/dist/* /app/dist/; \
  elif [ -f vite.config.js ] || [ -f vite.config.ts ]; then \
    echo '>> Build from frontend root'; \
    npx vite build || npm run build || (echo "Vite build failed"; exit 1); \
  else \
    echo "ERROR: vite.config.js/ts tidak ditemukan (di root atau public/src)"; \
    ls -la; exit 1; \
  fi

# ikutkan simple_upload.html kalau ada
RUN if [ -f public/simple_upload.html ]; then \
      cp public/simple_upload.html /app/dist/simple_upload.html; \
    fi

# ---------- serve (nginx) ----------
FROM nginx:alpine
# nginx.conf harus ada di frontend/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
