# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps di root frontend (warnetix/frontend/package.json)
COPY package*.json ./
RUN npm install --no-audit --no-fund

# bawa semua isi folder frontend
COPY . .

# ENV untuk Vite waktu build (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# Cari lokasi index.html & config yang bener, lalu build dari situ
RUN set -e; \
  if [ -f public/src/index.html ]; then BUILD_DIR="public/src"; \
  elif [ -f public/index.html ]; then BUILD_DIR="public"; \
  elif [ -f index.html ]; then BUILD_DIR="."; \
  else echo "ERROR: index.html tidak ditemukan di public/src, public, atau root"; exit 1; fi; \
  echo ">> build dir: $BUILD_DIR"; \
  cd "$BUILD_DIR"; \
  # tentuin config (kalau ada)
  if [ -f vite.config.js ]; then CFG=./vite.config.js; \
  elif [ -f vite.config.ts ]; then CFG=./vite.config.ts; \
  elif [ -f ../src/vite.config.js ]; then CFG=../src/vite.config.js; \
  elif [ -f ../src/vite.config.ts ]; then CFG=../src/vite.config.ts; \
  elif [ -f ../vite.config.js ]; then CFG=../vite.config.js; \
  elif [ -f ../vite.config.ts ]; then CFG=../vite.config.ts; \
  else CFG=""; fi; \
  if [ -n "$CFG" ]; then npx vite build -c "$CFG"; else npx vite build; fi; \
  mkdir -p /app/dist && mv dist/* /app/dist/; \
  # ikutkan halaman upload sederhana kalau ada
  if [ -f ../simple_upload.html ]; then cp ../simple_upload.html /app/dist/simple_upload.html; fi; \
  if [ -f ../../simple_upload.html ]; then cp ../../simple_upload.html /app/dist/simple_upload.html; fi

# ---------- serve (Nginx) ----------
FROM nginx:alpine
# file ini harus ada di frontend/nginx.conf (SPA fallback)
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
