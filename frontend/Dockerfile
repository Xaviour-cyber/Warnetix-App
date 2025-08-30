# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps di root frontend (warnetix/frontend/package*.json)
COPY package*.json ./
RUN npm install --no-audit --no-fund

# bawa seluruh isi folder frontend
COPY . .

# ENV buat Vite (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# Deteksi index.html & config, build Vite dengan --root yang tepat
RUN set -e; \
  INDEX=""; \
  for p in public/src/index.html public/index.html index.html; do \
    [ -f "$p" ] && INDEX="$p" && break; \
  done; \
  if [ -z "$INDEX" ]; then \
    INDEX=$(find . -maxdepth 5 -name index.html | head -n1 || true); \
  fi; \
  if [ -z "$INDEX" ]; then \
    echo "ERROR: index.html tidak ditemukan"; exit 1; \
  fi; \
  BUILD_DIR=$(dirname "$INDEX"); \
  echo ">> Vite build root: $BUILD_DIR (index: $INDEX)"; \
  cd "$BUILD_DIR"; \
  npx vite build; \
  mkdir -p /app/dist && cp -r dist/* /app/dist/; \
  [ -f ../simple_upload.html ] && cp ../simple_upload.html /app/dist/simple_upload.html || true; \
  [ -f ../../simple_upload.html ] && cp ../../simple_upload.html /app/dist/simple_upload.html || true

# ---------- serve (Nginx) ----------
FROM nginx:alpine
# nginx.conf harus ada di frontend/nginx.conf (SPA fallback)
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
