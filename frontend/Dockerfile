# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# bawa semua isi folder frontend sebagai konteks
COPY . .

# inject ENV waktu build (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# DETEKSI LOKASI package.json:
# - kalau ada di public/src → build dari situ
# - kalau ada di root frontend → build dari root
RUN set -e; \
  if [ -f public/src/package.json ]; then \
    echo ">> Build from public/src"; \
    cd public/src; \
    npm install --no-audit --no-fund; \
    npm run build; \
    mv dist /app/dist; \
  elif [ -f package.json ]; then \
    echo ">> Build from frontend/"; \
    npm install --no-audit --no-fund; \
    npm run build; \
    mv dist /app/dist; \
  else \
    echo "ERROR: package.json not found (expected at public/src/ or .)"; \
    ls -la; \
    exit 1; \
  fi; \
  # ikutkan halaman upload sederhana ke output
  if [ -f public/simple_upload.html ]; then \
    cp public/simple_upload.html /app/dist/simple_upload.html; \
  elif [ -f ../public/simple_upload.html ]; then \
    cp ../public/simple_upload.html /app/dist/simple_upload.html; \
  fi

# ---------- serve (nginx) ----------
FROM nginx:alpine
# nginx.conf harus ada di frontend/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
