# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps di root frontend (warnetix/frontend/package.json)
COPY package*.json ./
RUN npm install --no-audit --no-fund

# bawa semua isi folder frontend
COPY . .

# ENV buat Vite (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# Build dari lokasi yang bener (public/src ATAU public ATAU root)
RUN set -e; \
  if [ -f public/src/index.html ]; then \
    echo '>> build: public/src'; \
    cd public/src && /app/node_modules/.bin/vite build && mkdir -p /app/dist && mv dist/* /app/dist/; \
  elif [ -f public/index.html ]; then \
    echo '>> build: public'; \
    cd public && /app/node_modules/.bin/vite build && mkdir -p /app/dist && mv dist/* /app/dist/; \
  elif [ -f index.html ]; then \
    echo '>> build: root'; \
    /app/node_modules/.bin/vite build && mkdir -p /app/dist && mv dist/* /app/dist/; \
  else \
    echo 'ERROR: index.html tidak ditemukan di public/src, public, atau root' && exit 1; \
  fi; \
  # ikutkan halaman upload sederhana kalau ada
  if [ -f public/simple_upload.html ]; then \
    cp public/simple_upload.html /app/dist/simple_upload.html; \
  fi

# ---------- serve (Nginx) ----------
FROM nginx:alpine
# file ini harus ada di frontend/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
