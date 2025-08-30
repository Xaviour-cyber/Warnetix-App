# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app/public/src

# konteks build = folder 'frontend', jadi path relatif dari situ
COPY public/src/package*.json ./
RUN npm ci --no-audit --no-fund

# bawa semua source FE
COPY public/src/ .

# inject ENV saat build (set di Railway -> Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=

# Vite akan cari index.html di WORKDIR (/app/public/src)
RUN npm run build
# hasil: /app/public/src/dist

# ---------- serve (nginx) ----------
FROM nginx:alpine
# nginx.conf harus ada di frontend/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
# salin hasil build ke root web
COPY --from=build /app/public/src/dist /usr/share/nginx/html

# ikutkan halaman upload sederhana
COPY public/simple_upload.html /usr/share/nginx/html/simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]