# ---------- Build (React + Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps React (di frontend/public/src)
COPY frontend/public/src/package*.json ./
# gunakan lock kalau ada; kalau tidak, fallback npm install
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund

# source React
COPY frontend/public/src/ ./

# opsional: inject env build-time dari Railway (atau pakai .env.production)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

# build -> dist
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# hasil build ke root dokumen
COPY --from=build /app/dist ./

# pakai config SPA kamu
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# jaga rute lama /simple_upload.html tetap hidup (fallback ke index.html kalau nggak ada)
RUN [ -f simple_upload.html ] || cp index.html simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
