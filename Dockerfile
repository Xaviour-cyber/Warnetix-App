# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps React
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi

# source React (index.html, vite.config.js, src/, components/, pages/, public/)
COPY frontend/public/src/ ./
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
# SPA fallback - jangan proxy /api, karena FE pakai VITE_API_BASE
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# fallback kalau simple_upload.html gak ada
RUN [ -f /usr/share/nginx/html/simple_upload.html ] || cp /usr/share/nginx/html/index.html /usr/share/nginx/html/simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
