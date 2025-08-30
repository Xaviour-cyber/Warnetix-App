# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# paket React (subdir)
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund; \
    else \
      npm install --no-audit --no-fund; \
    fi

# source React
COPY frontend/public/src/ ./
# build ke /app/dist
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
# SPA config
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
# hasil build
COPY --from=build /app/dist /usr/share/nginx/html
# fallback untuk /simple_upload.html (kalau gak ada di public/)
RUN [ -f /usr/share/nginx/html/simple_upload.html ] || \
    cp /usr/share/nginx/html/index.html /usr/share/nginx/html/simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
