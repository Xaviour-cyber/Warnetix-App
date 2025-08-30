# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# paket React (di dalam frontend/public/src)
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund; \
    else \
      npm install --no-audit --no-fund; \
    fi

# seluruh source React
COPY frontend/public/src/ ./

# build vite => /app/dist
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# hasil build
COPY --from=build /app/dist ./

# config nginx untuk SPA + (opsional) proxy /api ke backend
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# fallback: pastikan /simple_upload.html ada
RUN [ -f simple_upload.html ] || cp index.html simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
