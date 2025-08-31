# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps dari folder React
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund; \
    else \
      npm install --no-audit --no-fund; \
    fi

# source React lengkap (index.html, main.jsx, vite.config.js, src/, components/, pages/, public/, dll)
COPY frontend/public/src/ ./

# build
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# hasil build
COPY --from=build /app/dist ./

# config SPA
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# fallback lama untuk /simple_upload.html kalau tidak ada di dist
RUN [ -f simple_upload.html ] || cp index.html simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
