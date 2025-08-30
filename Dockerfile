# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps FE (di src)
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund; \
    else \
      npm install --no-audit --no-fund; \
    fi

# bawa seluruh source FE
COPY frontend/public/src/ ./
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
WORKDIR /usr/share/nginx/html
COPY --from=build /app/dist ./
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# fallback opsional utk /simple_upload.html
RUN [ -f simple_upload.html ] || cp index.html simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
