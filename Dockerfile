# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY frontend/public/src/ ./
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
RUN [ -f /usr/share/nginx/html/simple_upload.html ] || cp /usr/share/nginx/html/index.html /usr/share/nginx/html/simple_upload.html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
