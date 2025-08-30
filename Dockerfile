# ---------- Build React ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps from the React app folder
COPY frontend/public/src/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund; \
    else \
      npm install --no-audit --no-fund; \
    fi

# app sources (index.html, vite.config.js, src/, components/, pages/, public/, etc.)
COPY frontend/public/src/ ./
RUN npm run build

# ---------- Runtime (nginx) ----------
FROM nginx:alpine
# SPA routing + /api proxy (static keeps working)
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
# ship the built site
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
