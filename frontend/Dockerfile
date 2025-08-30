# ---------- build (Vite) ----------
FROM node:20-alpine AS build
WORKDIR /app

# deps: package.json berada di frontend/public/src
COPY public/src/package.json ./package.json
RUN npm install --no-audit --no-fund

# source Vite (index.html, vite.config.js, src/**, dll) ada di frontend/public/src
COPY public/src/ ./

# injek env waktu build (set di Railway → Variables)
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

RUN npm run build
# hasil build -> /app/dist

# ---------- serve (Nginx) ----------
FROM nginx:alpine
# nginx.conf harus ada di frontend/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# ship hasil build
COPY --from=build /app/dist /usr/share/nginx/html

# ikutkan halaman upload sederhana di root
COPY public/simple_upload.html /usr/share/nginx/html/simple_upload.html

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
