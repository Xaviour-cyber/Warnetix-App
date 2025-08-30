# frontend/Dockerfile  — build context harus folder "frontend"
FROM nginx:alpine

# Nginx document root
WORKDIR /usr/share/nginx/html

# Copy seluruh isi frontend/public ke root Nginx
# (sudah termasuk /src dan simple_upload.html kalau ada)
COPY public/ ./

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
