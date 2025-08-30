FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# copy semua konten public dan public/src kalau ada
COPY public/ ./
COPY public/src/ ./    

# optional: halaman upload sederhana jika ada di root frontend/
COPY simple_upload.html ./ 

# nginx conf opsional (kalau kamu punya)
# COPY ../deploy/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx","-g","daemon off;"]
