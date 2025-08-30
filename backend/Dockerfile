# ---- Python runtime ----
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# bawa requirements; prefer yang ada di backend/
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# bawa source backend dgn namespace 'backend'
COPY backend/ /app/backend

# pastikan python bisa import package 'backend'
ENV PYTHONPATH=/app

EXPOSE 8000
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
