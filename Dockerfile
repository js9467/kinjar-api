# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=8

WORKDIR /app

# System deps (optional, keeps image small)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py ./app.py
COPY version.txt ./version.txt

# Security: run as non-root
RUN useradd -m appuser
USER appuser

EXPOSE 8080

# Gunicorn (prod)
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "${GUNICORN_WORKERS}", "--threads", "${GUNICORN_THREADS}", "app:app"]