FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY . /app

# Ensure persistent paths exist (Fly volume mounts here)
RUN mkdir -p /app/data && mkdir -p /app/data/media

EXPOSE 8080
# 1 worker is enough; avoids SQLite locking issues on startup
CMD ["sh","-c","gunicorn -w 1 -k gthread -b 0.0.0.0:${PORT:-8080} app:app"]
