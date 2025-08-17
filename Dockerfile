FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080

WORKDIR /app

# (Optional) build tools aren't needed here; keeping image small
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY . /app

# Ensure persistent paths exist (Fly volume will mount here)
RUN mkdir -p /app/data && mkdir -p /app/data/media

EXPOSE 8080

# Use Gunicorn to serve Flask app
# -w 2: two workers, -k gthread: simple threaded workers
CMD ["sh","-c","gunicorn -w 2 -k gthread -b 0.0.0.0:${PORT:-8080} app:app"]
