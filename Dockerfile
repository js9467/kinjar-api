# slim Python base
FROM python:3.12-slim

# env
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080

# system deps (if you add more libs later, install here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# app files
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY app.py /app/

# create a writable fallback data dir (no volume required to start)
RUN mkdir -p /tmp && chmod -R 777 /tmp

EXPOSE 8080

# Start the web server
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
