import os
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---- storage path (works without a volume; switches to /data if mounted) ----
DATA_DIR = os.environ.get("DATA_DIR", "/tmp")
os.makedirs(DATA_DIR, exist_ok=True)

@app.get("/health")
def health():
    return "ok", 200

@app.get("/")
def root():
    return jsonify(status="ok", data_dir=DATA_DIR)

# Example API (safe no-op)
@app.get("/posts")
def posts():
    # Example of using a header (works with PowerShell -Headers @{ "X-Family"="..." })
    family = request.headers.get("X-Family", "default")
    return jsonify(family=family, posts=[])

if __name__ == "__main__":
    # Dev runner (Fly will use Gunicorn from Dockerfile)
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
