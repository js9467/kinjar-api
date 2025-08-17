import os
from flask import Flask, jsonify, request

app = Flask(__name__)

# Persistent storage path (volume) or fallback for dev
DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

@app.get("/health")
def health():
    return "ok", 200

@app.get("/")
def root():
    return jsonify(status="ok", data_dir=DATA_DIR)

@app.get("/posts")
def posts():
    family = request.headers.get("X-Family", "default")
    return jsonify(family=family, posts=[])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
