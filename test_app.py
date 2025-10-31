#!/usr/bin/env python3
"""
Minimal test version to verify basic Flask startup
"""
import os
import datetime
from flask import Flask, jsonify

app = Flask(__name__)

@app.get("/")
def root():
    return jsonify({
        "message": "Kinjar API Test Server",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))