#!/usr/bin/env python3
"""
Safe version of app.py that catches initialization errors
"""
import os
import datetime
import logging
from flask import Flask, jsonify

# Setup logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kinjar-api")

app = Flask(__name__)

# Basic endpoints that always work
@app.get("/")
def root():
    return jsonify({
        "message": "Kinjar API Server",
        "version": "1.0.0",
        "status": "running",
        "health_endpoint": "/health"
    })

@app.get("/health")
def health():
    return jsonify({
        "status": "ok", 
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

# Try to import the full app functionality
try:
    log.info("Attempting to load full app functionality...")
    
    # Import all the complex functionality
    exec(open("app.py").read())
    
    log.info("Full app functionality loaded successfully!")
    
except Exception as e:
    log.error(f"Failed to load full app functionality: {e}")
    
    # Add a debug endpoint to show the error
    @app.get("/debug")
    def debug():
        return jsonify({
            "status": "partial",
            "error": str(e),
            "message": "Basic endpoints working, but full functionality failed to load"
        })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))