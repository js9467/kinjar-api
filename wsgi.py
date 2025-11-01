"""WSGI entry point for Gunicorn"""
from app import app

# This is the entry point for Gunicorn
# Use: gunicorn --config gunicorn.conf.py app:app
# Or: gunicorn wsgi:app

if __name__ == "__main__":
    # For local development only
    app.run(host="0.0.0.0", port=8080, debug=True)