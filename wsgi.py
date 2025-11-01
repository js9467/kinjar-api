"""ASGI adapter for Flask application"""
from asgiref.wsgi import WsgiToAsgi
from app import app

# Convert Flask WSGI app to ASGI
asgi_app = WsgiToAsgi(app)

# For Uvicorn
application = asgi_app

if __name__ == "__main__":
    # For local development only
    app.run(host="0.0.0.0", port=8080, debug=True)