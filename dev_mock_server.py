import os
import json
from uuid import uuid4
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Simple development storage mock
UPLOAD_DIR = os.path.join(os.getcwd(), "dev_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def corsify(response, origin=None):
    """Simple CORS helper for development"""
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route("/upload", methods=["POST"])
def mock_upload():
    """Simple mock upload endpoint for development"""
    origin = request.headers.get("Origin")
    
    if 'file' not in request.files:
        return corsify(jsonify({"ok": False, "error": "no_file"}), origin), 400
    
    file = request.files['file']
    if file.filename == '':
        return corsify(jsonify({"ok": False, "error": "no_filename"}), origin), 400
    
    family_slug = request.form.get('family_slug', 'default')
    upload_type = request.form.get('type', 'photo')
    
    # Generate mock response
    file_id = str(uuid4())
    filename = file.filename
    
    # Save file locally for development
    local_path = os.path.join(UPLOAD_DIR, f"{file_id}_{filename}")
    file.save(local_path)
    
    # Get file size
    file_size = os.path.getsize(local_path)
    
    response_data = {
        "ok": True,
        "id": file_id,
        "key": f"dev/{family_slug}/{file_id}/{filename}",
        "type": upload_type,
        "filename": filename,
        "size": file_size,
        "publicUrl": f"http://localhost:5000/uploads/{file_id}_{filename}",
        "message": "File uploaded to local development storage"
    }
    
    print(f"✅ Mock upload successful: {filename} ({file_size} bytes)")
    return corsify(jsonify(response_data), origin)

@app.route("/uploads/<filename>")
def serve_upload(filename):
    """Serve uploaded files for development"""
    return f"File: {filename} (stored locally for development)"

@app.route("/upload", methods=["OPTIONS"])
@app.route("/health", methods=["GET", "OPTIONS"])
@app.route("/status", methods=["GET", "OPTIONS"])
def handle_options():
    origin = request.headers.get("Origin")
    response = make_response(("", 204))
    return corsify(response, origin)

@app.route("/health")
@app.route("/status")
def health():
    origin = request.headers.get("Origin")
    return corsify(jsonify({"status": "ok", "message": "Development mock server"}), origin)

if __name__ == "__main__":
    print("🚀 Starting development mock upload server...")
    print(f"📁 Upload directory: {UPLOAD_DIR}")
    print("🌐 Server running on http://localhost:5000")
    print("📸 Ready to accept uploads!")
    app.run(host="0.0.0.0", port=5000, debug=True)