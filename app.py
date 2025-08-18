# app.py
import os
import json
import uuid
import shutil
import logging
from datetime import datetime
from typing import Tuple, Dict, Any, List

from flask import Flask, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename

# -----------------------
# Config
# -----------------------
PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
ALLOWED_EXTENSIONS = set(os.environ.get("ALLOWED_EXTENSIONS", "jpg,jpeg,png,gif,webp,mp4,mov,avi,txt,json,pdf").split(","))

# Ensure base data dir exists
os.makedirs(DATA_DIR, exist_ok=True)

# -----------------------
# App + Logging
# -----------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_MB * 1024 * 1024

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("kinjar")

# -----------------------
# Helpers
# -----------------------
def _ok() -> Dict[str, Any]:
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}

def _err(message: str, status: int = 400) -> Tuple[Dict[str, Any], int]:
    return {"ok": False, "error": message}, status

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def tenant_dir(tenant: str) -> str:
    td = os.path.join(DATA_DIR, "tenants", tenant)
    os.makedirs(td, exist_ok=True)
    os.makedirs(os.path.join(td, "uploads"), exist_ok=True)
    os.makedirs(os.path.join(td, "notes"), exist_ok=True)
    return td

def disk_info(path: str) -> Dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
        }
    except Exception as e:
        log.warning("disk_info error: %s", e)
        return {"total_bytes": None, "used_bytes": None, "free_bytes": None}

def check_writable(path: str) -> bool:
    try:
        test_path = os.path.join(path, f".writetest-{uuid.uuid4().hex}")
        with open(test_path, "w") as f:
            f.write("ok")
        os.remove(test_path)
        return True
    except Exception as e:
        log.error("writable check failed for %s: %s", path, e)
        return False

def list_files_for_tenant(tenant: str) -> List[Dict[str, Any]]:
    updir = os.path.join(tenant_dir(tenant), "uploads")
    files = []
    for root, _, filenames in os.walk(updir):
        for fn in filenames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, updir)
            try:
                st = os.stat(full)
                files.append({
                    "name": rel.replace("\\", "/"),
                    "size": st.st_size,
                    "updated": datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
                })
            except FileNotFoundError:
                continue
    return sorted(files, key=lambda x: x["name"])

# -----------------------
# Core Endpoints
# -----------------------
@app.get("/")
def root_status():
    """High-level status + volume check."""
    return jsonify({
        "status": "ok",
        "service": "kinjar-api",
        "data_dir": DATA_DIR,
        "has_volume": os.path.exists(DATA_DIR),
        "writable": check_writable(DATA_DIR),
        "disk": disk_info(DATA_DIR),
        "allowed_extensions": sorted(list(ALLOWED_EXTENSIONS)),
        "max_upload_mb": MAX_CONTENT_LENGTH_MB,
    })

@app.get("/health")
@app.get("/healthz")
def health():
    return "ok", 200

# -----------------------
# Tenant Ops
# -----------------------
@app.post("/tenant/<tenant>/note")
def add_note(tenant: str):
    """
    Create/append a simple note for a tenant.
    Body JSON: { "title": "...", "body": "..." }
    """
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON body", 400)

    title = (data or {}).get("title") or "Untitled"
    body = (data or {}).get("body") or ""
    nid = uuid.uuid4().hex

    notes_dir = os.path.join(tenant_dir(tenant), "notes")
    os.makedirs(notes_dir, exist_ok=True)
    note_path = os.path.join(notes_dir, f"{nid}.json")

    payload = {
        "id": nid,
        "title": title,
        "body": body,
        "created": datetime.utcnow().isoformat() + "Z",
    }
    with open(note_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    out = _ok()
    out["note"] = payload
    return jsonify(out), 201

@app.get("/tenant/<tenant>/notes")
def list_notes(tenant: str):
    notes_dir = os.path.join(tenant_dir(tenant), "notes")
    if not os.path.exists(notes_dir):
        return jsonify({"notes": []})
    notes = []
    for fn in os.listdir(notes_dir):
        if not fn.endswith(".json"):
            continue
        fp = os.path.join(notes_dir, fn)
        try:
            with open(fp, "r", encoding="utf-8") as f:
                notes.append(json.load(f))
        except Exception as e:
            log.warning("Failed reading note %s: %s", fp, e)
    notes.sort(key=lambda n: n.get("created", ""), reverse=True)
    return jsonify({"notes": notes})

# -----------------------
# Upload / Files
# -----------------------
@app.post("/upload")
def upload():
    """
    Multipart upload with fields:
      - tenant (required)
      - file (required)
    Saves to /data/tenants/<tenant>/uploads/<safe_filename>
    """
    tenant = (request.form.get("tenant") or "").strip()
    if not tenant:
        return _err("Missing 'tenant' form field", 400)

    if "file" not in request.files:
        return _err("Missing 'file' in form-data", 400)

    file = request.files["file"]
    if file.filename == "":
        return _err("Empty filename", 400)

    filename = secure_filename(file.filename)
    if not filename:
        return _err("Unsafe filename", 400)

    if not allowed_file(filename):
        return _err(f"Extension not allowed. Allowed: {sorted(list(ALLOWED_EXTENSIONS))}", 415)

    up_dir = os.path.join(tenant_dir(tenant), "uploads")
    os.makedirs(up_dir, exist_ok=True)

    # De-dup by prefixing with short UUID if exists
    dest_path = os.path.join(up_dir, filename)
    if os.path.exists(dest_path):
        name, dot, ext = filename.partition(".")
        filename = f"{name}-{uuid.uuid4().hex[:6]}{dot}{ext}" if dot else f"{name}-{uuid.uuid4().hex[:6]}"
        dest_path = os.path.join(up_dir, filename)

    file.save(dest_path)

    out = _ok()
    out["file"] = {
        "tenant": tenant,
        "name": filename,
        "size": os.path.getsize(dest_path),
        "url": f"/file/{tenant}/{filename}",
    }
    return jsonify(out), 201

@app.get("/files")
def list_files():
    """
    List files for a tenant.
    Query params: ?tenant=<tenant>
    """
    tenant = (request.args.get("tenant") or "").strip()
    if not tenant:
        return _err("Missing 'tenant' query param", 400)

    files = list_files_for_tenant(tenant)
    return jsonify({"tenant": tenant, "files": files})

@app.get("/file/<tenant>/<path:filename>")
def get_file(tenant: str, filename: str):
    up_dir = os.path.join(tenant_dir(tenant), "uploads")
    safe_name = secure_filename(filename)  # ensure traversal safety
    # Maintain subpaths if any (e.g., album/name.jpg) by normalizing
    # but only serve from uploads root:
    requested = os.path.normpath(os.path.join(up_dir, safe_name))
    if not requested.startswith(up_dir):
        abort(404)
    if not os.path.exists(requested):
        abort(404)
    # Use send_from_directory with relative path to avoid exposing full paths
    rel_dir = os.path.relpath(os.path.dirname(requested), up_dir)
    rel_name = os.path.basename(requested)
    serve_dir = up_dir if rel_dir == "." else os.path.join(up_dir, rel_dir)
    return send_from_directory(serve_dir, rel_name, as_attachment=False)

# -----------------------
# Error Handlers
# -----------------------
@app.errorhandler(413)
def too_large(_e):
    return _err(f"File too large (>{MAX_CONTENT_LENGTH_MB} MB)", 413)

@app.errorhandler(404)
def not_found(_e):
    return _err("Not found", 404)

@app.errorhandler(405)
def not_allowed(_e):
    return _err("Method not allowed", 405)

@app.errorhandler(Exception)
def on_exception(e):
    log.exception("Unhandled error: %s", e)
    return _err("Internal server error"), 500

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # For local dev: python app.py
    app.run(host="0.0.0.0", port=PORT, debug=bool(os.environ.get("DEBUG")))
