import os
import uuid
import json
import logging
from datetime import timedelta
from typing import List, Optional

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import boto3
from botocore.client import Config as BotoConfig

# ----------------------------
# Configuration
# ----------------------------
def env_str(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return val

def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        raise RuntimeError(f"Env var {name} must be an integer")

APP_NAME = os.getenv("APP_NAME", "kinjar-api")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Security
# Comma-separated API keys allowed to call sensitive endpoints (e.g., presign)
# Generate one and set the same value in your Vercel project as X-API-Key
API_KEYS: List[str] = [
    x.strip() for x in os.getenv("API_KEYS", "").split(",") if x.strip()
]

# CORS
ALLOWED_ORIGINS = [
    x.strip() for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()
]

# R2 / S3-compatible storage
# For Cloudflare R2: endpoint like https://<ACCOUNT_ID>.r2.cloudflarestorage.com
S3_ENDPOINT = os.getenv("S3_ENDPOINT")  # if not set and R2_ACCOUNT_ID is set, we derive it below
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
if not S3_ENDPOINT and R2_ACCOUNT_ID:
    S3_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

S3_ACCESS_KEY = env_str("S3_ACCESS_KEY_ID", os.getenv("R2_ACCESS_KEY_ID"))
S3_SECRET_KEY = env_str("S3_SECRET_ACCESS_KEY", os.getenv("R2_SECRET_ACCESS_KEY"))
S3_BUCKET     = env_str("S3_BUCKET", None)

# Presign behavior
PRESIGN_EXPIRES_SECONDS = env_int("PRESIGN_EXPIRES_SECONDS", 60)         # 1 min
PRESIGN_MAX_MB          = env_int("PRESIGN_MAX_MB", 50)                  # 50MB
PRESIGN_PREFIX          = os.getenv("PRESIGN_PREFIX", "t/")              # key prefix guard

# Optional: require a tenant slug for presign
REQUIRE_TENANT = os.getenv("REQUIRE_TENANT", "1") in ("1", "true", "TRUE")

# ----------------------------
# App & Logging
# ----------------------------
app = Flask(APP_NAME)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(APP_NAME)

# CORS: allow only the specified origins
if ALLOWED_ORIGINS:
    CORS(app, supports_credentials=False, origins=ALLOWED_ORIGINS)
else:
    # Default to no cross-origin unless explicitly allowed
    CORS(app, supports_credentials=False, origins=[])

# ----------------------------
# Helpers
# ----------------------------
def require_api_key():
    """Require X-API-Key for sensitive routes."""
    if not API_KEYS:
        # If you really want to run without API keys (dev), allow it—but log loudly.
        logger.warning("API_KEYS is empty; /presign is unsecured!")
        return
    provided = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not provided or provided not in API_KEYS:
        return make_response(jsonify({"ok": False, "error": "Unauthorized"}), 401)

def parse_tenant_slug() -> Optional[str]:
    # Accept either header or JSON body field
    slug = request.headers.get("x-tenant-slug")
    if slug:
        return slug.strip()
    if request.is_json:
        try:
            data = request.get_json(silent=True) or {}
            slug = (data.get("tenant_slug") or "").strip()
            return slug or None
        except Exception:
            return None
    return None

def s3_client():
    if not S3_ENDPOINT:
        raise RuntimeError("S3_ENDPOINT (or R2_ACCOUNT_ID) is required")
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=BotoConfig(s3={"addressing_style": "virtual"})
    )

# ----------------------------
# Routes
# ----------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy", "name": APP_NAME})

@app.get("/version")
def version():
    v = "unknown"
    try:
        with open("version.txt", "r", encoding="utf-8") as f:
            v = f.read().strip() or v
    except FileNotFoundError:
        pass
    return jsonify({"ok": True, "version": v})

from flask import Flask, request, jsonify
import os
import boto3
from uuid import uuid4

app = Flask(__name__)

# ---- helpers ----
def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{os.getenv('R2_ACCOUNT_ID')}.r2.cloudflarestorage.com",
        aws_access_key_id=os.getenv("R2_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("R2_SECRET_ACCESS_KEY"),
    )

S3_BUCKET = os.getenv("S3_BUCKET", "kinjar-media")

# ---- presign route ----
@app.route("/presign", methods=["POST"])
def presign():
    # --- auth guard ---
    api_key = request.headers.get("x-api-key")
    expected_keys = os.getenv("API_KEYS", "").split(",")
    if not api_key or api_key not in expected_keys:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    # --- tenant guard ---
    tenant = request.headers.get("x-tenant-slug")
    if not tenant:
        return jsonify({"ok": False, "error": "missing tenant slug"}), 400

    # --- parse request body ---
    data = request.get_json(force=True)
    filename = data.get("filename")
    content_type = data.get("contentType")
    if not filename or not content_type:
        return jsonify({"ok": False, "error": "filename and contentType required"}), 400

    # --- generate unique key ---
    key = f"t/{tenant}/posts/{uuid4()}/{filename}"

    # --- presign PUT url ---
    s3 = s3_client()
    put_url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": S3_BUCKET,
            "Key": key,
            "ContentType": content_type,
        },
        ExpiresIn=int(os.getenv("PRESIGN_EXPIRES_SECONDS", "60")),
    )

    return jsonify({
        "ok": True,
        "key": key,
        "put": {
            "url": put_url,
            "headers": { "Content-Type": content_type }
        }
    })


@app.get("/r2/head")
def r2_head():
    unauthorized = require_api_key()
    if unauthorized:
        return unauthorized
    key = request.args.get("key")
    if not key:
        return make_response(jsonify({"ok": False, "error": "Missing key"}), 400)
    try:
        s3 = s3_client()
        obj = s3.head_object(Bucket=S3_BUCKET, Key=key)
        return jsonify({"ok": True, "exists": True, "size": obj.get("ContentLength"), "contentType": obj.get("ContentType")})
    except Exception as e:
        return jsonify({"ok": True, "exists": False, "error": str(e)})

# Global error handler (clean JSON)
@app.errorhandler(Exception)
def handle_unexpected(e):
    logger.exception("unhandled error")
    return make_response(jsonify({"ok": False, "error": str(e)}), 500)

# Gunicorn entrypoint expects "app:app"
if __name__ == "__main__":
    # Dev server (not used on Fly)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
