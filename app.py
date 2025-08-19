import os
import logging
from uuid import uuid4
from flask import Flask, request, jsonify, make_response
import boto3
from botocore.config import Config as BotoConfig

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kinjar-api")

# ---------- ENV HELPERS ----------
def env_str(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing env var: {name}")
    return val

def env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]

# Required
R2_ACCOUNT_ID = env_str("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = env_str("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = env_str("R2_SECRET_ACCESS_KEY")
S3_BUCKET = env_str("S3_BUCKET")  # your notes use S3_BUCKET=kinjar-media

# Optional
PUBLIC_MEDIA_BASE = os.getenv("PUBLIC_MEDIA_BASE", "")  # e.g. https://media.kinjar.com
API_KEYS = set(env_list("API_KEYS"))  # supports multiple keys, comma-separated
ALLOWED_ORIGINS = set(env_list("ALLOWED_ORIGINS"))      # CORS allowlist for API
PORT = int(os.getenv("PORT", "8080"))

# ---------- R2 CLIENT ----------
def s3_client():
    # Cloudflare R2 requires SigV4; "auto" region; account-id subdomain
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        region_name="auto",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )

# ---------- UTIL ----------
def is_authorized(req) -> bool:
    if not API_KEYS:
        return True  # open if not configured
    supplied = (
        req.headers.get("x-api-key")
        or req.headers.get("Authorization", "").replace("Bearer ", "")
    )
    return supplied in API_KEYS

def corsify(resp, origin: str | None):
    if origin and (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    return resp

@app.after_request
def add_common_headers(resp):
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin")
        if origin and (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Vary"] = "Origin"
    return resp

# ---------- ROUTES ----------
@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "bucket": S3_BUCKET,
        "public_media_base": PUBLIC_MEDIA_BASE or None,
        "allowed_origins": list(ALLOWED_ORIGINS) or ["* (not restricted)"],
    })

@app.post("/presign")
def presign():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant = (request.headers.get("x-tenant-slug") or "default").strip() or "default"
    body = request.get_json(silent=True) or {}
    filename = (body.get("filename") or "file.bin").replace("\\", "/").split("/")[-1]
    ctype = body.get("contentType") or "application/octet-stream"

    key = f"t/{tenant}/posts/{uuid4()}/{filename}"
    try:
        s3 = s3_client()
        put_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": ctype},
            ExpiresIn=300,
            HttpMethod="PUT",
        )
        resp = {
            "ok": True,
            "key": key,
            "maxMB": 50,
            "put": {"url": put_url, "headers": {"Content-Type": ctype}},
        }
        if PUBLIC_MEDIA_BASE:
            resp["publicUrl"] = f"{PUBLIC_MEDIA_BASE.rstrip('/')}/{key}"
        return corsify(jsonify(resp), origin)
    except Exception:
        log.exception("presign failed")
        return corsify(jsonify({"ok": False, "error": "presign_failed"}), origin), 500

@app.get("/r2/head")
def head_meta():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing key"}), origin), 400

    try:
        s3 = s3_client()
        h = s3.head_object(Bucket=S3_BUCKET, Key=key)
        return corsify(jsonify({
            "ok": True,
            "key": key,
            "size": h.get("ContentLength"),
            "type": h.get("ContentType"),
            "etag": h.get("ETag"),
        }), origin)
    except Exception:
        return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404

# CORS preflight endpoints
@app.route("/presign", methods=["OPTIONS"])
@app.route("/r2/head", methods=["OPTIONS"])
def options():
    return make_response(("", 204))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
