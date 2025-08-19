import os
import re
import time
import json
import logging
from uuid import uuid4
from typing import Optional, List

from flask import Flask, request, jsonify, make_response

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

import psycopg
from psycopg_pool import ConnectionPool

# ---------------- Setup ----------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kinjar-api")

def env_str(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing env var: {name}")
    return val

def env_list(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]

# Required (R2)
S3_BUCKET = env_str("S3_BUCKET")
R2_ACCOUNT_ID = env_str("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = env_str("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = env_str("R2_SECRET_ACCESS_KEY")

# Required (Neon)
DATABASE_URL = env_str("DATABASE_URL")

# Optional
PUBLIC_MEDIA_BASE = os.getenv("PUBLIC_MEDIA_BASE", "")
API_KEYS = set(env_list("API_KEYS"))                      # comma-separated supported
ALLOWED_ORIGINS = set(env_list("ALLOWED_ORIGINS"))        # for API CORS
PORT = int(os.getenv("PORT", "8080"))
DATA_DIR = os.getenv("DATA_DIR", "/data")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")

# Security/validation knobs
ALLOWED_CONTENT_TYPES = set((
    "image/jpeg", "image/png", "image/webp", "image/gif",
    "video/mp4", "video/quicktime",
    "text/plain", "application/pdf"
))
TENANT_RE = re.compile(r"^[a-z0-9-]{1,63}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")

# ---------------- R2 client ----------------
def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        region_name="auto",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )

# ---------------- DB (Neon) ----------------
import psycopg
from psycopg_pool import ConnectionPool

DATABASE_URL = os.getenv("DATABASE_URL")  # may be unset/invalid at boot
pool = None
DB_READY = False
DB_ERR = None

DDL = """
CREATE TABLE IF NOT EXISTS media_objects (
  id            uuid PRIMARY KEY,
  tenant        text NOT NULL,
  r2_key        text NOT NULL UNIQUE,
  filename      text NOT NULL,
  content_type  text NOT NULL,
  size_bytes    bigint,
  status        text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_media_objects_tenant_created ON media_objects (tenant, created_at DESC);
"""

def db_connect_once():
    global pool, DB_READY, DB_ERR
    if DB_READY or DB_ERR:
        return
    try:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set")
        from psycopg_pool import ConnectionPool
        pool = ConnectionPool(
            DATABASE_URL,
            min_size=0,
            max_size=5,
            kwargs={"autocommit": True, "prepare_threshold": 0},
        )
        with pool.connection() as con, con.cursor() as cur:
            # Run DDL in separate statements (psycopg3 disallows multiple-in-one)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS media_objects (
                  id            uuid PRIMARY KEY,
                  tenant        text NOT NULL,
                  r2_key        text NOT NULL UNIQUE,
                  filename      text NOT NULL,
                  content_type  text NOT NULL,
                  size_bytes    bigint,
                  status        text NOT NULL,           -- presigned | uploaded | deleted
                  created_at    timestamptz NOT NULL DEFAULT now(),
                  updated_at    timestamptz NOT NULL DEFAULT now(),
                  deleted_at    timestamptz
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_media_objects_tenant_created
                  ON media_objects (tenant, created_at DESC);
            """)
        DB_READY = True
        DB_ERR = None
    except Exception as e:
        DB_ERR = str(e)
        log.exception("DB init failed; continuing without DB")


def with_db():
    db_connect_once()
    if not DB_READY:
        raise RuntimeError(f"DB not ready: {DB_ERR or 'unknown'}")

def db_insert_presign(mid, tenant, key, filename, ctype):
    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute(
            """INSERT INTO media_objects (id, tenant, r2_key, filename, content_type, status)
               VALUES (%s,%s,%s,%s,%s,'presigned')
               ON CONFLICT (r2_key) DO NOTHING""",
            (mid, tenant, key, filename, ctype),
        )

def db_mark_uploaded(key, size, ctype):
    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute(
            """UPDATE media_objects
                  SET status='uploaded',
                      size_bytes=COALESCE(%s,size_bytes),
                      content_type=COALESCE(%s,content_type),
                      updated_at=now()
                WHERE r2_key=%s""",
            (size, ctype, key),
        )

def db_soft_delete(key):
    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute(
            "UPDATE media_objects SET status='deleted', deleted_at=now(), updated_at=now() WHERE r2_key=%s",
            (key,),
        )

def db_list(tenant, limit=50):
    with_db()
    with pool.connection() as con, con.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            """SELECT id, tenant, r2_key AS key, filename, content_type,
                      size_bytes AS size, status, created_at, updated_at, deleted_at
               FROM media_objects
               WHERE tenant=%s AND deleted_at IS NULL
               ORDER BY created_at DESC
               LIMIT %s""",
            (tenant, limit),
        )
        return list(cur.fetchall())

# ---------------- helpers ----------------
def is_authorized(req) -> bool:
    if not API_KEYS:
        return True
    supplied = req.headers.get("x-api-key") or req.headers.get("Authorization", "").replace("Bearer ", "")
    return supplied in API_KEYS

def corsify(resp, origin: Optional[str]):
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
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Vary"] = "Origin"
    return resp

def sanitize_tenant(tenant: str) -> Optional[str]:
    t = (tenant or "default").strip().lower()
    return t if TENANT_RE.match(t) else None

def sanitize_filename(name: str) -> Optional[str]:
    n = (name or "file.bin").replace("\\","/").split("/")[-1]
    return n if FILENAME_RE.match(n) else None

def audit(event: str, **fields):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            rec = {"ts": int(time.time()), "event": event, **fields}
            f.write(json.dumps(rec) + "\n")
    except Exception:
        log.exception("audit write failed")

# ---------------- Routes ----------------
@app.get("/health")
def health():
    db_connect_once()
    return jsonify({
        "status": "ok",
        "bucket": S3_BUCKET,
        "public_media_base": PUBLIC_MEDIA_BASE or None,
        "allowed_origins": list(ALLOWED_ORIGINS) or ["* (not restricted)"],
        "db_ready": DB_READY,
        "db_error": DB_ERR,
    })


@app.post("/presign")
def presign():
    origin = request.headers.get("Origin")

    # Auth
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    # Tenant + input validation
    tenant = sanitize_tenant(request.headers.get("x-tenant-slug", "default"))
    if not tenant:
        return corsify(jsonify({"ok": False, "error": "invalid_tenant"}), origin), 400

    body = request.get_json(silent=True) or {}
    filename = sanitize_filename(body.get("filename", "file.bin"))
    if not filename:
        return corsify(jsonify({"ok": False, "error": "invalid_filename"}), origin), 400

    ctype = (body.get("contentType") or "application/octet-stream").strip()
    if ALLOWED_CONTENT_TYPES and ctype not in ALLOWED_CONTENT_TYPES:
        return corsify(jsonify({"ok": False, "error": "unsupported_content_type"}), origin), 415

    # Generate object key (id also used as DB primary key)
    mid = str(uuid4())
    key = f"t/{tenant}/posts/{mid}/{filename}"

    # Sign the PUT (do NOT sign Content-Type)
    try:
        s3 = s3_client()
        put_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": key,
                # NOTE: Intentionally NO "ContentType" here
            },
            ExpiresIn=300,
            HttpMethod="PUT",
        )
    except Exception:
        log.exception("presign failed while signing")
        return corsify(jsonify({"ok": False, "error": "presign_failed"}), origin), 500

    # Best-effort DB record; never block presign on DB availability
    try:
        db_insert_presign(mid, tenant, key, filename, ctype)
    except Exception:
        log.exception("DB insert failed during presign; continuing without DB")

    # Response
    resp = {
        "ok": True,
        "id": mid,
        "key": key,
        "maxMB": 50,
        "put": {
            "url": put_url,
            # Client hint only — header is NOT required by the signature
            "headers": {"Content-Type": ctype},
        },
    }
    if PUBLIC_MEDIA_BASE:
        resp["publicUrl"] = f"{PUBLIC_MEDIA_BASE.rstrip('/')}/{key}"

    audit("presign", tenant=tenant, id=mid, key=key, ctype=ctype)
    return corsify(jsonify(resp), origin)




@app.get("/r2/head")
def head_meta():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing_key"}), origin), 400

    try:
        h = s3_client().head_object(Bucket=S3_BUCKET, Key=key)
        size = h.get("ContentLength")
        ctype = h.get("ContentType")
        db_mark_uploaded(key, size, ctype)
        audit("head", key=key, status="ok", size=size, type=ctype)
        return corsify(jsonify({
            "ok": True,
            "key": key,
            "size": size,
            "type": ctype,
            "etag": h.get("ETag"),
        }), origin)
    except ClientError as e:
        audit("head", key=key, status="miss", err=str(e))
        return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404

# GET /media/signed-get?key=...&expires=300
@app.get("/media/signed-get")
def signed_get():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    expires = min(max(int(request.args.get("expires", "300")), 60), 3600)
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing_key"}), origin), 400

    try:
        url = s3_client().generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": S3_BUCKET, "Key": key},
            ExpiresIn=expires,
            HttpMethod="GET",
        )
        audit("signed_get", key=key, expires=expires)
        return corsify(jsonify({"ok": True, "url": url, "expires": expires}), origin)
    except Exception:
        log.exception("signed_get failed")
        return corsify(jsonify({"ok": False, "error": "sign_failed"}), origin), 500

# GET /media/list?tenant=slug&limit=50
# lists from DB (fast), not directly from R2
@app.get("/media/list")
def list_media():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant = sanitize_tenant(request.args.get("tenant", ""))
    if not tenant:
        return corsify(jsonify({"ok": False, "error": "invalid_tenant"}), origin), 400

    limit = min(max(int(request.args.get("limit", "50")), 1), 1000)
    try:
        items = db_list(tenant, limit)
        audit("list", tenant=tenant, count=len(items))
        return corsify(jsonify({"ok": True, "items": items}), origin)
    except Exception:
        log.exception("list failed")
        return corsify(jsonify({"ok": False, "error": "list_failed"}), origin), 500

# DELETE /media/delete?key=...
@app.delete("/media/delete")
def delete_media():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing_key"}), origin), 400

    # basic multi-tenant guard
    tenant = sanitize_tenant(request.headers.get("x-tenant-slug", ""))
    if not tenant or not key.startswith(f"t/{tenant}/"):
        return corsify(jsonify({"ok": False, "error": "forbidden_key"}), origin), 403

    try:
        s3_client().delete_object(Bucket=S3_BUCKET, Key=key)
        db_soft_delete(key)
        audit("delete", key=key, tenant=tenant)
        return corsify(jsonify({"ok": True}), origin)
    except Exception:
        log.exception("delete failed")
        return corsify(jsonify({"ok": False, "error": "delete_failed"}), origin), 500

# CORS preflight
@app.route("/presign", methods=["OPTIONS"])
@app.route("/r2/head", methods=["OPTIONS"])
@app.route("/media/signed-get", methods=["OPTIONS"])
@app.route("/media/list", methods=["OPTIONS"])
@app.route("/media/delete", methods=["OPTIONS"])
def options():
    return make_response(("", 204))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
