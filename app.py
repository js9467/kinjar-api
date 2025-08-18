import os
import json
import logging
from typing import List, Optional
from uuid import uuid4
from urllib.parse import urlparse

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import boto3
from botocore.config import Config as BotoConfig

import psycopg
from psycopg_pool import ConnectionPool

# ----------------------------
# DB (Neon / Postgres)
# ----------------------------
DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. postgresql://user:pass@proj.pooler.neon.tech/db?sslmode=require
DB_POOL: ConnectionPool | None = None


def db_exec(sql: str, params: tuple = ()):
    if not DATABASE_URL or not DB_POOL:
        return
    with DB_POOL.connection() as conn:
        conn.execute(sql, params)


def db_fetchall(sql: str, params: tuple = ()):
    if not DATABASE_URL or not DB_POOL:
        return []
    with DB_POOL.connection() as conn:
        with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def init_db():
    """Tiny pool + create table if missing."""
    global DB_POOL
    if not DATABASE_URL:
        return
    DB_POOL = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=4,
        timeout=10,
        kwargs={"autocommit": True},
    )
    with DB_POOL.connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
              key TEXT PRIMARY KEY,
              tenant_slug TEXT NOT NULL,
              filename TEXT NOT NULL,
              content_type TEXT NOT NULL,
              status TEXT NOT NULL,   -- 'presigned' | 'uploaded'
              size BIGINT,
              etag TEXT,
              version_id TEXT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )

# ----------------------------
# Env helpers
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

# Security (comma-separated list)
API_KEYS: List[str] = [x.strip() for x in os.getenv("API_KEYS", "").split(",") if x.strip()]

# CORS
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()]

# R2 / S3-compatible storage
S3_ENDPOINT = os.getenv("S3_ENDPOINT")
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
if not S3_ENDPOINT and R2_ACCOUNT_ID:
    S3_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

S3_ACCESS_KEY = env_str("S3_ACCESS_KEY_ID", os.getenv("R2_ACCESS_KEY_ID"))
S3_SECRET_KEY = env_str("S3_SECRET_ACCESS_KEY", os.getenv("R2_SECRET_ACCESS_KEY"))
S3_BUCKET = env_str("S3_BUCKET")

PRESIGN_EXPIRES_SECONDS = env_int("PRESIGN_EXPIRES_SECONDS", 60)
PRESIGN_MAX_MB = env_int("PRESIGN_MAX_MB", 50)
PRESIGN_PREFIX = os.getenv("PRESIGN_PREFIX", "t/")
REQUIRE_TENANT = os.getenv("REQUIRE_TENANT", "1") in ("1", "true", "TRUE")

# Optional public base (e.g., r2.dev or CDN) for direct viewing
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. https://kinjar-media.r2.dev

# ----------------------------
# App setup
# ----------------------------
app = Flask(APP_NAME)
init_db()

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(APP_NAME)

if ALLOWED_ORIGINS:
    CORS(app, supports_credentials=False, origins=ALLOWED_ORIGINS)
else:
    CORS(app, supports_credentials=False, origins=[])

# ----------------------------
# Helpers
# ----------------------------
def require_api_key():
    """Require X-API-Key for sensitive routes."""
    if not API_KEYS:
        logger.warning("API_KEYS is empty; sensitive endpoints are unsecured!")
        return
    provided = request.headers.get("X-API-Key") or request.headers.get("x-api-key") or request.args.get("api_key")
    if not provided or provided not in API_KEYS:
        return make_response(jsonify({"ok": False, "error": "Unauthorized"}), 401)


def parse_tenant_slug() -> Optional[str]:
    slug = request.headers.get("x-tenant-slug")
    if slug:
        return slug.strip()
    if request.is_json:
        data = (request.get_json(silent=True) or {})
        s = (data.get("tenant_slug") or "").strip()
        if s:
            return s
    return None


def s3_client():
    if not S3_ENDPOINT:
        raise RuntimeError("S3_ENDPOINT (or R2_ACCOUNT_ID) is required")
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,  # https://<ACCOUNT>.r2.cloudflarestorage.com
        region_name="auto",        # required for R2 SigV4
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=BotoConfig(
            signature_version="s3v4",           # force SigV4
            s3={"addressing_style": "virtual"}, # needed for R2
        ),
    )


def public_url_for(key: str) -> str:
    """Build a public URL if the bucket is public; else, caller should use /presign-get."""
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL.rstrip('/')}/{key.lstrip('/')}"
    host = urlparse(S3_ENDPOINT).netloc  # e.g. 6023...c616.r2.cloudflarestorage.com
    return f"https://{S3_BUCKET}.{host}/{key}"

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


@app.get("/presign-get")
def presign_get():
    unauthorized = require_api_key()
    if unauthorized:
        return unauthorized
    key = request.args.get("key")
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    s3 = s3_client()
    url = s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": S3_BUCKET, "Key": key},
        ExpiresIn=60,
    )
    return jsonify({"ok": True, "url": url})


@app.post("/presign")
def presign():
    # Auth
    unauthorized = require_api_key()
    if unauthorized:
        return unauthorized

    # Tenant (optional enforcement)
    tenant = parse_tenant_slug()
    if REQUIRE_TENANT and not tenant:
        return jsonify({"ok": False, "error": "missing tenant slug"}), 400
    tenant = tenant or "default"

    # Body
    data = request.get_json(force=True)
    filename = data.get("filename")
    content_type = data.get("contentType")
    if not filename or not content_type:
        return jsonify({"ok": False, "error": "filename and contentType required"}), 400

    # Guard key prefix if configured
    prefix = (PRESIGN_PREFIX + "/") if (PRESIGN_PREFIX and not PRESIGN_PREFIX.endswith("/")) else PRESIGN_PREFIX
    key = f"{prefix}{tenant}/posts/{uuid4()}/{filename}"

    # Generate presigned PUT URL (R2 supports PUT, not POST)
    s3 = s3_client()
    put_url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": S3_BUCKET,
            "Key": key,
            "ContentType": content_type,
            # Optionally add cache control:
            # "CacheControl": "public, max-age=31536000, immutable",
        },
        ExpiresIn=PRESIGN_EXPIRES_SECONDS,
    )

    # record presign intent in DB
    db_exec(
        """
        INSERT INTO assets (key, tenant_slug, filename, content_type, status)
        VALUES (%s, %s, %s, %s, 'presigned')
        ON CONFLICT (key) DO UPDATE SET
          tenant_slug = EXCLUDED.tenant_slug,
          filename = EXCLUDED.filename,
          content_type = EXCLUDED.content_type,
          status = 'presigned',
          updated_at = now();
        """,
        (key, tenant, filename, content_type),
    )

    return jsonify(
        {
            "ok": True,
            "key": key,
            "put": {"url": put_url, "headers": {"Content-Type": content_type}},
            "publicUrl": public_url_for(key),  # if bucket is public, this will work directly
            "maxMB": PRESIGN_MAX_MB,
        }
    )


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

        # update DB on success
        size = obj.get("ContentLength")
        ctype = obj.get("ContentType")
        etag = obj.get("ETag")
        version_id = obj.get("VersionId")
        db_exec(
            """
            UPDATE assets
               SET status = 'uploaded',
                   size = %s,
                   etag = %s,
                   version_id = %s,
                   content_type = %s,
                   updated_at = now()
             WHERE key = %s;
            """,
            (size, etag, version_id, ctype, key),
        )

        return jsonify(
            {
                "ok": True,
                "exists": True,
                "size": size,
                "contentType": ctype,
            }
        )
    except Exception as e:
        return jsonify({"ok": True, "exists": False, "error": str(e)})


@app.get("/assets")
def list_assets():
    unauthorized = require_api_key()
    if unauthorized:
        return unauthorized
    tenant = parse_tenant_slug() or request.args.get("tenant") or "default"
    rows = db_fetchall(
        """
        SELECT key, filename, content_type, status, size, etag, version_id, created_at, updated_at
          FROM assets
         WHERE tenant_slug = %s
         ORDER BY created_at DESC
         LIMIT 50
        """,
        (tenant,),
    )
    return jsonify({"ok": True, "tenant": tenant, "items": rows})


@app.get("/diag/db")
def diag_db():
    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "DATABASE_URL not set"}), 500
    if not DB_POOL:
        return jsonify({"ok": False, "error": "DB pool not initialized"}), 500
    try:
        with DB_POOL.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("select current_database(), current_user, now()")
                db, usr, ts = cur.fetchone()
        return jsonify({"ok": True, "db": db, "user": usr, "now": ts.isoformat()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/diag/s3")
def diag_s3():
    try:
        c = s3_client()
        test_url = c.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET, "Key": "diag/test.txt", "ContentType": "text/plain"},
            ExpiresIn=60,
        )
        return jsonify(
            {
                "ok": True,
                "sigv4_in_url": ("X-Amz-Signature=" in test_url) or ("X-Amz-Algorithm=AWS4-HMAC-SHA256" in test_url),
                "url_sample": test_url[:120] + "...",
                "config_sigver": getattr(getattr(c, "meta", None), "config", None).signature_version
                if getattr(getattr(c, "meta", None), "config", None)
                else None,
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/diag/routes")
def diag_routes():
    try:
        return jsonify(
            {
                "ok": True,
                "routes": [f"{r.rule} -> {','.join(sorted(r.methods or []))}" for r in app.url_map.iter_rules()],
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# Global error handler
@app.errorhandler(Exception)
def handle_unexpected(e):
    logger.exception("unhandled error")
    return make_response(jsonify({"ok": False, "error": str(e)}), 500)


# Dev entry
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
