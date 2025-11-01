import os
import re
import time
import json
import logging
import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any

from flask import Flask, request, jsonify, make_response

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from argon2 import PasswordHasher
import jwt

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

# Required (R2) - make optional for development
S3_BUCKET = os.getenv("S3_BUCKET", "kinjar-dev-bucket")
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")

# Required (Neon) - make optional for development
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/kinjar_dev")

# Optional
PUBLIC_MEDIA_BASE = os.getenv("PUBLIC_MEDIA_BASE", "")
API_KEYS = set(env_list("API_KEYS"))                      # comma-separated supported
ALLOWED_ORIGINS = set(env_list("ALLOWED_ORIGINS"))        # for API CORS
PORT = int(os.getenv("PORT", "8080"))
DATA_DIR = os.getenv("DATA_DIR", "/data")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")
ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "kinjar.com")

# Auth / Session
JWT_SECRET = os.getenv("JWT_SECRET", "temp-dev-secret-change-in-production")  # Temporary default for development
JWT_ALG = "HS256"
JWT_TTL_MIN = 60 * 24 * 14  # 14 days
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", None)
ROOT_EMAILS = set(env_list("ROOT_EMAILS"))

ph = PasswordHasher()

# Security/validation knobs
ALLOWED_CONTENT_TYPES = set((
    "image/jpeg", "image/png", "image/webp", "image/gif",
    "video/mp4", "video/quicktime",
    "text/plain", "application/pdf"
))
TENANT_RE = re.compile(r"^[a-z0-9-]{1,63}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
TENANT_ROLES = {"OWNER", "ADMIN", "MEMBER"}

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
DATABASE_URL = os.getenv("DATABASE_URL")  # may be unset/invalid at boot
pool: Optional[ConnectionPool] = None
DB_READY = False
DB_ERR = None

def db_connect_once():
    """
    Initialize global connection pool and run DDL (idempotent).
    """
    global pool, DB_READY, DB_ERR
    if DB_READY or DB_ERR:
        return
    try:
        if not DATABASE_URL or DATABASE_URL == "postgresql://localhost/kinjar_dev":
            log.warning("DATABASE_URL not set or using development default - some features may not work")
            DB_ERR = "Database not configured"
            return
            
        pool = ConnectionPool(
            DATABASE_URL,
            min_size=0,
            max_size=5,
            kwargs={"autocommit": True, "prepare_threshold": 0},
        )
        with pool.connection() as con, con.cursor() as cur:
            # --- existing media_objects DDL ---
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

            # --- NEW: users / tenants / memberships / signup_requests ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                  id            uuid PRIMARY KEY,
                  email         text UNIQUE NOT NULL,
                  password_hash text,
                  global_role   text NOT NULL DEFAULT 'USER',
                  created_at    timestamptz NOT NULL DEFAULT now()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                  id         uuid PRIMARY KEY,
                  slug       text UNIQUE NOT NULL,
                  name       text NOT NULL,
                  created_at timestamptz NOT NULL DEFAULT now()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenant_users (
                  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  role      text NOT NULL DEFAULT 'OWNER',
                  PRIMARY KEY (user_id, tenant_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS global_settings (
                  key        text PRIMARY KEY,
                  value      jsonb NOT NULL,
                  updated_at timestamptz NOT NULL DEFAULT now()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenant_settings (
                  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  key       text NOT NULL,
                  value     jsonb NOT NULL,
                  updated_at timestamptz NOT NULL DEFAULT now(),
                  PRIMARY KEY (tenant_id, key)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS signup_requests (
                  id             uuid PRIMARY KEY,
                  email          text NOT NULL,
                  password_hash  text NOT NULL,
                  tenant_name    text NOT NULL,
                  desired_slug   text,
                  status         text NOT NULL DEFAULT 'pending', -- pending|approved|denied
                  created_at     timestamptz NOT NULL DEFAULT now(),
                  decided_at     timestamptz,
                  decided_by     uuid,
                  decision_reason text
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_signup_requests_status_created
                  ON signup_requests (status, created_at DESC);
            """)

            # --- VIDEO BLOG FEATURES ---
            # Enhanced media_objects to include more metadata
            cur.execute("""
                ALTER TABLE media_objects 
                ADD COLUMN IF NOT EXISTS title text,
                ADD COLUMN IF NOT EXISTS description text,
                ADD COLUMN IF NOT EXISTS thumbnail_url text,
                ADD COLUMN IF NOT EXISTS duration_seconds integer,
                ADD COLUMN IF NOT EXISTS width integer,
                ADD COLUMN IF NOT EXISTS height integer,
                ADD COLUMN IF NOT EXISTS uploaded_by uuid REFERENCES users(id),
                ADD COLUMN IF NOT EXISTS is_public boolean DEFAULT false,
                ADD COLUMN IF NOT EXISTS view_count integer DEFAULT 0;
            """)

            # Content posts - represents a video blog post
            cur.execute("""
                CREATE TABLE IF NOT EXISTS content_posts (
                  id            uuid PRIMARY KEY,
                  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  author_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  media_id      uuid REFERENCES media_objects(id) ON DELETE SET NULL,
                  title         text NOT NULL,
                  content       text,                    -- main text content/commentary
                  content_type  text NOT NULL DEFAULT 'video_blog', -- video_blog, photo_blog, text_post
                  status        text NOT NULL DEFAULT 'published', -- draft, published, archived
                  is_public     boolean DEFAULT true,
                  view_count    integer DEFAULT 0,
                  created_at    timestamptz NOT NULL DEFAULT now(),
                  updated_at    timestamptz NOT NULL DEFAULT now(),
                  published_at  timestamptz
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_posts_tenant_published
                  ON content_posts (tenant_id, published_at DESC) WHERE status = 'published';
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_posts_author
                  ON content_posts (author_id, created_at DESC);
            """)

            # Comments on content posts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS content_comments (
                  id         uuid PRIMARY KEY,
                  post_id    uuid NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
                  author_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  parent_id  uuid REFERENCES content_comments(id) ON DELETE CASCADE, -- for threaded comments
                  content    text NOT NULL,
                  status     text NOT NULL DEFAULT 'published', -- published, hidden, deleted
                  created_at timestamptz NOT NULL DEFAULT now(),
                  updated_at timestamptz NOT NULL DEFAULT now()
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_comments_post_created
                  ON content_comments (post_id, created_at ASC) WHERE status = 'published';
            """)

            # User invitations to tenants
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenant_invitations (
                  id           uuid PRIMARY KEY,
                  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  invited_by   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  email        text NOT NULL,
                  role         text NOT NULL DEFAULT 'MEMBER',
                  status       text NOT NULL DEFAULT 'pending', -- pending, accepted, expired, revoked
                  invite_token text UNIQUE NOT NULL,
                  expires_at   timestamptz NOT NULL,
                  created_at   timestamptz NOT NULL DEFAULT now(),
                  accepted_at  timestamptz
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenant_invitations_tenant_status
                  ON tenant_invitations (tenant_id, status);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenant_invitations_token
                  ON tenant_invitations (invite_token) WHERE status = 'pending';
            """)

            # User profiles for additional info
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                  user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                  display_name text,
                  avatar_url  text,
                  bio         text,
                  phone       text,
                  updated_at  timestamptz NOT NULL DEFAULT now()
                );
            """)

            # Activity feed for showing recent actions
            cur.execute("""
                CREATE TABLE IF NOT EXISTS activity_feed (
                  id          uuid PRIMARY KEY,
                  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
                  action_type text NOT NULL, -- post_created, comment_added, user_joined, etc.
                  entity_type text NOT NULL, -- content_post, comment, user, etc.
                  entity_id   uuid,
                  metadata    jsonb,
                  created_at  timestamptz NOT NULL DEFAULT now()
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_activity_feed_tenant_created
                  ON activity_feed (tenant_id, created_at DESC);
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

# ---------------- Media helpers (existing) ----------------
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
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
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

# ---------------- Generic helpers ----------------
def is_authorized(req) -> bool:
    """
    API key guard for media endpoints (unchanged).
    Auth endpoints DO NOT require an API key.
    """
    if not API_KEYS:
        return True
    supplied = req.headers.get("x-api-key") or req.headers.get("Authorization", "").replace("Bearer ", "")
    return supplied in API_KEYS

def corsify(resp, origin: Optional[str]):
    if origin:
        # Allow specific origins from ALLOWED_ORIGINS OR any kinjar.com subdomain
        if (ALLOWED_ORIGINS and origin in ALLOWED_ORIGINS) or origin.endswith('.kinjar.com') or origin == 'https://kinjar.com':
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
            # Prevent caching of CORS responses
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        # Allow if ALLOWED_ORIGINS is empty (for testing)
        elif not ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
            # Prevent caching of CORS responses
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
    return resp

@app.after_request
def add_common_headers(resp):
    origin = request.headers.get("Origin")
    if origin:
        # Allow specific origins from ALLOWED_ORIGINS OR any kinjar.com subdomain
        if (ALLOWED_ORIGINS and origin in ALLOWED_ORIGINS) or origin.endswith('.kinjar.com') or origin == 'https://kinjar.com':
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
            # Prevent caching of CORS responses
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        # Allow if ALLOWED_ORIGINS is empty (for testing)
        elif not ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
            # Prevent caching of CORS responses
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
    return resp

def corsify(response, origin=None):
    """
    CORS helper function - returns response as-is since CORS headers
    are already handled by @app.after_request decorator
    """
    return response

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

# ---------------- Auth helpers ----------------
def sign_jwt(payload: Dict[str, Any]) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        return None

def set_session_cookie(resp, token: str):
    resp.set_cookie(
        "kinjar_session",
        token,
        httponly=True,
        secure=True,
        samesite="Lax",
        domain=COOKIE_DOMAIN if COOKIE_DOMAIN else None,
        max_age=JWT_TTL_MIN * 60,
        path="/",
    )

def clear_session_cookie(resp):
    resp.set_cookie(
        "kinjar_session",
        "",
        expires=0,
        httponly=True,
        secure=True,
        samesite="Lax",
        domain=COOKIE_DOMAIN if COOKIE_DOMAIN else None,
        path="/",
    )

def current_user_row() -> Optional[Dict[str, Any]]:
    token = request.cookies.get("kinjar_session")
    if not token:
        return None
    payload = verify_jwt(token)
    if not payload or "uid" not in payload:
        return None
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, email, global_role, created_at FROM users WHERE id = %s", (payload["uid"],))
        row = cur.fetchone()
        return row

def require_auth():
    user = current_user_row()
    if not user:
        return None, make_response(jsonify({"ok": False, "error": "Unauthorized"}), 401)
    return user, None

def require_root():
    user = current_user_row()
    if not user or user["global_role"] != "ROOT":
        return None, make_response(jsonify({"ok": False, "error": "Forbidden"}), 403)
    return user, None

def slugify_base(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    s = re.sub(r"-+", "-", s).strip("-")
    s = s or "family"
    return s[:63]

def unique_slug(conn, base: str) -> str:
    # ensure slug uniqueness; append short suffix if needed
    slug = base
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM tenants WHERE slug=%s", (slug,))
        i = 1
        while cur.fetchone() is not None:
            slug = f"{base}-{i}"
            cur.execute("SELECT 1 FROM tenants WHERE slug=%s", (slug,))
            i += 1
    return slug

def ensure_user_basic(con, email: str) -> Dict[str, Any]:
    email = email.strip().lower()
    if not email:
        raise ValueError("email_required")
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, email, global_role FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        if row:
            return {"id": str(row["id"]), "email": row["email"], "role": row["global_role"]}
    uid = str(uuid4())
    role = "ROOT" if email in ROOT_EMAILS else "USER"
    with con.cursor() as cur:
        cur.execute(
            """INSERT INTO users (id, email, password_hash, global_role)
                   VALUES (%s,%s,NULL,%s)""",
            (uid, email, role),
        )
    return {"id": uid, "email": email, "role": role}

def create_tenant(con, name: str, desired_slug: Optional[str], owner_user_id: Optional[str] = None) -> Dict[str, Any]:
    base = slugify_base(desired_slug or name)
    if not TENANT_RE.match(base):
        base = slugify_base(base)
    slug = unique_slug(con, base)
    tid = str(uuid4())
    with con.cursor() as cur:
        cur.execute("INSERT INTO tenants (id, slug, name) VALUES (%s,%s,%s)", (tid, slug, name))
        if owner_user_id:
            cur.execute(
                """INSERT INTO tenant_users (user_id, tenant_id, role)
                       VALUES (%s,%s,'OWNER')
                       ON CONFLICT (user_id, tenant_id) DO UPDATE SET role='OWNER'""",
                (owner_user_id, tid),
            )
    return {"id": tid, "slug": slug, "name": name}

# ---------------- Health & Status Routes ----------------
# Note: /health endpoint is defined later in the file around line 1149

@app.get("/status")
def status():
    origin = request.headers.get("Origin")
    return corsify(jsonify({
        "ok": True,
        "service": "kinjar-api",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), origin)

# ---------------- Auth & Accounts Routes ----------------
@app.post("/auth/login")
def auth_login():
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return corsify(jsonify({"ok": False, "error": "Missing email or password"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, email, password_hash, global_role, created_at FROM users WHERE email=%s", (email,))
        row = cur.fetchone()

    if not row or not row["password_hash"]:
        return corsify(jsonify({"ok": False, "error": "Invalid credentials"}), origin), 401

    try:
        ph.verify(row["password_hash"], password)
    except Exception:
        return corsify(jsonify({"ok": False, "error": "Invalid credentials"}), origin), 401

    now = int(datetime.datetime.utcnow().timestamp())
    token = sign_jwt({"uid": str(row["id"]), "iat": now, "exp": now + JWT_TTL_MIN * 60})
    resp = make_response(jsonify({"ok": True, "user": {k: row[k] for k in ("id", "email", "global_role", "created_at")}}))
    set_session_cookie(resp, token)
    return corsify(resp, origin)

@app.get("/auth/me")
def auth_me():
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    # include tenants memberships
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
          SELECT t.id, t.slug, t.name, tu.role
          FROM tenant_users tu
          JOIN tenants t ON t.id = tu.tenant_id
          WHERE tu.user_id = %s
          ORDER BY t.created_at DESC
        """, (user["id"],))
        tenants = list(cur.fetchall())
    return corsify(jsonify({"ok": True, "user": user, "tenants": tenants}), origin)

@app.post("/auth/logout")
def auth_logout():
    origin = request.headers.get("Origin")
    resp = make_response(jsonify({"ok": True}))
    clear_session_cookie(resp)
    return corsify(resp, origin)

@app.post("/auth/change-password")
def auth_change_password():
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    data = request.get_json(silent=True) or {}
    current_password = data.get("currentPassword") or ""
    new_password = data.get("newPassword") or ""
    
    if not current_password or not new_password:
        return corsify(jsonify({"ok": False, "error": "Missing current or new password"}), origin), 400
    
    if len(new_password) < 8:
        return corsify(jsonify({"ok": False, "error": "New password must be at least 8 characters"}), origin), 400
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Verify current password
        cur.execute("SELECT password_hash FROM users WHERE id=%s", (user["id"],))
        row = cur.fetchone()
        
        if not row or not row["password_hash"]:
            return corsify(jsonify({"ok": False, "error": "Account has no password set"}), origin), 400
        
        try:
            ph.verify(row["password_hash"], current_password)
        except Exception:
            return corsify(jsonify({"ok": False, "error": "Current password is incorrect"}), origin), 401
        
        # Update to new password
        new_password_hash = ph.hash(new_password)
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_password_hash, user["id"]))
    
    audit("password_changed", user=str(user["id"]))
    return corsify(jsonify({"ok": True, "message": "Password changed successfully"}), origin)

@app.post("/auth/forgot-password")
def auth_forgot_password():
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    
    if not email:
        return corsify(jsonify({"ok": False, "error": "Email is required"}), origin), 400
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, email FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        
        if not user:
            # Don't reveal if email exists - always return success
            return corsify(jsonify({"ok": True, "message": "If the email exists, a reset link has been sent"}), origin)
        
        # TODO: Generate reset token and send email
        # For now, just log it for demo purposes
        log.info(f"Password reset requested for {email}")
        audit("password_reset_requested", user=str(user["id"]))
    
    return corsify(jsonify({"ok": True, "message": "If the email exists, a reset link has been sent"}), origin)

# Optional: self-serve register for ROOT emails only (bootstrap)
@app.post("/auth/register")
def auth_register():
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password or len(password) < 8:
        return corsify(jsonify({"ok": False, "error": "Invalid email or password"}), origin), 400
    pw_hash = ph.hash(password)

    with_db()
    try:
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            uid = str(uuid4())
            role = "ROOT" if email in ROOT_EMAILS else "USER"
            cur.execute("""INSERT INTO users (id,email,password_hash,global_role)
                           VALUES (%s,%s,%s,%s) RETURNING id,email,global_role,created_at""",
                        (uid, email, pw_hash, role))
            user = cur.fetchone()
    except psycopg.errors.UniqueViolation:
        return corsify(jsonify({"ok": False, "error": "Email already registered"}), origin), 409

    now = int(datetime.datetime.utcnow().timestamp())
    token = sign_jwt({"uid": str(user["id"]), "iat": now, "exp": now + JWT_TTL_MIN * 60})
    resp = make_response(jsonify({"ok": True, "user": user}))
    set_session_cookie(resp, token)
    return corsify(resp, origin)

# ---------------- Signup Request (Queue) ----------------
@app.post("/signup/request")
def signup_request():
    """
    Public endpoint: user requests access & proposes a family (tenant).
    Admin will approve -> tenant created -> user created/updated -> OWNER.
    """
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    family_name = (data.get("familyName") or data.get("tenantName") or "").strip()
    desired_slug = (data.get("desiredSlug") or "").strip().lower()

    if not email or not password or len(password) < 8 or not family_name:
        return corsify(jsonify({"ok": False, "error": "invalid_input"}), origin), 400
    if desired_slug and not TENANT_RE.match(desired_slug):
        return corsify(jsonify({"ok": False, "error": "invalid_slug"}), origin), 400

    pw_hash = ph.hash(password)
    req_id = str(uuid4())

    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute("""INSERT INTO signup_requests
                       (id, email, password_hash, tenant_name, desired_slug, status)
                       VALUES (%s,%s,%s,%s,%s,'pending')""",
                    (req_id, email, pw_hash, family_name, desired_slug or None))

    audit("signup_request", email=email, tenant_name=family_name, slug=desired_slug or None, id=req_id)
    return corsify(jsonify({"ok": True, "requestId": req_id}), origin)

@app.get("/admin/signup/requests")
def listar_signup_requests():
    """
    Admin-only list; default status=pending
    """
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)
    status = request.args.get("status", "pending")
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("""SELECT id, email, tenant_name, desired_slug, status, created_at
                       FROM signup_requests
                       WHERE status=%s
                       ORDER BY created_at ASC""", (status,))
        items = list(cur.fetchall())
    return corsify(jsonify({"ok": True, "items": items}), origin)

def ensure_user_with_password(con, email: str, pw_hash: str) -> Dict[str, Any]:
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, email, password_hash, global_role FROM users WHERE email=%s", (email,))
        u = cur.fetchone()
        if u:
            # if no password set, set it; otherwise keep existing
            if not u["password_hash"]:
                cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, u["id"]))
            return {"id": str(u["id"]), "email": u["email"], "role": u["global_role"]}
        # create new user (USER; promote via ROOT_EMAILS if matches)
        uid = str(uuid4())
        role = "ROOT" if email in ROOT_EMAILS else "USER"
        cur.execute("""INSERT INTO users (id,email,password_hash,global_role)
                       VALUES (%s,%s,%s,%s)""", (uid, email, pw_hash, role))
        return {"id": uid, "email": email, "role": role}

@app.post("/admin/signup/approve")
def approve_signup():
    """
    Admin approves a signup request -> creates/updates user, creates tenant, maps OWNER.
    """
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    req_id = data.get("requestId") or ""
    if not req_id:
        return corsify(jsonify({"ok": False, "error": "missing_request_id"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM signup_requests WHERE id=%s FOR UPDATE", (req_id,))
        r = cur.fetchone()
        if not r:
            return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404
        if r["status"] != "pending":
            return corsify(jsonify({"ok": False, "error": f"already_{r['status']}"}), origin), 409

        # ensure user
        user = ensure_user_with_password(con, r["email"], r["password_hash"])
        # create tenant + membership
        tenant = create_tenant(con, r["tenant_name"], r["desired_slug"], user["id"])

        # mark request approved
        cur.execute("""UPDATE signup_requests
                       SET status='approved', decided_at=now(), decided_by=%s
                       WHERE id=%s""", (admin["id"], req_id))

    audit("signup_approved", request_id=req_id, tenant=tenant["slug"], email=r["email"])
    return corsify(jsonify({"ok": True, "tenant": tenant}), origin)

@app.post("/admin/signup/deny")
def deny_signup():
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    req_id = data.get("requestId") or ""
    reason = (data.get("reason") or "").strip() or None
    if not req_id:
        return corsify(jsonify({"ok": False, "error": "missing_request_id"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id,status FROM signup_requests WHERE id=%s FOR UPDATE", (req_id,))
        r = cur.fetchone()
        if not r:
            return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404
        if r["status"] != "pending":
            return corsify(jsonify({"ok": False, "error": f"already_{r['status']}"}), origin), 409

        cur.execute("""UPDATE signup_requests
                       SET status='denied', decided_at=now(), decided_by=%s, decision_reason=%s
                       WHERE id=%s""", (admin["id"], reason, req_id))

    audit("signup_denied", request_id=req_id, reason=reason)
    return corsify(jsonify({"ok": True}), origin)

def tenant_to_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "id": row["id"],
        "slug": row["slug"],
        "name": row["name"],
        "createdAt": row["created_at"].isoformat() if isinstance(row["created_at"], datetime.datetime) else row["created_at"],
    }
    if ROOT_DOMAIN:
        payload["domain"] = f"{row['slug']}.{ROOT_DOMAIN}"
    members = row.get("members")
    if members is not None:
        payload["members"] = members if isinstance(members, list) else json.loads(members)
    return payload

def fetch_tenant(con, tenant_id: str) -> Optional[Dict[str, Any]]:
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT t.id, t.slug, t.name, t.created_at,
                   COALESCE(json_agg(json_build_object('userId', tu.user_id, 'email', u.email, 'role', tu.role)
                                     ORDER BY tu.role)
                            FILTER (WHERE tu.user_id IS NOT NULL), '[]'::json) AS members
            FROM tenants t
            LEFT JOIN tenant_users tu ON tu.tenant_id = t.id
            LEFT JOIN users u ON u.id = tu.user_id
            WHERE t.id = %s
            GROUP BY t.id
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return tenant_to_payload(row)

@app.get("/admin/tenants")
def admin_list_tenants():
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT t.id, t.slug, t.name, t.created_at,
                   COALESCE(json_agg(json_build_object('userId', tu.user_id, 'email', u.email, 'role', tu.role)
                                     ORDER BY tu.role)
                            FILTER (WHERE tu.user_id IS NOT NULL), '[]'::json) AS members
            FROM tenants t
            LEFT JOIN tenant_users tu ON tu.tenant_id = t.id
            LEFT JOIN users u ON u.id = tu.user_id
            GROUP BY t.id
            ORDER BY t.created_at DESC
            """
        )
        tenants = [tenant_to_payload(row) for row in cur.fetchall()]

    return corsify(jsonify({"ok": True, "tenants": tenants}), origin)

@app.post("/admin/tenants")
def admin_create_tenant():
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or data.get("familyName") or "").strip()
    desired_slug = (data.get("slug") or data.get("desiredSlug") or "").strip().lower() or None
    owner_email = (data.get("ownerEmail") or "").strip().lower()
    if not name:
        return corsify(jsonify({"ok": False, "error": "name_required"}), origin), 400
    if desired_slug and not TENANT_RE.match(desired_slug):
        desired_slug = slugify_base(desired_slug)
        if not desired_slug or not TENANT_RE.match(desired_slug):
            return corsify(jsonify({"ok": False, "error": "invalid_slug"}), origin), 400

    with_db()
    with pool.connection() as con:
        owner = None
        if owner_email:
            try:
                owner = ensure_user_basic(con, owner_email)
            except ValueError:
                return corsify(jsonify({"ok": False, "error": "invalid_owner_email"}), origin), 400
        tenant = create_tenant(con, name, desired_slug, owner["id"] if owner else None)
        payload = fetch_tenant(con, tenant["id"])

    audit("tenant_created", tenant=tenant["slug"], admin=str(admin["id"]))
    return corsify(jsonify({"ok": True, "tenant": payload}), origin), 201

@app.patch("/admin/tenants/<tenant_id>")
def admin_update_tenant(tenant_id: str):
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    desired_slug = (data.get("slug") or data.get("desiredSlug") or "").strip().lower()

    if not name and not desired_slug:
        return corsify(jsonify({"ok": False, "error": "nothing_to_update"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, slug, name FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,))
        current = cur.fetchone()
        if not current:
            return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404

        updates = []
        values: List[Any] = []
        if name:
            updates.append("name=%s")
            values.append(name)
        if desired_slug:
            cleaned = desired_slug if TENANT_RE.match(desired_slug) else slugify_base(desired_slug)
            if not cleaned or not TENANT_RE.match(cleaned):
                return corsify(jsonify({"ok": False, "error": "invalid_slug"}), origin), 400
            with con.cursor() as c2:
                c2.execute("SELECT 1 FROM tenants WHERE slug=%s AND id<>%s", (cleaned, tenant_id))
                if c2.fetchone():
                    return corsify(jsonify({"ok": False, "error": "slug_in_use"}), origin), 409
            updates.append("slug=%s")
            values.append(cleaned)

        if updates:
            values.append(tenant_id)
            cur.execute(f"UPDATE tenants SET {', '.join(updates)} WHERE id=%s", values)

        payload = fetch_tenant(con, tenant_id)

    audit("tenant_updated", tenant=tenant_id, admin=str(admin["id"]))
    return corsify(jsonify({"ok": True, "tenant": payload}), origin)

@app.post("/admin/tenants/<tenant_id>/members")
def admin_add_tenant_member(tenant_id: str):
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "MEMBER").strip().upper()
    if role not in TENANT_ROLES:
        return corsify(jsonify({"ok": False, "error": "invalid_role"}), origin), 400

    with_db()
    with pool.connection() as con:
        tenant = fetch_tenant(con, tenant_id)
        if not tenant:
            return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404
        try:
            user = ensure_user_basic(con, email)
        except ValueError:
            return corsify(jsonify({"ok": False, "error": "invalid_email"}), origin), 400
        with con.cursor() as cur:
            cur.execute(
                """INSERT INTO tenant_users (user_id, tenant_id, role)
                       VALUES (%s,%s,%s)
                       ON CONFLICT (user_id, tenant_id) DO UPDATE SET role=EXCLUDED.role""",
                (user["id"], tenant_id, role),
            )
        tenant = fetch_tenant(con, tenant_id)

    audit("tenant_member_upserted", tenant=tenant_id, user=email, role=role, admin=str(admin["id"]))
    return corsify(jsonify({"ok": True, "tenant": tenant}), origin)

@app.delete("/admin/tenants/<tenant_id>/members")
def admin_remove_tenant_member(tenant_id: str):
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return corsify(jsonify({"ok": False, "error": "email_required"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user:
            return corsify(jsonify({"ok": False, "error": "user_not_found"}), origin), 404
        cur.execute("DELETE FROM tenant_users WHERE user_id=%s AND tenant_id=%s", (user["id"], tenant_id))
        tenant = fetch_tenant(con, tenant_id)

    audit("tenant_member_removed", tenant=tenant_id, user=email, admin=str(admin["id"]))
    return corsify(jsonify({"ok": True, "tenant": tenant}), origin)

@app.get("/admin/settings")
def admin_list_settings():
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT key, value, updated_at FROM global_settings ORDER BY key ASC")
        items = [
            {"key": row["key"], "value": row["value"], "updatedAt": row["updated_at"].isoformat()}
            for row in cur.fetchall()
        ]

    return corsify(jsonify({"ok": True, "settings": items}), origin)

@app.put("/admin/settings/<key>")
def admin_upsert_setting(key: str):
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True)
    if data is None or "value" not in data:
        return corsify(jsonify({"ok": False, "error": "value_required"}), origin), 400

    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute(
            """INSERT INTO global_settings (key, value)
                   VALUES (%s, %s::jsonb)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()""",
            (key, json.dumps(data["value"])),
        )

    audit("setting_upsert", key=key, admin=str(admin["id"]))
    return corsify(jsonify({"ok": True, "key": key, "value": data["value"]}), origin)

@app.delete("/admin/settings/<key>")
def admin_delete_setting(key: str):
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    with_db()
    with pool.connection() as con, con.cursor() as cur:
        cur.execute("DELETE FROM global_settings WHERE key=%s", (key,))

    audit("setting_deleted", key=key, admin=str(admin["id"]))
    return corsify(jsonify({"ok": True}), origin)

# ---------------- Health ----------------
@app.get("/")
def root():
    origin = request.headers.get("Origin")
    return corsify(jsonify({
        "message": "Kinjar API Server",
        "version": "1.0.0",
        "status": "running",
        "health_endpoint": "/health"
    }), origin)

@app.get("/health")
def health():
    # Fast health check - don't try to connect to external services
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.get("/debug")
def debug():
    # Debug endpoint to see request headers
    return jsonify({
        "status": "ok",
        "headers": dict(request.headers),
        "method": request.method,
        "url": request.url,
        "remote_addr": request.remote_addr,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.get("/status")
def detailed_status():
    # Detailed status with more information - not used for health checks
    origin = request.headers.get("Origin")
    try:
        db_connect_once()
    except Exception as e:
        log.warning(f"DB connection failed in status check: {e}")
    
    return corsify(jsonify({
        "status": "ok",
        "bucket": S3_BUCKET if S3_BUCKET != "kinjar-dev-bucket" else "not-configured",
        "public_media_base": PUBLIC_MEDIA_BASE or None,
        "allowed_origins": list(ALLOWED_ORIGINS) or ["* (not restricted)"],
        "root_domain": ROOT_DOMAIN,
        "db_ready": DB_READY,
        "db_error": DB_ERR,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }), origin)

# ---------------- R2 / Media Routes (unchanged behavior) ----------------
@app.post("/presign")
def presign():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

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

    mid = str(uuid4())
    key = f"t/{tenant}/posts/{mid}/{filename}"

    try:
        s3 = s3_client()
        put_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET, "Key": key},
            ExpiresIn=300,
            HttpMethod="PUT",
        )
    except Exception:
        log.exception("presign failed while signing")
        return corsify(jsonify({"ok": False, "error": "presign_failed"}), origin), 500

    try:
        db_insert_presign(mid, tenant, key, filename, ctype)
    except Exception:
        log.exception("DB insert failed during presign; continuing without DB")

    resp = {
        "ok": True,
        "id": mid,
        "key": key,
        "maxMB": 50,
        "put": {"url": put_url, "headers": {"Content-Type": ctype}},
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
            "ok": True, "key": key, "size": size, "type": ctype, "etag": h.get("ETag"),
        }), origin)
    except ClientError as e:
        audit("head", key=key, status="miss", err=str(e))
        return corsify(jsonify({"ok": False, "error": "not_found"}), origin), 404

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

@app.delete("/media/delete")
def delete_media():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing_key"}), origin), 400

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

@app.post("/upload")
def direct_upload():
    """Direct file upload endpoint for family media"""
    origin = request.headers.get("Origin")
    # TODO: Add proper authentication later - allowing for development
    # if not is_authorized(request):
    #     return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    # Check if file was uploaded
    if 'file' not in request.files:
        return corsify(jsonify({"ok": False, "error": "no_file"}), origin), 400
    
    file = request.files['file']
    if file.filename == '':
        return corsify(jsonify({"ok": False, "error": "no_filename"}), origin), 400
    
    # Get form data
    family_slug = request.form.get('family_slug', '')
    upload_type = request.form.get('type', 'photo')  # photo or video
    
    if not family_slug:
        return corsify(jsonify({"ok": False, "error": "missing_family_slug"}), origin), 400
    
    tenant = sanitize_tenant(family_slug)
    if not tenant:
        return corsify(jsonify({"ok": False, "error": "invalid_tenant"}), origin), 400
    
    # Validate file type
    allowed_extensions = {
        'photo': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        'video': ['mp4', 'mov', 'avi', 'webm', 'mkv']
    }
    
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if file_ext not in allowed_extensions.get(upload_type, []):
        return corsify(jsonify({"ok": False, "error": "invalid_file_type"}), origin), 400
    
    # Generate unique ID and key
    mid = str(uuid4())
    safe_filename = sanitize_filename(file.filename)
    key = f"t/{tenant}/posts/{mid}/{safe_filename}"
    
    try:
        # Upload to R2
        s3 = s3_client()
        s3.upload_fileobj(
            file,
            S3_BUCKET,
            key,
            ExtraArgs={
                'ContentType': file.content_type or f'image/{file_ext}' if upload_type == 'photo' else f'video/{file_ext}'
            }
        )
        
        # Save to database
        file.seek(0, 2)  # Seek to end to get size
        file_size = file.tell()
        
        db_insert_presign(mid, tenant, key, safe_filename, file.content_type)
        db_mark_uploaded(key, file_size, file.content_type)
        
        # Create content post entry
        with_db()
        with pool.connection() as con:
            # Get tenant ID
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant,))
                tenant_row = cur.fetchone()
                if not tenant_row:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404
                
                tenant_id = tenant_row['id']
                
                # For now, use system user as author (can be enhanced later)
                author_id = "system"
                title = f"{upload_type.title()} upload - {safe_filename}"
                
                create_content_post(
                    con, 
                    tenant_id=tenant_id,
                    author_id=author_id,
                    title=title,
                    content=f"Uploaded {upload_type}",
                    media_id=mid,
                    content_type=upload_type,
                    is_public=True
                )
        
        audit("upload", tenant=tenant, id=mid, key=key, type=upload_type, size=file_size)
        
        resp = {
            "ok": True,
            "id": mid,
            "key": key,
            "type": upload_type,
            "filename": safe_filename,
            "size": file_size
        }
        
        if PUBLIC_MEDIA_BASE:
            resp["publicUrl"] = f"{PUBLIC_MEDIA_BASE.rstrip('/')}/{key}"
        
        return corsify(jsonify(resp), origin)
        
    except Exception as e:
        log.exception("Upload failed")
        return corsify(jsonify({"ok": False, "error": f"upload_failed: {str(e)}"}), origin), 500

# ---------------- Video Blog API Routes ----------------

# Helper functions for video blog features
def create_content_post(con, tenant_id: str, author_id: str, title: str, content: str = "", 
                       media_id: str = None, content_type: str = "video_blog", is_public: bool = True) -> Dict[str, Any]:
    """Create a new content post (video blog entry)"""
    post_id = str(uuid4())
    published_at = datetime.datetime.now(datetime.timezone.utc)
    
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            INSERT INTO content_posts (id, tenant_id, author_id, media_id, title, content, 
                                     content_type, is_public, published_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (post_id, tenant_id, author_id, media_id, title, content, content_type, is_public, published_at))
        post = cur.fetchone()
        
        # Add to activity feed
        cur.execute("""
            INSERT INTO activity_feed (id, tenant_id, user_id, action_type, entity_type, entity_id, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (str(uuid4()), tenant_id, author_id, "post_created", "content_post", post_id, 
              json.dumps({"title": title, "content_type": content_type})))
        
    return post

def get_tenant_posts(con, tenant_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Get published posts for a tenant with author and media info"""
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT 
                p.*,
                u.email as author_email,
                up.display_name as author_name,
                up.avatar_url as author_avatar,
                m.filename as media_filename,
                m.content_type as media_content_type,
                m.r2_key as media_r2_key,
                m.thumbnail_url as media_thumbnail,
                m.duration_seconds as media_duration
            FROM content_posts p
            JOIN users u ON p.author_id = u.id
            LEFT JOIN user_profiles up ON u.id = up.user_id
            LEFT JOIN media_objects m ON p.media_id = m.id
            WHERE p.tenant_id = %s AND p.status = 'published'
            ORDER BY p.published_at DESC
            LIMIT %s OFFSET %s
        """, (tenant_id, limit, offset))
        return cur.fetchall()

def get_post_comments(con, post_id: str) -> List[Dict[str, Any]]:
    """Get comments for a post with author info"""
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT 
                c.*,
                u.email as author_email,
                up.display_name as author_name,
                up.avatar_url as author_avatar
            FROM content_comments c
            JOIN users u ON c.author_id = u.id
            LEFT JOIN user_profiles up ON u.id = up.user_id
            WHERE c.post_id = %s AND c.status = 'published'
            ORDER BY c.created_at ASC
        """, (post_id,))
        return cur.fetchall()

def add_comment(con, post_id: str, author_id: str, content: str, parent_id: str = None) -> Dict[str, Any]:
    """Add a comment to a post"""
    comment_id = str(uuid4())
    
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            INSERT INTO content_comments (id, post_id, author_id, parent_id, content)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING *
        """, (comment_id, post_id, author_id, parent_id, content))
        comment = cur.fetchone()
        
        # Get tenant_id for activity feed
        cur.execute("SELECT tenant_id FROM content_posts WHERE id = %s", (post_id,))
        tenant_row = cur.fetchone()
        if tenant_row:
            cur.execute("""
                INSERT INTO activity_feed (id, tenant_id, user_id, action_type, entity_type, entity_id, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid4()), tenant_row['tenant_id'], author_id, "comment_added", "comment", comment_id,
                  json.dumps({"post_id": post_id, "content_preview": content[:100]})))
        
    return comment

# API Routes
@app.post("/api/posts")
def create_post():
    """Create a new video blog post"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "")
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "missing_tenant"}), origin), 400

    body = request.get_json(silent=True) or {}
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    media_id = body.get("media_id")
    content_type = body.get("content_type", "video_blog")
    is_public = body.get("is_public", True)

    if not title:
        return corsify(jsonify({"ok": False, "error": "title_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            # Get tenant by slug
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                # Check user is member of tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], tenant["id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "not_tenant_member"}), origin), 403

            post = create_content_post(con, tenant["id"], user["id"], title, content, 
                                     media_id, content_type, is_public)
            
            audit("post_created", tenant=tenant_slug, post_id=post["id"], title=title)
            return corsify(jsonify({"ok": True, "post": post}), origin)

    except Exception as e:
        log.exception("Failed to create post")
        return corsify(jsonify({"ok": False, "error": "create_failed"}), origin), 500

@app.get("/api/posts")
def list_posts():
    """List posts for a tenant"""
    origin = request.headers.get("Origin")
    
    tenant_slug = request.args.get("tenant", "")
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "missing_tenant"}), origin), 400

    limit = min(max(int(request.args.get("limit", "20")), 1), 100)
    offset = max(int(request.args.get("offset", "0")), 0)

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

            posts = get_tenant_posts(con, tenant["id"], limit, offset)
            
            # Add signed URLs for media
            for post in posts:
                if post.get("media_r2_key"):
                    try:
                        signed_url = s3_client().generate_presigned_url(
                            ClientMethod="get_object",
                            Params={"Bucket": S3_BUCKET, "Key": post["media_r2_key"]},
                            ExpiresIn=3600,
                        )
                        post["media_url"] = signed_url
                    except Exception:
                        log.exception(f"Failed to generate signed URL for {post['media_r2_key']}")

            return corsify(jsonify({"ok": True, "posts": posts}), origin)

    except Exception as e:
        log.exception("Failed to list posts")
        return corsify(jsonify({"ok": False, "error": "list_failed"}), origin), 500

@app.get("/api/posts/<post_id>")
def get_post(post_id: str):
    """Get a specific post with comments"""
    origin = request.headers.get("Origin")
    
    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get post with author and media info
                cur.execute("""
                    SELECT 
                        p.*,
                        u.email as author_email,
                        up.display_name as author_name,
                        up.avatar_url as author_avatar,
                        m.filename as media_filename,
                        m.content_type as media_content_type,
                        m.r2_key as media_r2_key,
                        m.thumbnail_url as media_thumbnail,
                        m.duration_seconds as media_duration,
                        t.slug as tenant_slug
                    FROM content_posts p
                    JOIN users u ON p.author_id = u.id
                    JOIN tenants t ON p.tenant_id = t.id
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    LEFT JOIN media_objects m ON p.media_id = m.id
                    WHERE p.id = %s AND p.status = 'published'
                """, (post_id,))
                post = cur.fetchone()
                
                if not post:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                # Increment view count
                cur.execute("UPDATE content_posts SET view_count = view_count + 1 WHERE id = %s", (post_id,))

            # Get comments
            comments = get_post_comments(con, post_id)
            
            # Add signed URL for media
            if post.get("media_r2_key"):
                try:
                    signed_url = s3_client().generate_presigned_url(
                        ClientMethod="get_object",
                        Params={"Bucket": S3_BUCKET, "Key": post["media_r2_key"]},
                        ExpiresIn=3600,
                    )
                    post["media_url"] = signed_url
                except Exception:
                    log.exception(f"Failed to generate signed URL for {post['media_r2_key']}")

            return corsify(jsonify({"ok": True, "post": dict(post), "comments": comments}), origin)

    except Exception as e:
        log.exception("Failed to get post")
        return corsify(jsonify({"ok": False, "error": "get_failed"}), origin), 500

@app.post("/api/posts/<post_id>/comments")
def add_post_comment(post_id: str):
    """Add a comment to a post"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    content = body.get("content", "").strip()
    parent_id = body.get("parent_id")

    if not content:
        return corsify(jsonify({"ok": False, "error": "content_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            # Verify post exists and user can comment
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT p.*, t.slug as tenant_slug FROM content_posts p
                    JOIN tenants t ON p.tenant_id = t.id
                    WHERE p.id = %s AND p.status = 'published'
                """, (post_id,))
                post = cur.fetchone()
                if not post:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                # Check user is member of tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], post["tenant_id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "not_tenant_member"}), origin), 403

            comment = add_comment(con, post_id, user["id"], content, parent_id)
            
            audit("comment_added", post_id=post_id, comment_id=comment["id"], tenant=post["tenant_slug"])
            return corsify(jsonify({"ok": True, "comment": comment}), origin)

    except Exception as e:
        log.exception("Failed to add comment")
        return corsify(jsonify({"ok": False, "error": "comment_failed"}), origin), 500

@app.post("/api/tenants/<tenant_id>/invite")
def invite_user(tenant_id: str):
    """Invite a user to join a tenant"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    email = body.get("email", "").strip().lower()
    role = body.get("role", "MEMBER")

    if not email or role not in TENANT_ROLES:
        return corsify(jsonify({"ok": False, "error": "invalid_input"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Check user can invite (is admin/owner of tenant)
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER')
                """, (user["id"], tenant_id))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Create invitation
                invite_id = str(uuid4())
                invite_token = str(uuid4())
                expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
                
                cur.execute("""
                    INSERT INTO tenant_invitations (id, tenant_id, invited_by, email, role, invite_token, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (invite_id, tenant_id, user["id"], email, role, invite_token, expires_at))
                invitation = cur.fetchone()

            audit("user_invited", tenant_id=tenant_id, email=email, role=role, invited_by=user["email"])
            return corsify(jsonify({"ok": True, "invitation": dict(invitation)}), origin)

    except Exception as e:
        log.exception("Failed to invite user")
        return corsify(jsonify({"ok": False, "error": "invite_failed"}), origin), 500

@app.post("/families/<family_slug>/invite")
def invite_family_member(family_slug: str):
    """Invite a user to join a family (by slug)"""
    origin = request.headers.get("Origin")
    # TODO: Add proper authentication later - allowing for development
    # user = current_user_row()
    # if not user:
    #     return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    email = body.get("email", "").strip().lower()

    if not email:
        return corsify(jsonify({"ok": False, "error": "email_required"}), origin), 400

    tenant = sanitize_tenant(family_slug)
    if not tenant:
        return corsify(jsonify({"ok": False, "error": "invalid_family"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID from slug
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant,))
                tenant_row = cur.fetchone()
                if not tenant_row:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                tenant_id = tenant_row['id']

                # For development, skip permission check
                # TODO: Add proper permission checking later

                # Create invitation
                invite_id = str(uuid4())
                invite_token = str(uuid4())
                expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
                
                cur.execute("""
                    INSERT INTO tenant_invitations (id, tenant_id, invited_by, email, role, invite_token, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (invite_id, tenant_id, "system", email, "MEMBER", invite_token, expires_at))
                invitation = cur.fetchone()

            audit("family_invited", tenant_id=tenant_id, family_slug=family_slug, email=email)
            return corsify(jsonify({"ok": True, "invitation": dict(invitation), "message": f"Invitation sent to {email}"}), origin)

    except Exception as e:
        log.exception("Failed to invite family member")
        return corsify(jsonify({"ok": False, "error": f"invite_failed: {str(e)}"}), origin), 500

# CORS preflight
@app.route("/", methods=["OPTIONS"])
@app.route("/health", methods=["OPTIONS"])
@app.route("/status", methods=["OPTIONS"])
@app.route("/presign", methods=["OPTIONS"])
@app.route("/r2/head", methods=["OPTIONS"])
@app.route("/media/signed-get", methods=["OPTIONS"])
@app.route("/media/list", methods=["OPTIONS"])
@app.route("/media/delete", methods=["OPTIONS"])
@app.route("/upload", methods=["OPTIONS"])
@app.route("/auth/login", methods=["OPTIONS"])
@app.route("/auth/register", methods=["OPTIONS"])
@app.route("/auth/me", methods=["OPTIONS"])
@app.route("/auth/logout", methods=["OPTIONS"])
@app.route("/signup/request", methods=["OPTIONS"])
@app.route("/admin/signup/requests", methods=["OPTIONS"])
@app.route("/admin/signup/approve", methods=["OPTIONS"])
@app.route("/admin/signup/deny", methods=["OPTIONS"])
@app.route("/admin/tenants", methods=["OPTIONS"])
@app.route("/admin/tenants/<tenant_id>", methods=["OPTIONS"])
@app.route("/admin/tenants/<tenant_id>/members", methods=["OPTIONS"])
@app.route("/admin/settings", methods=["OPTIONS"])
@app.route("/admin/settings/<key>", methods=["OPTIONS"])
@app.route("/api/posts", methods=["OPTIONS"])
@app.route("/api/posts/<post_id>", methods=["OPTIONS"])
@app.route("/api/posts/<post_id>/comments", methods=["OPTIONS"])
@app.route("/api/tenants/<tenant_id>/invite", methods=["OPTIONS"])
@app.route("/families/<family_slug>/invite", methods=["OPTIONS"])
def options():
    origin = request.headers.get("Origin")
    response = make_response(("", 204))
    return corsify(response, origin)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
