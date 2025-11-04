import os
import re
import time
import json
import logging
import datetime
from uuid import uuid4
from typing import Optional, List, Dict, Any
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, jsonify, make_response, redirect
from flask_cors import CORS

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from argon2 import PasswordHasher
import jwt
import requests
import mimetypes

# ---------------- Setup ----------------
app = Flask(__name__)

# Configure CORS to allow requests from Kinjar subdomains
CORS(app, 
     origins=[
         'https://slaughterbeck.kinjar.com',  # Specific subdomain
         'https://kinjar.com',               # Main domain
         'https://www.kinjar.com',           # WWW subdomain
         'http://localhost:3000',            # Local development
         'https://kinjar.vercel.app',        # Vercel deployments
     ],
     allow_headers=['Content-Type', 'Authorization', 'x-tenant-slug'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
     supports_credentials=True
)

# Additional CORS handling for complex cases
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        # Allow specific Kinjar domains
        allowed_origins = [
            'https://slaughterbeck.kinjar.com',
            'https://kinjar.com',
            'https://www.kinjar.com',
            'http://localhost:3000',
            'https://kinjar.vercel.app'
        ]
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-tenant-slug'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        origin = request.headers.get('Origin')
        if origin:
            allowed_origins = [
                'https://slaughterbeck.kinjar.com',
                'https://kinjar.com', 
                'https://www.kinjar.com',
                'http://localhost:3000',
                'https://kinjar.vercel.app'
            ]
            if origin in allowed_origins:
                response = make_response()
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-tenant-slug'
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response

# Configure Flask for larger file uploads. Some iOS Live Photos and newer
# devices can easily exceed 50MB even when they appear "small" in the photo
# picker, so allow up to 150MB to avoid spurious 413 errors while still
# preventing runaway uploads.
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024  # 150MB limit
app.config['UPLOAD_TIMEOUT'] = 300  # 5 minutes

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kinjar-api")


class StorageNotConfigured(RuntimeError):
    """Raised when required storage configuration is missing."""

    pass

def env_str(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing env var: {name}")
    return val

def env_list(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]

# Required (Vercel Blob) - make optional for development
VERCEL_BLOB_TOKEN = os.getenv("BLOB_READ_WRITE_TOKEN", "")

# Required (Neon) - make optional for development
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/kinjar_dev")

# R2 Configuration - for media storage
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
S3_BUCKET = os.getenv("R2_BUCKET", "kinjar-media")

# Optional
PUBLIC_MEDIA_BASE = os.getenv("PUBLIC_MEDIA_BASE", "")
API_KEYS = set(env_list("API_KEYS"))                      # comma-separated supported
ALLOWED_ORIGINS = set(env_list("ALLOWED_ORIGINS"))        # for API CORS
PORT = int(os.getenv("PORT", "8080"))
DATA_DIR = os.getenv("DATA_DIR", "/data")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")
ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "kinjar.com")

# Email Configuration for invitations
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@kinjar.com")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Kinjar Family Platform")

# Auth / Session
JWT_SECRET = os.getenv("JWT_SECRET", "temp-dev-secret-change-in-production")  # Temporary default for development
JWT_ALG = "HS256"
JWT_TTL_MIN = 60 * 24 * 14  # 14 days
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", None)
_cookie_secure_env = os.getenv("COOKIE_SECURE")
if _cookie_secure_env is None:
    COOKIE_SECURE = None  # auto-detect based on request context
else:
    COOKIE_SECURE = _cookie_secure_env.strip().lower() not in {"false", "0", "no"}
ROOT_EMAILS = set(env_list("ROOT_EMAILS"))

ph = PasswordHasher()

# Security/validation knobs
ALLOWED_CONTENT_TYPES = set((
    "image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif", "image/heic", "image/heif",
    "video/mp4", "video/quicktime", "video/mov", "video/avi", "video/webm", "video/m4v", "video/3gp", "video/3gpp",
    "text/plain", "application/pdf"
))
TENANT_RE = re.compile(r"^[a-z0-9-]{1,63}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
TENANT_ROLES = {"OWNER", "ADMIN", "ADULT", "CHILD_0_5", "CHILD_5_10", "CHILD_10_14", "CHILD_14_16", "CHILD_16_ADULT", "MEMBER"}

# ---------------- Vercel Blob Upload ----------------
def upload_to_vercel_blob(file_data, filename, content_type):
    """Upload file to Vercel Blob storage and return the public URL"""
    if not VERCEL_BLOB_TOKEN:
        raise StorageNotConfigured("BLOB_READ_WRITE_TOKEN not configured")
    
    # Generate a unique filename to avoid conflicts
    file_extension = filename.split('.')[-1] if '.' in filename else 'bin'
    unique_filename = f"{uuid4()}.{file_extension}"
    
    # Correct Vercel Blob upload endpoint - PUT to specific filename
    upload_url = f"https://blob.vercel-storage.com/{unique_filename}"
    
    headers = {
        'Authorization': f'Bearer {VERCEL_BLOB_TOKEN}',
        'X-Content-Type': content_type,
    }
    
    try:
        # Upload the file using PUT request
        response = requests.put(upload_url, data=file_data, headers=headers)
        response.raise_for_status()
        
        # Parse the response to get the actual public URL
        result = response.json()
        public_url = result.get('url', upload_url)
        
        log.info(f"Successfully uploaded to Vercel Blob: {public_url}")
        
        # Return the public URL from Vercel Blob response
        return {
            'url': public_url,
            'filename': unique_filename,
            'size': len(file_data),
            'content_type': content_type
        }
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to upload to Vercel Blob: {e}")
        # Log response details for debugging
        if hasattr(e, 'response') and e.response is not None:
            log.error(f"Response status: {e.response.status_code}")
            log.error(f"Response text: {e.response.text}")
        raise Exception(f"Upload failed: {str(e)}")

# ---------------- R2 client ----------------
def s3_client():
    missing = []
    if not R2_ACCOUNT_ID:
        missing.append("R2_ACCOUNT_ID")
    if not R2_ACCESS_KEY_ID:
        missing.append("R2_ACCESS_KEY_ID")
    if not R2_SECRET_ACCESS_KEY:
        missing.append("R2_SECRET_ACCESS_KEY")
    if missing:
        raise StorageNotConfigured(
            "Missing R2 configuration: " + ", ".join(sorted(missing))
        )

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
                  r2_key        text UNIQUE,
                  filename      text NOT NULL,
                  content_type  text NOT NULL,
                  size_bytes    bigint,
                  status        text NOT NULL,           -- presigned | uploaded | deleted
                  external_url  text,                    -- for externally hosted media (e.g., Vercel Blob)
                  created_at    timestamptz NOT NULL DEFAULT now(),
                  updated_at    timestamptz NOT NULL DEFAULT now(),
                  deleted_at    timestamptz
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_media_objects_tenant_created
                  ON media_objects (tenant, created_at DESC);
            """)

            # Add external_url column if it doesn't exist (for backward compatibility)
            try:
                cur.execute("""
                    ALTER TABLE media_objects 
                    ADD COLUMN IF NOT EXISTS external_url text;
                """)
                cur.execute("""
                    ALTER TABLE media_objects 
                    ALTER COLUMN r2_key DROP NOT NULL;
                """)
            except Exception as e:
                # Column might already exist or constraint might not exist
                log.warning(f"Schema migration warning (can be ignored): {e}")
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
                  visibility    text DEFAULT 'family', -- 'family', 'connections', 'public'
                  view_count    integer DEFAULT 0,
                  created_at    timestamptz NOT NULL DEFAULT now(),
                  updated_at    timestamptz NOT NULL DEFAULT now(),
                  published_at  timestamptz
                );
            """)
            
            # Add visibility column if it doesn't exist (migration)
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE content_posts ADD COLUMN visibility text DEFAULT 'family';
                EXCEPTION
                    WHEN duplicate_column THEN NULL;
                END $$;
            """)
            # Update existing rows to have proper visibility based on is_public
            cur.execute("""
                UPDATE content_posts 
                SET visibility = CASE 
                    WHEN is_public = true THEN 'public' 
                    ELSE 'family' 
                END 
                WHERE visibility IS NULL;
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
                  invited_name text,
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
            
            # Migration: Add invited_name column if it doesn't exist
            cur.execute("""
                ALTER TABLE tenant_invitations 
                ADD COLUMN IF NOT EXISTS invited_name text;
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

            # Add new columns for enhanced user profiles
            try:
                cur.execute("""
                    ALTER TABLE user_profiles 
                    ADD COLUMN IF NOT EXISTS birthdate DATE;
                """)
                cur.execute("""
                    ALTER TABLE user_profiles 
                    ADD COLUMN IF NOT EXISTS avatar_color text DEFAULT '#3B82F6';
                """)
                cur.execute("""
                    ALTER TABLE user_profiles 
                    ADD COLUMN IF NOT EXISTS role_override text;
                """)
                cur.execute("""
                    ALTER TABLE user_profiles 
                    ADD COLUMN IF NOT EXISTS permissions_manual boolean DEFAULT false;
                """)
            except Exception as e:
                # Columns might already exist
                log.warning(f"User profile schema migration warning (can be ignored): {e}")

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

            # Family connections - allows families to connect and share content
            cur.execute("""
                CREATE TABLE IF NOT EXISTS family_connections (
                  id             uuid PRIMARY KEY,
                  requesting_tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  target_tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  status         text NOT NULL DEFAULT 'pending', -- pending, accepted, declined, blocked
                  requested_by   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  responded_by   uuid REFERENCES users(id) ON DELETE SET NULL,
                  request_message text,
                  response_message text,
                  created_at     timestamptz NOT NULL DEFAULT now(),
                  responded_at   timestamptz,
                  UNIQUE(requesting_tenant_id, target_tenant_id)
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_family_connections_target_status
                  ON family_connections (target_tenant_id, status);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_family_connections_requesting_status
                  ON family_connections (requesting_tenant_id, status);
            """)

            # Family settings for customization
            cur.execute("""
                CREATE TABLE IF NOT EXISTS family_settings (
                  tenant_id       uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                  family_photo    text,                    -- URL to family photo
                  theme_color     text DEFAULT '#2563eb',  -- Primary color
                  banner_image    text,                    -- Banner/header image
                  description     text,                    -- Family description
                  is_public       boolean DEFAULT false,   -- Whether family can be discovered
                  allow_connections boolean DEFAULT true,  -- Whether other families can request connections
                  updated_at      timestamptz NOT NULL DEFAULT now(),
                  updated_by      uuid REFERENCES users(id)
                );
            """)

            # Content visibility - tracks which families can see which posts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS content_visibility (
                  post_id      uuid NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
                  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                  granted_by   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  granted_at   timestamptz NOT NULL DEFAULT now(),
                  PRIMARY KEY (post_id, tenant_id)
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_visibility_tenant_granted
                  ON content_visibility (tenant_id, granted_at DESC);
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
        # Allow specific origins from ALLOWED_ORIGINS OR any kinjar.com subdomain OR Vercel deployments
        if (ALLOWED_ORIGINS and origin in ALLOWED_ORIGINS) or \
           origin.endswith('.kinjar.com') or origin == 'https://kinjar.com' or \
           origin.endswith('.vercel.app'):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,x-family-context,Authorization"
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
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,x-family-context,Authorization"
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
        # Allow specific origins from ALLOWED_ORIGINS OR any kinjar.com subdomain OR Vercel deployments
        if (ALLOWED_ORIGINS and origin in ALLOWED_ORIGINS) or \
           origin.endswith('.kinjar.com') or origin == 'https://kinjar.com' or \
           origin.endswith('.vercel.app'):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS,PUT,PATCH"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,x-family-context,Authorization"
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
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,x-family-context,Authorization"
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
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,x-family-context,Authorization"
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

def _should_use_secure_cookies() -> bool:
    """Determine whether the session cookie must be marked secure."""
    if COOKIE_SECURE is not None:
        return COOKIE_SECURE

    # Honor proxy headers commonly set by Fly.io / other proxies.
    proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    if proto:
        return proto == "https"

    if request.is_secure:
        return True

    host = (request.host or "").split(":")[0]
    return host not in {"localhost", "127.0.0.1"}

def _session_cookie_kwargs() -> Dict[str, Any]:
    secure = _should_use_secure_cookies()
    # Browsers require SameSite=None cookies to also be Secure. When falling
    # back to non-secure cookies (e.g. local development over http), use Lax
    # so the cookie is accepted and still sent on top-level navigations.
    samesite = "None" if secure else "Lax"
    return {
        "httponly": True,
        "secure": secure,
        "samesite": samesite,
        "domain": COOKIE_DOMAIN if COOKIE_DOMAIN else None,
        "path": "/",
    }

def set_session_cookie(resp, token: str):
    kwargs = _session_cookie_kwargs()
    resp.set_cookie(
        "kinjar_session",
        token,
        max_age=JWT_TTL_MIN * 60,
        **kwargs,
    )

def clear_session_cookie(resp):
    kwargs = _session_cookie_kwargs()
    resp.set_cookie(
        "kinjar_session",
        "",
        expires=0,
        **kwargs,
    )

def current_user_row() -> Optional[Dict[str, Any]]:
    # Try cookie-based auth first
    token = request.cookies.get("kinjar_session")
    
    # If no cookie, try Authorization header
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
    
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

def send_invitation_email(email: str, name: str, family_name: str, invitation_token: str, family_slug: str):
    """Send an invitation email to a new family member"""
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        log.warning(f"SMTP not configured, skipping email to {email}")
        return False
    
    try:
        # Create the invitation URL
        base_url = f"https://{ROOT_DOMAIN}"
        invitation_url = f"{base_url}/auth/register?token={invitation_token}&family={family_slug}"
        
        # Create email content
        subject = f"You're invited to join {family_name} on Kinjar!"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #3B82F6;">Welcome to Kinjar!</h1>
            </div>
            
            <div style="background: #F8FAFC; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h2 style="color: #1F2937; margin-top: 0;">Hi {name}!</h2>
                <p style="color: #4B5563; font-size: 16px; line-height: 1.5;">
                    You've been invited to join <strong>{family_name}</strong> on Kinjar, 
                    a private family social platform where you can share photos, videos, 
                    and memories with your loved ones.
                </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{invitation_url}" 
                   style="background: #3B82F6; color: white; padding: 14px 28px; 
                          text-decoration: none; border-radius: 6px; font-weight: bold; 
                          font-size: 16px; display: inline-block;">
                    Join {family_name}
                </a>
            </div>
            
            <div style="border-top: 1px solid #E5E7EB; padding-top: 20px; margin-top: 30px;">
                <p style="color: #6B7280; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:
                </p>
                <p style="color: #3B82F6; font-size: 14px; word-break: break-all;">
                    {invitation_url}
                </p>
                <p style="color: #6B7280; font-size: 12px; margin-top: 20px;">
                    This invitation will expire in 7 days. If you have any questions, 
                    please contact the family member who invited you.
                </p>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
Hi {name}!

You've been invited to join {family_name} on Kinjar, a private family social platform 
where you can share photos, videos, and memories with your loved ones.

To accept this invitation and create your account, please visit:
{invitation_url}

This invitation will expire in 7 days. If you have any questions, 
please contact the family member who invited you.

Welcome to the family!
The Kinjar Team
        """
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg['To'] = email
        
        # Attach text and HTML versions
        text_part = MIMEText(text_body, 'plain')
        html_part = MIMEText(html_body, 'html')
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            
        log.info(f"Invitation email sent successfully to {email}")
        return True
        
    except Exception as e:
        log.error(f"Failed to send invitation email to {email}: {str(e)}")
        return False

def ensure_user_basic(con, email: str) -> Dict[str, Any]:
    email = email.strip().lower()
    if not email:
        raise ValueError("email_required")

def calculate_age(birthdate) -> int:
    """Calculate age from birthdate"""
    if not birthdate:
        return None
    from datetime import date
    today = date.today()
    return today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))

def determine_role_from_age(age: int, is_admin: bool = False) -> str:
    """Determine appropriate role based on age"""
    if is_admin:
        return "ADMIN"
    if age is None:
        return "ADULT"  # Default for unknown age
    if age < 5:
        return "CHILD_0_5"
    elif age < 10:
        return "CHILD_5_10"
    elif age < 14:
        return "CHILD_10_14"
    elif age < 16:
        return "CHILD_14_16"
    elif age < 18:
        return "CHILD_16_ADULT"
    else:
        return "ADULT"

def get_role_permissions(role: str) -> Dict[str, bool]:
    """Get permissions for a given role"""
    permissions = {
        "can_post": True,
        "can_post_public": True,
        "can_comment": True,
        "can_react": True,
        "can_invite_members": False,
        "can_manage_family": False,
        "requires_approval": False,
        "can_moderate": False
    }
    
    if role in ["OWNER", "ADMIN"]:
        permissions.update({
            "can_invite_members": True,
            "can_manage_family": True,
            "can_moderate": True
        })
    elif role == "ADULT":
        permissions.update({
            "can_invite_members": False,
            "can_manage_family": False
        })
    elif role.startswith("CHILD_"):
        if role in ["CHILD_0_5", "CHILD_5_10"]:
            permissions.update({
                "can_post_public": False,
                "requires_approval": True
            })
        elif role in ["CHILD_10_14"]:
            permissions.update({
                "can_post_public": False,
                "requires_approval": True
            })
        elif role in ["CHILD_14_16", "CHILD_16_ADULT"]:
            permissions.update({
                "requires_approval": True
            })
    elif role == "MEMBER":
        # Legacy role - treat as adult
        pass
    
    return permissions
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

    # Get user profile and memberships
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT display_name, avatar_url, avatar_color, birthdate, bio, phone, 
                   role_override, permissions_manual 
            FROM user_profiles WHERE user_id = %s
        """, (row["id"],))
        profile = cur.fetchone()
        
        cur.execute("""
            SELECT t.id as family_id, t.slug as family_slug, t.name as family_name, 
                   tu.role
            FROM tenant_users tu
            JOIN tenants t ON t.id = tu.tenant_id
            WHERE tu.user_id = %s
            ORDER BY t.name ASC
        """, (row["id"],))
        memberships = list(cur.fetchall())

    now = int(datetime.datetime.utcnow().timestamp())
    token = sign_jwt({"uid": str(row["id"]), "iat": now, "exp": now + JWT_TTL_MIN * 60})
    
    # Calculate age if birthdate is available
    age = None
    if profile and profile.get("birthdate"):
        age = calculate_age(profile["birthdate"])
    
    # Format user data
    user_data = {
        "id": str(row["id"]),
        "name": profile["display_name"] if profile else email.split("@")[0],
        "email": email,
        "avatarColor": profile["avatar_color"] if profile else "#3B82F6",
        "avatarUrl": profile["avatar_url"] if profile else None,
        "birthdate": profile["birthdate"].isoformat() if profile and profile["birthdate"] else None,
        "age": age,
        "bio": profile["bio"] if profile else None,
        "phone": profile["phone"] if profile else None,
        "globalRole": "ROOT_ADMIN" if row["global_role"] == "ROOT" else "FAMILY_ADMIN" if memberships else "MEMBER",
        "memberships": [
            {
                "familyId": m["family_id"],
                "familySlug": m["family_slug"],
                "familyName": m["family_name"],
                "role": m["role"],
                "joinedAt": None,
                "permissions": get_role_permissions(m["role"])
            }
            for m in memberships
        ],
        "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
        "lastLoginAt": datetime.datetime.utcnow().isoformat()
    }
    
    # Return token in both cookie and response body for maximum compatibility
    resp = make_response(jsonify({
        "ok": True, 
        "token": token,
        "user": user_data
    }))
    set_session_cookie(resp, token)
    return corsify(resp, origin)

@app.get("/auth/me")
def auth_me():
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Get user profile
        cur.execute("""
            SELECT display_name, avatar_url, avatar_color, birthdate, bio, phone,
                   role_override, permissions_manual
            FROM user_profiles WHERE user_id = %s
        """, (user["id"],))
        profile = cur.fetchone()
        
        # Get family memberships
        cur.execute("""
            SELECT t.id as family_id, t.slug as family_slug, t.name as family_name, 
                   tu.role
            FROM tenant_users tu
            JOIN tenants t ON t.id = tu.tenant_id
            WHERE tu.user_id = %s
            ORDER BY t.name ASC
        """, (user["id"],))
        memberships = list(cur.fetchall())

    # Calculate age if birthdate is available
    age = None
    if profile and profile.get("birthdate"):
        age = calculate_age(profile["birthdate"])

    # Format user data to match frontend expectations
    user_data = {
        "id": user["id"],
        "name": profile["display_name"] if profile else user["email"].split("@")[0],
        "email": user["email"],
        "avatarColor": profile["avatar_color"] if profile else "#3B82F6",
        "avatarUrl": profile["avatar_url"] if profile else None,
        "birthdate": profile["birthdate"].isoformat() if profile and profile["birthdate"] else None,
        "age": age,
        "bio": profile["bio"] if profile else None,
        "phone": profile["phone"] if profile else None,
        "globalRole": "ROOT_ADMIN" if user["global_role"] == "ROOT" else "FAMILY_ADMIN" if memberships else "MEMBER",
        "memberships": [
            {
                "familyId": m["family_id"],
                "familySlug": m["family_slug"],
                "familyName": m["family_name"],
                "role": m["role"],
                "joinedAt": None,
                "permissions": get_role_permissions(m["role"])
            }
            for m in memberships
        ],
        "createdAt": user["created_at"].isoformat() if user.get("created_at") else None,
        "lastLoginAt": datetime.datetime.utcnow().isoformat()
    }
    
    return corsify(jsonify({"ok": True, "user": user_data}), origin)

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
    invitation_token = data.get("token") or ""  # Invitation token
    
    if not email or not password or len(password) < 8:
        return corsify(jsonify({"ok": False, "error": "Invalid email or password"}), origin), 400
    
    pw_hash = ph.hash(password)

    with_db()
    try:
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check if this is an invitation-based registration
            invitation = None
            if invitation_token:
                cur.execute("""
                    SELECT ti.id, ti.tenant_id, ti.invited_by, ti.email, ti.invited_name, 
                           ti.role, ti.status, ti.invite_token, ti.expires_at, ti.created_at, ti.accepted_at,
                           t.name as family_name, t.slug as family_slug
                    FROM tenant_invitations ti
                    JOIN tenants t ON ti.tenant_id = t.id
                    WHERE ti.invite_token = %s AND ti.status = 'pending'
                      AND ti.expires_at > now()
                """, (invitation_token,))
                invitation = cur.fetchone()
                
                if not invitation:
                    return corsify(jsonify({"ok": False, "error": "Invalid or expired invitation"}), origin), 400
                
                if invitation["email"] != email:
                    return corsify(jsonify({"ok": False, "error": "Email doesn't match invitation"}), origin), 400
            
            # Create user account
            uid = str(uuid4())
            role = "ROOT" if email in ROOT_EMAILS else "USER"
            cur.execute("""INSERT INTO users (id,email,password_hash,global_role)
                           VALUES (%s,%s,%s,%s) RETURNING id,email,global_role,created_at""",
                        (uid, email, pw_hash, role))
            user = cur.fetchone()
            
            # If this is an invitation-based registration, add user to family
            if invitation:
                # Use the invited name from invitation, or fall back to email prefix
                display_name = invitation.get("invited_name") or email.split('@')[0]
                
                # Create user profile with name from invitation
                cur.execute("""
                    INSERT INTO user_profiles (user_id, display_name)
                    VALUES (%s, %s)
                """, (uid, display_name))
                
                # Add user to family with invited role
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, %s)
                """, (uid, invitation["tenant_id"], invitation["role"]))
                
                # Mark invitation as accepted
                cur.execute("""
                    UPDATE tenant_invitations 
                    SET status = 'accepted', accepted_at = now()
                    WHERE id = %s
                """, (invitation["id"],))
                
                log.info(f"User {email} registered and added to family {invitation['family_name']} with role {invitation['role']}")
            
            con.commit()
            
    except psycopg.errors.UniqueViolation:
        return corsify(jsonify({"ok": False, "error": "Email already registered"}), origin), 409

    now = int(datetime.datetime.utcnow().timestamp())
    token = sign_jwt({"uid": str(user["id"]), "iat": now, "exp": now + JWT_TTL_MIN * 60})
    resp_data = {"ok": True, "user": user}
    
    # Include family info if this was an invitation registration
    if invitation:
        resp_data["family"] = {
            "id": invitation["tenant_id"],
            "name": invitation["family_name"],
            "slug": invitation["family_slug"],
            "role": invitation["role"]
        }
    
    resp = make_response(jsonify(resp_data))
    set_session_cookie(resp, token)
    return corsify(resp, origin)

@app.get("/auth/invitation/<token>")
def get_invitation_details(token: str):
    """Get details about an invitation token for the registration form"""
    origin = request.headers.get("Origin")
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT ti.email, ti.role, ti.expires_at, t.name as family_name, t.slug as family_slug
            FROM tenant_invitations ti
            JOIN tenants t ON ti.tenant_id = t.id
            WHERE ti.invite_token = %s AND ti.status = 'pending'
              AND ti.expires_at > now()
        """, (token,))
        invitation = cur.fetchone()
        
        if not invitation:
            return corsify(jsonify({"ok": False, "error": "Invalid or expired invitation"}), origin), 404
        
        return corsify(jsonify({
            "ok": True,
            "invitation": {
                "email": invitation["email"],
                "role": invitation["role"],
                "familyName": invitation["family_name"],
                "familySlug": invitation["family_slug"],
                "expiresAt": invitation["expires_at"].isoformat()
            }
        }), origin)

# ---------------- User Profile Management ----------------
@app.patch("/auth/profile")
def update_profile():
    """Update user profile information"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    data = request.get_json(silent=True) or {}
    
    # Validate fields
    updates = {}
    if "displayName" in data:
        updates["display_name"] = data["displayName"].strip()[:100] if data["displayName"] else None
    if "bio" in data:
        updates["bio"] = data["bio"].strip()[:500] if data["bio"] else None
    if "phone" in data:
        updates["phone"] = data["phone"].strip()[:20] if data["phone"] else None
    if "avatarColor" in data:
        updates["avatar_color"] = data["avatarColor"] if data["avatarColor"] else "#3B82F6"
    if "avatarUrl" in data:
        updates["avatar_url"] = data["avatarUrl"]
    if "birthdate" in data:
        if data["birthdate"]:
            try:
                from datetime import datetime
                birthdate = datetime.fromisoformat(data["birthdate"].replace('Z', '+00:00')).date()
                updates["birthdate"] = birthdate
            except ValueError:
                return corsify(jsonify({"ok": False, "error": "Invalid birthdate format"}), origin), 400
        else:
            updates["birthdate"] = None
    
    if not updates:
        return corsify(jsonify({"ok": False, "error": "No valid fields to update"}), origin), 400
    
    # Update profile
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Create profile if it doesn't exist
        cur.execute("""
            INSERT INTO user_profiles (user_id) 
            VALUES (%s) 
            ON CONFLICT (user_id) DO NOTHING
        """, (user["id"],))
        
        # Build update query dynamically
        set_clauses = [f"{k} = %s" for k in updates.keys()]
        values = list(updates.values()) + [user["id"]]
        
        cur.execute(f"""
            UPDATE user_profiles 
            SET {', '.join(set_clauses)}, updated_at = now()
            WHERE user_id = %s
        """, values)
        
        con.commit()
    
    return corsify(jsonify({"ok": True, "message": "Profile updated successfully"}), origin)

@app.post("/auth/upload-avatar")
def upload_avatar():
    """Upload and set user avatar"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    if 'avatar' not in request.files:
        return corsify(jsonify({"ok": False, "error": "No avatar file provided"}), origin), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return corsify(jsonify({"ok": False, "error": "No file selected"}), origin), 400
    
    # Validate file type
    content_type = file.content_type or mimetypes.guess_type(file.filename)[0] or ""
    if not content_type.startswith('image/'):
        return corsify(jsonify({"ok": False, "error": "File must be an image"}), origin), 400
    
    # Validate file size (max 5MB for avatars)
    file_data = file.read()
    if len(file_data) > 5 * 1024 * 1024:  # 5MB
        return corsify(jsonify({"ok": False, "error": "Avatar file too large (max 5MB)"}), origin), 400
    
    try:
        # Generate filename for avatar
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        avatar_filename = f"avatars/{user['id']}.{file_extension}"
        
        # Upload to Vercel Blob
        avatar_url = upload_to_vercel_blob(file_data, avatar_filename, content_type)
        
        # Update user profile with new avatar URL
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Create profile if it doesn't exist
            cur.execute("""
                INSERT INTO user_profiles (user_id, avatar_url) 
                VALUES (%s, %s) 
                ON CONFLICT (user_id) DO UPDATE SET
                    avatar_url = EXCLUDED.avatar_url,
                    updated_at = now()
            """, (user["id"], avatar_url))
            
            con.commit()
        
        return corsify(jsonify({
            "ok": True, 
            "message": "Avatar uploaded successfully",
            "avatarUrl": avatar_url
        }), origin)
        
    except Exception as e:
        log.error(f"Failed to upload avatar for user {user['id']}: {str(e)}")
        return corsify(jsonify({"ok": False, "error": "Failed to upload avatar"}), origin), 500

@app.post("/api/family/<family_id>/member/<member_id>/avatar")
def upload_member_avatar(family_id: str, member_id: str):
    """Upload avatar for a family member (admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Check if user has admin permissions for this family
        cur.execute("""
            SELECT role FROM tenant_users 
            WHERE user_id = %s AND tenant_id = %s
        """, (user["id"], family_id))
        membership = cur.fetchone()
        
        if not membership or membership["role"] not in ["OWNER", "ADMIN"]:
            return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403
        
        # Verify member exists in family
        cur.execute("""
            SELECT u.id FROM users u
            JOIN tenant_users tu ON u.id = tu.user_id
            WHERE u.id = %s AND tu.tenant_id = %s
        """, (member_id, family_id))
        member = cur.fetchone()
        
        if not member:
            return corsify(jsonify({"ok": False, "error": "Member not found"}), origin), 404
    
    if 'avatar' not in request.files:
        return corsify(jsonify({"ok": False, "error": "No avatar file provided"}), origin), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return corsify(jsonify({"ok": False, "error": "No file selected"}), origin), 400
    
    # Validate file type
    content_type = file.content_type or mimetypes.guess_type(file.filename)[0] or ""
    if not content_type.startswith('image/'):
        return corsify(jsonify({"ok": False, "error": "File must be an image"}), origin), 400
    
    # Validate file size (max 5MB for avatars)
    file_data = file.read()
    if len(file_data) > 5 * 1024 * 1024:  # 5MB
        return corsify(jsonify({"ok": False, "error": "Avatar file too large (max 5MB)"}), origin), 400
    
    try:
        # Generate filename for avatar
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        avatar_filename = f"avatars/{member_id}.{file_extension}"
        
        # Upload to Vercel Blob
        avatar_url = upload_to_vercel_blob(file_data, avatar_filename, content_type)
        
        # Update member profile with new avatar URL
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Create profile if it doesn't exist
            cur.execute("""
                INSERT INTO user_profiles (user_id, avatar_url) 
                VALUES (%s, %s) 
                ON CONFLICT (user_id) DO UPDATE SET
                    avatar_url = EXCLUDED.avatar_url,
                    updated_at = now()
            """, (member_id, avatar_url))
            
            con.commit()
        
        return corsify(jsonify({
            "ok": True, 
            "message": "Member avatar updated successfully",
            "avatarUrl": avatar_url
        }), origin)
        
    except Exception as e:
        log.error(f"Failed to upload avatar for member {member_id}: {str(e)}")
        return corsify(jsonify({"ok": False, "error": "Failed to upload avatar"}), origin), 500

@app.patch("/api/family/<family_id>/member/<member_id>")
def update_family_member(family_id: str, member_id: str):
    """Update family member details (admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    data = request.get_json(silent=True) or {}
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Check if user has admin permissions for this family
        cur.execute("""
            SELECT role FROM tenant_users 
            WHERE user_id = %s AND tenant_id = %s
        """, (user["id"], family_id))
        membership = cur.fetchone()
        
        if not membership or membership["role"] not in ["OWNER", "ADMIN"]:
            return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403
        
        # Verify member exists in family
        cur.execute("""
            SELECT u.id, tu.role FROM users u
            JOIN tenant_users tu ON u.id = tu.user_id
            WHERE u.id = %s AND tu.tenant_id = %s
        """, (member_id, family_id))
        member = cur.fetchone()
        
        if not member:
            return corsify(jsonify({"ok": False, "error": "Member not found"}), origin), 404
        
        # Prepare updates
        profile_updates = {}
        role_update = None
        
        if "name" in data:
            profile_updates["display_name"] = data["name"].strip()[:100] if data["name"] else None
        if "quote" in data:
            profile_updates["bio"] = data["quote"].strip()[:500] if data["quote"] else None
        if "birthdate" in data:
            if data["birthdate"]:
                try:
                    from datetime import datetime
                    birthdate = datetime.fromisoformat(data["birthdate"].replace('Z', '+00:00')).date()
                    profile_updates["birthdate"] = birthdate
                except ValueError:
                    return corsify(jsonify({"ok": False, "error": "Invalid birthdate format"}), origin), 400
            else:
                profile_updates["birthdate"] = None
        
        if "role" in data and data["role"] in TENANT_ROLES:
            role_update = data["role"]
        
        # Update profile if there are changes
        if profile_updates:
            # Create profile if it doesn't exist
            cur.execute("""
                INSERT INTO user_profiles (user_id) 
                VALUES (%s) 
                ON CONFLICT (user_id) DO NOTHING
            """, (member_id,))
            
            # Build update query dynamically
            set_clauses = [f"{k} = %s" for k in profile_updates.keys()]
            values = list(profile_updates.values()) + [member_id]
            
            cur.execute(f"""
                UPDATE user_profiles 
                SET {', '.join(set_clauses)}, updated_at = now()
                WHERE user_id = %s
            """, values)
        
        # Update role if specified
        if role_update and role_update != member["role"]:
            cur.execute("""
                UPDATE tenant_users 
                SET role = %s
                WHERE user_id = %s AND tenant_id = %s
            """, (role_update, member_id, family_id))
        
        con.commit()
    
    return corsify(jsonify({"ok": True, "message": "Member updated successfully"}), origin)

@app.delete("/api/family/<family_id>/member/<member_id>")
def remove_family_member(family_id: str, member_id: str):
    """Remove a member from the family (admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    with_db()
    with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
        # Check if user has admin permissions for this family
        cur.execute("""
            SELECT role FROM tenant_users 
            WHERE user_id = %s AND tenant_id = %s
        """, (user["id"], family_id))
        membership = cur.fetchone()
        
        if not membership or membership["role"] not in ["OWNER", "ADMIN", "ADULT"]:
            return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403
        
        # Verify member exists in family
        cur.execute("""
            SELECT u.id, tu.role FROM users u
            JOIN tenant_users tu ON u.id = tu.user_id
            WHERE u.id = %s AND tu.tenant_id = %s
        """, (member_id, family_id))
        member = cur.fetchone()
        
        if not member:
            return corsify(jsonify({"ok": False, "error": "Member not found"}), origin), 404
        
        # Prevent removing the last owner
        if member["role"] == "OWNER":
            cur.execute("""
                SELECT COUNT(*) as owner_count FROM tenant_users 
                WHERE tenant_id = %s AND role = 'OWNER'
            """, (family_id,))
            owner_count = cur.fetchone()["owner_count"]
            
            if owner_count <= 1:
                return corsify(jsonify({"ok": False, "error": "Cannot remove the last owner"}), origin), 400
        
        # Prevent self-removal
        if member_id == user["id"]:
            return corsify(jsonify({"ok": False, "error": "Cannot remove yourself"}), origin), 400
        
        # Remove member from family
        cur.execute("""
            DELETE FROM tenant_users 
            WHERE user_id = %s AND tenant_id = %s
        """, (member_id, family_id))
        
        con.commit()
    
    return corsify(jsonify({"ok": True, "message": "Member removed successfully"}), origin)

@app.post("/test/send-email")
def test_send_email():
    """Test endpoint to verify SMTP configuration"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    log.info(f"[TEST EMAIL] Received data: {data}")
    test_email = data.get("to") or data.get("email", "test@example.com")
    test_name = data.get("name", "Test User")
    test_subject = data.get("subject", "Test Email from Kinjar")
    test_body = data.get("body", "This is a test email.")
    
    log.info(f"[TEST EMAIL] Attempting to send test email to: {test_email}")
    log.info(f"[TEST EMAIL] SMTP Config - Host: {SMTP_HOST}, Port: {SMTP_PORT}, Username: {SMTP_USERNAME}")
    log.info(f"[TEST EMAIL] SMTP Username set: {'Yes' if SMTP_USERNAME else 'No'}")
    log.info(f"[TEST EMAIL] SMTP Password set: {'Yes' if SMTP_PASSWORD else 'No'}")
    
    try:
        # Test email sending
        success = send_invitation_email(
            email=test_email,
            name=test_name,
            family_name="Test Family",
            invitation_token="test-token-123",
            family_slug="testfamily"
        )
        
        if success:
            return corsify(jsonify({
                "ok": True, 
                "message": f"Test email sent successfully to {test_email}",
                "smtp_configured": True
            }), origin)
        else:
            return corsify(jsonify({
                "ok": False, 
                "error": "Failed to send test email - check SMTP configuration",
                "smtp_configured": bool(SMTP_USERNAME and SMTP_PASSWORD)
            }), origin), 500
            
    except Exception as e:
        log.error(f"[TEST EMAIL] Exception: {str(e)}")
        return corsify(jsonify({
            "ok": False, 
            "error": f"Email test failed: {str(e)}",
            "smtp_configured": bool(SMTP_USERNAME and SMTP_PASSWORD)
        }), origin), 500

@app.post("/auth/invite-member")
def invite_family_member():
    """Invite a new member to join a family"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    try:
        data = request.get_json(silent=True) or {}
        log.info(f"[INVITE] Received data: {data}")
        
        email = (data.get("email") or "").strip().lower()
        name = (data.get("name") or "").strip()
        family_id = data.get("familyId")
        birthdate = data.get("birthdate")
        role = data.get("role", "ADULT")
        
        log.info(f"[INVITE] Parsed - name: '{name}', familyId: '{family_id}', email: '{email}', role: '{role}'")
        
        # Calculate age if birthdate is provided
        age = None
        birth_date = None
        if birthdate:
            try:
                from datetime import datetime, timedelta
                birth_date = datetime.fromisoformat(birthdate.replace('Z', '+00:00')).date()
                age = calculate_age(birth_date)
                # Auto-assign role based on age unless manually specified
                if role == "ADULT" and age is not None:
                    role = determine_role_from_age(age)
                log.info(f"[INVITE] Calculated age: {age}, assigned role: {role}")
            except ValueError as e:
                log.error(f"[INVITE] Invalid birthdate format: {birthdate}, error: {e}")
                pass
        
        # Email is optional for kids under 16
        is_child_under_16 = age is not None and age < 16
        if not is_child_under_16 and not email:
            log.error(f"[INVITE] Email required for users 16+, age: {age}")
            return corsify(jsonify({"ok": False, "error": "Email is required for users 16 and older"}), origin), 400
        
        if not name or not family_id:
            log.error(f"[INVITE] Missing required fields - name: '{name}', familyId: '{family_id}'")
            return corsify(jsonify({"ok": False, "error": "Missing required fields (name, familyId)"}), origin), 400
        
        if role not in TENANT_ROLES:
            log.error(f"[INVITE] Invalid role: {role}, valid roles: {TENANT_ROLES}")
            return corsify(jsonify({"ok": False, "error": "Invalid role"}), origin), 400
        
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check if user has permission to invite members to this family
            log.info(f"[INVITE] Checking permissions for user {user['id']} in family {family_id}")
            cur.execute("""
                SELECT role FROM tenant_users 
                WHERE user_id = %s AND tenant_id = %s
            """, (user["id"], family_id))
            membership = cur.fetchone()
            
            log.info(f"[INVITE] User membership: {membership}")
            if not membership or membership["role"] not in ["OWNER", "ADMIN", "ADULT"]:
                log.error(f"[INVITE] Permission denied - membership: {membership}, required roles: ['OWNER', 'ADMIN', 'ADULT']")
                return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403
            
            # Get family info for the invitation
            cur.execute("""
                SELECT name, slug FROM tenants WHERE id = %s
            """, (family_id,))
            family = cur.fetchone()
            if not family:
                return corsify(jsonify({"ok": False, "error": "Family not found"}), origin), 404
            
            # For children under 16, create them directly without sending an email
            if is_child_under_16:
                # Check if child already exists by name (since no email)
                cur.execute("""
                    SELECT up.user_id FROM user_profiles up
                    JOIN tenant_users tu ON up.user_id = tu.user_id
                    WHERE up.display_name = %s AND tu.tenant_id = %s
                """, (name, family_id))
                if cur.fetchone():
                    return corsify(jsonify({"ok": False, "error": "Child with this name already exists in family"}), origin), 409
                
                # Create user without email (for kids under 16)
                new_user_id = str(uuid4())
                child_email = f"child.{new_user_id}@kinjar.internal"
                cur.execute("""
                    INSERT INTO users (id, email, global_role)
                    VALUES (%s, %s, 'USER')
                """, (new_user_id, child_email))
                
                # Create profile
                cur.execute("""
                    INSERT INTO user_profiles (user_id, display_name, birthdate)
                    VALUES (%s, %s, %s)
                """, (new_user_id, name, birth_date if birthdate else None))
                
                # Add to family
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, %s)
                """, (new_user_id, family_id, role))
                
                con.commit()
                
                return corsify(jsonify({
                    "ok": True, 
                    "message": f"Child {name} added to family successfully",
                    "userId": new_user_id,
                    "assignedRole": role,
                    "emailSent": False
                }), origin)
            
            # For adults and teens (16+), send an invitation email
            if not email:
                return corsify(jsonify({"ok": False, "error": "Email is required for members 16 and older"}), origin), 400
            
            # Check if email is already a member
            cur.execute("""
                SELECT u.id FROM users u
                JOIN tenant_users tu ON u.id = tu.user_id
                WHERE u.email = %s AND tu.tenant_id = %s
            """, (email, family_id))
            if cur.fetchone():
                return corsify(jsonify({"ok": False, "error": "User is already a member"}), origin), 409
            
            # Check if there's already a pending invitation for this email
            cur.execute("""
                SELECT id FROM tenant_invitations 
                WHERE email = %s AND tenant_id = %s AND status = 'pending'
            """, (email, family_id))
            existing_invitation = cur.fetchone()
            
            if existing_invitation:
                return corsify(jsonify({"ok": False, "error": "Invitation already sent to this email"}), origin), 409
            
            # Create invitation token and record
            invite_id = str(uuid4())
            invite_token = str(uuid4()).replace('-', '')  # Clean token for URL
            expires_at = datetime.now() + timedelta(days=7)  # 7 day expiry
            
            cur.execute("""
                INSERT INTO tenant_invitations (
                    id, tenant_id, invited_by, email, invited_name, role, 
                    invite_token, expires_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            """, (invite_id, family_id, user["id"], email, name, role, invite_token, expires_at))
            
            con.commit()
            
            # Send invitation email
            email_sent = send_invitation_email(email, name, family["name"], invite_token, family["slug"])
            
            return corsify(jsonify({
                "ok": True, 
                "message": "Invitation sent successfully",
                "invitationId": invite_id,
                "assignedRole": role,
                "emailSent": email_sent,
                "expiresAt": expires_at.isoformat()
            }), origin)
            
    except Exception as e:
        log.error(f"[INVITE] Exception in invite_family_member: {e}")
        import traceback
        log.error(f"[INVITE] Traceback: {traceback.format_exc()}")
        return corsify(jsonify({
            "ok": False, 
            "error": "Internal server error",
            "debug": str(e) if app.debug else None
        }), origin), 500

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

# ---------------- Enhanced Root Admin Endpoints ----------------

@app.get("/admin/dashboard")
def admin_dashboard():
    """Get system-wide statistics for root admin dashboard"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                stats = {}
                
                # Family statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_families,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as new_families_30d,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as new_families_7d
                    FROM tenants
                """)
                family_stats = cur.fetchone()
                stats.update(dict(family_stats))
                
                # User statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as new_users_30d,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as new_users_7d,
                        COUNT(*) FILTER (WHERE global_role = 'ROOT') as root_users
                    FROM users
                """)
                user_stats = cur.fetchone()
                stats.update(dict(user_stats))
                
                # Content statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_posts,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as new_posts_30d,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as new_posts_7d,
                        SUM(view_count) as total_views
                    FROM content_posts WHERE status = 'published'
                """)
                content_stats = cur.fetchone()
                stats.update(dict(content_stats))
                
                # Media statistics  
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_media,
                        SUM(size_bytes) as total_storage_bytes,
                        COUNT(*) FILTER (WHERE content_type LIKE 'image/%') as total_images,
                        COUNT(*) FILTER (WHERE content_type LIKE 'video/%') as total_videos,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as new_media_30d
                    FROM media_objects WHERE status = 'uploaded'
                """)
                media_stats = cur.fetchone()
                stats.update(dict(media_stats))
                
                # Family connections
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_connections,
                        COUNT(*) FILTER (WHERE status = 'accepted') as active_connections,
                        COUNT(*) FILTER (WHERE status = 'pending') as pending_connections
                    FROM family_connections
                """)
                connection_stats = cur.fetchone()
                stats.update(dict(connection_stats))
                
                # Signup requests
                cur.execute("""
                    SELECT 
                        COUNT(*) as pending_signups,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as new_signup_requests_7d
                    FROM signup_requests WHERE status = 'pending'
                """)
                signup_stats = cur.fetchone()
                stats.update(dict(signup_stats))

                # Active families (posted in last 30 days)
                cur.execute("""
                    SELECT COUNT(DISTINCT tenant_id) as active_families_30d
                    FROM content_posts 
                    WHERE created_at >= NOW() - INTERVAL '30 days' AND status = 'published'
                """)
                activity_stats = cur.fetchone()
                stats.update(dict(activity_stats))

            return corsify(jsonify({"ok": True, "stats": stats}), origin)

    except Exception as e:
        log.exception("Failed to get admin dashboard")
        return corsify(jsonify({"ok": False, "error": "dashboard_failed"}), origin), 500

@app.get("/admin/families")
def admin_list_all_families():
    """List all families with detailed information"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)
    search = request.args.get("search", "").strip()

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Build query with optional search
                base_query = """
                    SELECT 
                        t.id, t.slug, t.name, t.created_at,
                        COUNT(tu.user_id) as member_count,
                        COUNT(cp.id) as post_count,
                        COUNT(mo.id) as media_count,
                        SUM(mo.size_bytes) as storage_bytes,
                        fs.family_photo, fs.description, fs.is_public,
                        MAX(cp.created_at) as last_post_at,
                        MAX(af.created_at) as last_activity_at
                    FROM tenants t
                    LEFT JOIN tenant_users tu ON t.id = tu.tenant_id
                    LEFT JOIN content_posts cp ON t.id = cp.tenant_id AND cp.status = 'published'
                    LEFT JOIN media_objects mo ON t.slug = mo.tenant AND mo.status = 'uploaded'
                    LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                    LEFT JOIN activity_feed af ON t.id = af.tenant_id
                """
                
                params = []
                if search:
                    base_query += " WHERE (t.name ILIKE %s OR t.slug ILIKE %s OR fs.description ILIKE %s)"
                    search_pattern = f"%{search}%"
                    params.extend([search_pattern, search_pattern, search_pattern])
                
                base_query += """
                    GROUP BY t.id, t.slug, t.name, t.created_at, fs.family_photo, fs.description, fs.is_public
                    ORDER BY t.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([limit, offset])
                
                cur.execute(base_query, params)
                families = [dict(row) for row in cur.fetchall()]
                
                # Get total count
                count_query = "SELECT COUNT(*) as total FROM tenants t"
                count_params = []
                if search:
                    count_query += """
                        LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                        WHERE (t.name ILIKE %s OR t.slug ILIKE %s OR fs.description ILIKE %s)
                    """
                    count_params.extend([search_pattern, search_pattern, search_pattern])
                
                cur.execute(count_query, count_params)
                total = cur.fetchone()["total"]

            return corsify(jsonify({
                "ok": True, 
                "families": families, 
                "total": total,
                "limit": limit,
                "offset": offset
            }), origin)

    except Exception as e:
        log.exception("Failed to list families")
        return corsify(jsonify({"ok": False, "error": "list_families_failed"}), origin), 500

@app.get("/admin/families/<family_slug>/details")
def admin_get_family_details(family_slug: str):
    """Get detailed information about a specific family"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get family basic info
                cur.execute("SELECT * FROM tenants WHERE slug = %s", (family_slug,))
                family = cur.fetchone()
                if not family:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                # Get family settings
                cur.execute("SELECT * FROM family_settings WHERE tenant_id = %s", (family["id"],))
                settings = cur.fetchone()

                # Get members with roles
                cur.execute("""
                    SELECT 
                        u.id, u.email, u.created_at, u.global_role,
                        tu.role as family_role,
                        up.display_name, up.avatar_url, up.bio
                    FROM tenant_users tu
                    JOIN users u ON tu.user_id = u.id
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    WHERE tu.tenant_id = %s
                    ORDER BY 
                        CASE tu.role 
                            WHEN 'OWNER' THEN 1 
                            WHEN 'ADMIN' THEN 2 
                            WHEN 'MEMBER' THEN 3 
                            ELSE 4 
                        END
                """, (family["id"],))
                members = [dict(row) for row in cur.fetchall()]

                # Get recent posts
                cur.execute("""
                    SELECT 
                        cp.id, cp.title, cp.created_at, cp.view_count, cp.content_type,
                        u.email as author_email,
                        up.display_name as author_name
                    FROM content_posts cp
                    JOIN users u ON cp.author_id = u.id
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    WHERE cp.tenant_id = %s AND cp.status = 'published'
                    ORDER BY cp.created_at DESC
                    LIMIT 10
                """, (family["id"],))
                recent_posts = [dict(row) for row in cur.fetchall()]

                # Get connected families
                connected_families = get_connected_families(con, family["id"])

                # Get statistics
                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT tu.user_id) as member_count,
                        COUNT(DISTINCT cp.id) as post_count,
                        COUNT(DISTINCT mo.id) as media_count,
                        SUM(mo.size_bytes) as storage_bytes,
                        SUM(cp.view_count) as total_views
                    FROM tenants t
                    LEFT JOIN tenant_users tu ON t.id = tu.tenant_id
                    LEFT JOIN content_posts cp ON t.id = cp.tenant_id AND cp.status = 'published'
                    LEFT JOIN media_objects mo ON t.slug = mo.tenant AND mo.status = 'uploaded'
                    WHERE t.id = %s
                    GROUP BY t.id
                """, (family["id"],))
                stats = cur.fetchone()

            return corsify(jsonify({
                "ok": True,
                "family": dict(family),
                "settings": dict(settings) if settings else None,
                "members": members,
                "recent_posts": recent_posts,
                "connected_families": connected_families,
                "stats": dict(stats) if stats else {}
            }), origin)

    except Exception as e:
        log.exception("Failed to get family details")
        return corsify(jsonify({"ok": False, "error": "family_details_failed"}), origin), 500

@app.post("/admin/families/<family_slug>/suspend")
def admin_suspend_family(family_slug: str):
    """Suspend a family (disable posting/activity)"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    body = request.get_json(silent=True) or {}
    reason = body.get("reason", "").strip()
    duration_days = body.get("duration_days")  # None for indefinite

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Verify family exists
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (family_slug,))
                family = cur.fetchone()
                if not family:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                # Add suspension to tenant settings
                suspension_data = {
                    "suspended": True,
                    "suspended_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "suspended_by": admin["email"],
                    "suspension_reason": reason,
                    "suspension_duration_days": duration_days
                }

                cur.execute("""
                    INSERT INTO tenant_settings (tenant_id, key, value)
                    VALUES (%s, 'suspension', %s::jsonb)
                    ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """, (family["id"], json.dumps(suspension_data)))

        audit("family_suspended", family=family_slug, reason=reason, admin=admin["email"])
        return corsify(jsonify({"ok": True, "family": family_slug, "suspended": True}), origin)

    except Exception as e:
        log.exception("Failed to suspend family")
        return corsify(jsonify({"ok": False, "error": "suspension_failed"}), origin), 500

@app.delete("/admin/families/<family_slug>/suspend")
def admin_unsuspend_family(family_slug: str):
    """Remove suspension from a family"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Verify family exists
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (family_slug,))
                family = cur.fetchone()
                if not family:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                # Remove suspension
                cur.execute("""
                    DELETE FROM tenant_settings 
                    WHERE tenant_id = %s AND key = 'suspension'
                """, (family["id"],))

        audit("family_unsuspended", family=family_slug, admin=admin["email"])
        return corsify(jsonify({"ok": True, "family": family_slug, "suspended": False}), origin)

    except Exception as e:
        log.exception("Failed to unsuspend family")
        return corsify(jsonify({"ok": False, "error": "unsuspension_failed"}), origin), 500

@app.get("/admin/users")
def admin_list_users():
    """List all users with their family memberships"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)
    search = request.args.get("search", "").strip()

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Build query with optional search
                base_query = """
                    SELECT 
                        u.id, u.email, u.created_at, u.global_role,
                        up.display_name, up.avatar_url,
                        COUNT(tu.tenant_id) as family_count,
                        COUNT(cp.id) as post_count,
                        COUNT(cc.id) as comment_count,
                        MAX(af.created_at) as last_activity
                    FROM users u
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    LEFT JOIN tenant_users tu ON u.id = tu.user_id
                    LEFT JOIN content_posts cp ON u.id = cp.author_id AND cp.status = 'published'
                    LEFT JOIN content_comments cc ON u.id = cc.author_id AND cc.status = 'published'
                    LEFT JOIN activity_feed af ON u.id = af.user_id
                """
                
                params = []
                if search:
                    base_query += " WHERE (u.email ILIKE %s OR up.display_name ILIKE %s)"
                    search_pattern = f"%{search}%"
                    params.extend([search_pattern, search_pattern])
                
                base_query += """
                    GROUP BY u.id, u.email, u.created_at, u.global_role, up.display_name, up.avatar_url
                    ORDER BY u.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([limit, offset])
                
                cur.execute(base_query, params)
                users = [dict(row) for row in cur.fetchall()]
                
                # Get family memberships for each user
                for user in users:
                    cur.execute("""
                        SELECT t.slug, t.name, tu.role 
                        FROM tenant_users tu
                        JOIN tenants t ON tu.tenant_id = t.id
                        WHERE tu.user_id = %s
                        ORDER BY t.name
                    """, (user["id"],))
                    user["families"] = [dict(row) for row in cur.fetchall()]

                # Get total count
                count_query = "SELECT COUNT(*) as total FROM users u"
                count_params = []
                if search:
                    count_query += """
                        LEFT JOIN user_profiles up ON u.id = up.user_id
                        WHERE (u.email ILIKE %s OR up.display_name ILIKE %s)
                    """
                    count_params.extend([search_pattern, search_pattern])
                
                cur.execute(count_query, count_params)
                total = cur.fetchone()["total"]

            return corsify(jsonify({
                "ok": True, 
                "users": users, 
                "total": total,
                "limit": limit,
                "offset": offset
            }), origin)

    except Exception as e:
        log.exception("Failed to list users")
        return corsify(jsonify({"ok": False, "error": "list_users_failed"}), origin), 500

@app.get("/admin/audit")
def admin_get_audit_log():
    """Get recent audit log entries"""
    origin = request.headers.get("Origin")
    admin, err = require_root()
    if err:
        return corsify(err, origin)

    limit = min(max(int(request.args.get("limit", "100")), 1), 1000)
    event_filter = request.args.get("event", "").strip()

    try:
        # Read audit log file
        if not os.path.exists(AUDIT_FILE):
            return corsify(jsonify({"ok": True, "entries": [], "total": 0}), origin)

        entries = []
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if not event_filter or entry.get("event", "").startswith(event_filter):
                        entries.append(entry)
                except (json.JSONDecodeError, ValueError):
                    continue

        # Sort by timestamp descending and limit
        entries.sort(key=lambda x: x.get("ts", 0), reverse=True)
        entries = entries[:limit]

        # Convert timestamps to readable format
        for entry in entries:
            if "ts" in entry:
                entry["timestamp"] = datetime.datetime.fromtimestamp(
                    entry["ts"], tz=datetime.timezone.utc
                ).isoformat()

        return corsify(jsonify({
            "ok": True, 
            "entries": entries,
            "total": len(entries),
            "audit_file": AUDIT_FILE
        }), origin)

    except Exception as e:
        log.exception("Failed to get audit log")
        return corsify(jsonify({"ok": False, "error": "audit_failed"}), origin), 500

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
    # TODO: Add proper authentication later - allowing for development
    # if not is_authorized(request):
    #     return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

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
    except StorageNotConfigured as e:
        log.warning("presign requested but storage is not configured: %s", e)
        return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503
    try:
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

# ---------------- Enhanced Mobile Upload API ----------------

@app.post("/api/media/upload/prepare")
def prepare_media_upload():
    """Enhanced upload preparation with metadata support for mobile"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    body = request.get_json(silent=True) or {}
    filename = sanitize_filename(body.get("filename", "file.bin"))
    if not filename:
        return corsify(jsonify({"ok": False, "error": "invalid_filename"}), origin), 400

    ctype = (body.get("contentType") or "application/octet-stream").strip()
    if ALLOWED_CONTENT_TYPES and ctype not in ALLOWED_CONTENT_TYPES:
        return corsify(jsonify({"ok": False, "error": "unsupported_content_type"}), origin), 415

    # Enhanced metadata capture
    metadata = {
        "title": body.get("title", "").strip(),
        "description": body.get("description", "").strip(), 
        "location": body.get("location"),  # GPS coordinates
        "device_info": body.get("device_info"),  # Device/camera info
        "dimensions": body.get("dimensions"),  # Width/height for images/videos
        "duration": body.get("duration"),  # For videos
        "file_size": body.get("file_size"),  # Expected file size
    }

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Verify tenant exists and user is member
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], tenant["id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "not_tenant_member"}), origin), 403

        mid = str(uuid4())
        key = f"t/{tenant_slug}/uploads/{mid}/{filename}"

        try:
            s3 = s3_client()
        except StorageNotConfigured as e:
            log.warning("media upload prepare requested but storage is not configured: %s", e)
            return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

        # Generate presigned URLs for upload and POST-complete
        put_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": ctype},
            ExpiresIn=900,  # 15 minutes for mobile uploads
            HttpMethod="PUT",
        )

        # Enhanced database record with metadata
        with_db()
        with pool.connection() as con, con.cursor() as cur:
            cur.execute("""
                INSERT INTO media_objects 
                (id, tenant, r2_key, filename, content_type, status, uploaded_by, title, description,
                 width, height, duration_seconds, size_bytes)
                VALUES (%s, %s, %s, %s, %s, 'presigned', %s, %s, %s, %s, %s, %s, %s)
            """, (
                mid, tenant_slug, key, filename, ctype, user["id"],
                metadata["title"], metadata["description"],
                metadata["dimensions"].get("width") if metadata["dimensions"] else None,
                metadata["dimensions"].get("height") if metadata["dimensions"] else None,
                metadata["duration"], metadata["file_size"]
            ))

        response = {
            "ok": True,
            "upload_id": mid,
            "key": key,
            "upload_url": put_url,
            "expires_in": 900,
            "max_size_mb": 150,
            "content_type": ctype,
            "complete_url": f"/api/media/upload/{mid}/complete"
        }

        audit("media_upload_prepared", 
              tenant=tenant_slug, 
              upload_id=mid, 
              filename=filename,
              content_type=ctype,
              user_email=user["email"])

        return corsify(jsonify(response), origin)

    except Exception as e:
        log.exception("Failed to prepare media upload")
        return corsify(jsonify({"ok": False, "error": "prepare_failed"}), origin), 500

@app.post("/api/media/upload/<upload_id>/complete")
def complete_media_upload(upload_id: str):
    """Mark upload as complete and optionally create a post"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    create_post = body.get("create_post", False)
    post_title = body.get("post_title", "").strip()
    post_content = body.get("post_content", "").strip()
    share_with_families = body.get("share_with_families", [])

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get media object
                cur.execute("""
                    SELECT mo.*, t.id as tenant_id, t.slug as tenant_slug 
                    FROM media_objects mo
                    JOIN tenants t ON mo.tenant = t.slug
                    WHERE mo.id = %s AND mo.uploaded_by = %s AND mo.status = 'presigned'
                """, (upload_id, user["id"]))
                media_obj = cur.fetchone()
                
                if not media_obj:
                    return corsify(jsonify({"ok": False, "error": "upload_not_found"}), origin), 404

                # Verify upload was successful by checking object in storage
                try:
                    s3 = s3_client()
                    head_response = s3.head_object(Bucket=S3_BUCKET, Key=media_obj["r2_key"])
                    actual_size = head_response.get("ContentLength", 0)
                    actual_content_type = head_response.get("ContentType", media_obj["content_type"])
                except Exception as e:
                    log.warning(f"Could not verify upload for {upload_id}: {e}")
                    return corsify(jsonify({"ok": False, "error": "upload_verification_failed"}), origin), 400

                # Mark as uploaded
                cur.execute("""
                    UPDATE media_objects 
                    SET status = 'uploaded', size_bytes = %s, content_type = %s, updated_at = now()
                    WHERE id = %s
                    RETURNING *
                """, (actual_size, actual_content_type, upload_id))
                
                updated_media = cur.fetchone()
                
                result = {
                    "ok": True,
                    "media": dict(updated_media),
                    "post_created": False
                }

                # Optionally create a post
                if create_post and post_title:
                    post = create_content_post(
                        con, media_obj["tenant_id"], user["id"], 
                        post_title, post_content, upload_id, 
                        "photo" if actual_content_type.startswith("image/") else "video"
                    )
                    result["post_created"] = True
                    result["post"] = dict(post)
                    
                    # Share with connected families if requested
                    if share_with_families:
                        shared_with = []
                        for family_slug in share_with_families:
                            cur.execute("SELECT id FROM tenants WHERE slug = %s", (family_slug,))
                            target_tenant = cur.fetchone()
                            if target_tenant and share_post_with_family(con, post["id"], target_tenant["id"], user["id"]):
                                shared_with.append(family_slug)
                        result["shared_with"] = shared_with

        audit("media_upload_completed", 
              tenant=media_obj["tenant_slug"],
              upload_id=upload_id, 
              size_bytes=actual_size,
              post_created=create_post,
              user_email=user["email"])

        return corsify(jsonify(result), origin)

    except Exception as e:
        log.exception("Failed to complete media upload")
        return corsify(jsonify({"ok": False, "error": "completion_failed"}), origin), 500

@app.get("/api/media/<media_id>")
def get_media_info(media_id: str):
    """Get media object info with signed URL"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get media with tenant info
                cur.execute("""
                    SELECT mo.*, t.id as tenant_id, t.slug as tenant_slug 
                    FROM media_objects mo
                    JOIN tenants t ON mo.tenant = t.slug
                    WHERE mo.id = %s AND mo.status = 'uploaded'
                """, (media_id,))
                media_obj = cur.fetchone()
                
                if not media_obj:
                    return corsify(jsonify({"ok": False, "error": "media_not_found"}), origin), 404

                # Check user has access (member of tenant or connected family)
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], media_obj["tenant_id"]))
                membership = cur.fetchone()
                
                if not membership:
                    # Check if user's family is connected
                    cur.execute("""
                        SELECT DISTINCT tu.tenant_id FROM tenant_users tu
                        JOIN family_connections fc ON (
                            (fc.requesting_tenant_id = tu.tenant_id AND fc.target_tenant_id = %s)
                            OR (fc.target_tenant_id = tu.tenant_id AND fc.requesting_tenant_id = %s)
                        )
                        WHERE tu.user_id = %s AND fc.status = 'accepted'
                    """, (media_obj["tenant_id"], media_obj["tenant_id"], user["id"]))
                    
                    if not cur.fetchone():
                        return corsify(jsonify({"ok": False, "error": "access_denied"}), origin), 403

                # Generate signed URL
                try:
                    s3 = s3_client()
                    signed_url = s3.generate_presigned_url(
                        ClientMethod="get_object",
                        Params={"Bucket": S3_BUCKET, "Key": media_obj["r2_key"]},
                        ExpiresIn=3600,
                    )
                    media_dict = dict(media_obj)
                    media_dict["url"] = signed_url
                    
                    return corsify(jsonify({"ok": True, "media": media_dict}), origin)
                    
                except StorageNotConfigured as e:
                    log.warning("get_media_info requested but storage is not configured: %s", e)
                    return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

    except Exception as e:
        log.exception("Failed to get media info")
        return corsify(jsonify({"ok": False, "error": "get_media_failed"}), origin), 500

@app.get("/r2/head")
def head_meta():
    origin = request.headers.get("Origin")
    if not is_authorized(request):
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    key = request.args.get("key", "")
    if not key:
        return corsify(jsonify({"ok": False, "error": "missing_key"}), origin), 400

    try:
        s3 = s3_client()
    except StorageNotConfigured as e:
        log.warning("head_meta requested but storage is not configured: %s", e)
        return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

    try:
        h = s3.head_object(Bucket=S3_BUCKET, Key=key)
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
        s3 = s3_client()
    except StorageNotConfigured as e:
        log.warning("signed_get requested but storage is not configured: %s", e)
        return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

    try:
        url = s3.generate_presigned_url(
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
        s3 = s3_client()
    except StorageNotConfigured as e:
        log.warning("delete requested but storage is not configured: %s", e)
        return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

    try:
        s3.delete_object(Bucket=S3_BUCKET, Key=key)
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
    except StorageNotConfigured as e:
        log.warning("direct upload requested but storage is not configured: %s", e)
        return corsify(jsonify({"ok": False, "error": "storage_not_configured"}), origin), 503

    try:
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

@app.post("/upload/complete")
def upload_complete():
    """Notify API that a presigned upload has completed"""
    origin = request.headers.get("Origin")
    # TODO: Add proper authentication later - allowing for development
    # if not is_authorized(request):
    #     return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant = sanitize_tenant(request.headers.get("x-tenant-slug", "default"))
    if not tenant:
        return corsify(jsonify({"ok": False, "error": "invalid_tenant"}), origin), 400

    body = request.get_json(silent=True) or {}
    upload_id = body.get("id")
    key = body.get("key") 
    upload_type = body.get("type", "photo")
    file_size = body.get("size", 0)

    if not upload_id or not key:
        return corsify(jsonify({"ok": False, "error": "missing_required_fields"}), origin), 400

    try:
        # Mark the upload as completed in the database
        db_mark_uploaded(key, file_size, "")
        
        # Create a content post for the uploaded media
        try:
            if pool:
                with pool.connection() as con:
                    tenant_id = get_or_create_tenant(con, tenant)
                    
                    # For now, use a default author - in production you'd get this from auth
                    author_id = tenant_id  # Using tenant_id as default author
                    
                    # Extract filename from key
                    filename = key.split('/')[-1] if '/' in key else key
                    title = f"{upload_type.title()} upload - {filename}"
                    
                    result = create_content_post(
                        con, 
                        tenant_id, 
                        author_id, 
                        title,
                        content=f"Uploaded {upload_type} via presigned URL",
                        media_id=upload_id,
                        content_type="media_upload",
                        is_public=True
                    )
                    
                    log.info(f"Created content post for upload: {result['id']}")
                    
        except Exception as e:
            log.exception("Failed to create content post for upload")
            # Don't fail the upload completion for this

        resp = {
            "ok": True,
            "id": upload_id,
            "key": key,
            "type": upload_type,
            "size": file_size
        }
        
        if PUBLIC_MEDIA_BASE:
            resp["publicUrl"] = f"{PUBLIC_MEDIA_BASE.rstrip('/')}/{key}"
        
        audit("upload_complete", tenant=tenant, id=upload_id, key=key, size=file_size)
        return corsify(jsonify(resp), origin)
        
    except Exception as e:
        log.exception("Upload completion failed")
        return corsify(jsonify({"ok": False, "error": f"completion_failed: {str(e)}"}), origin), 500

# ---------------- Video Blog API Routes ----------------

# Helper functions for video blog features
def create_content_post(con, tenant_id: str, author_id: str, title: str, content: str = "", 
                       media_id: str = None, media_url: str = None, content_type: str = "video_blog", 
                       is_public: bool = True, visibility: str = "family") -> Dict[str, Any]:
    """Create a new content post (video blog entry)"""
    post_id = str(uuid4())
    published_at = datetime.datetime.now(datetime.timezone.utc)
    
    log.info(f"[DEBUG] Creating post with media_id={media_id}, media_url={media_url}")
    
    with con.cursor(row_factory=dict_row) as cur:
        # Get user's role and permissions in this family
        cur.execute("""
            SELECT tu.role, up.birthdate, up.permissions_manual
            FROM tenant_users tu
            LEFT JOIN user_profiles up ON tu.user_id = up.user_id
            WHERE tu.user_id = %s AND tu.tenant_id = %s
        """, (author_id, tenant_id))
        user_membership = cur.fetchone()
        
        # Determine if post needs approval
        status = "published"  # Default status
        if user_membership:
            permissions = get_role_permissions(user_membership["role"])
            
            # Check if user needs approval for this type of post
            if is_public and not permissions["can_post_public"]:
                # User cannot post publicly at all
                raise ValueError("User is not allowed to post publicly")
            
            if permissions["requires_approval"]:
                if is_public:
                    status = "pending_approval"  # Public posts need approval
                # Family posts might also need approval for very young children
                elif user_membership["role"] in ["CHILD_0_5", "CHILD_5_10"]:
                    status = "pending_approval"
        
        # If we have a media_url (e.g., from Vercel Blob) but no media_id, create a media object
        actual_media_id = media_id
        if media_url and not media_id:
            # Create a media object entry for the external URL
            media_object_id = str(uuid4())
            # Extract filename from URL or generate one
            filename = media_url.split('/')[-1] if media_url else f"upload_{int(time.time())}"
            
            cur.execute("""
                INSERT INTO media_objects (id, tenant, filename, content_type, 
                                         external_url, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (media_object_id, tenant_id, filename, 'image/jpeg', media_url, 'completed', published_at))
            actual_media_id = media_object_id
        
        # Create the post with appropriate status
        # First check if visibility column exists
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'content_posts' AND column_name = 'visibility'
        """)
        has_visibility = cur.fetchone() is not None
        
        if has_visibility:
            cur.execute("""
                INSERT INTO content_posts (id, tenant_id, author_id, media_id, title, content, 
                                         content_type, is_public, visibility, status, published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (post_id, tenant_id, author_id, actual_media_id, title, content, content_type, is_public, visibility, status, published_at))
        else:
            # Fallback for databases without visibility column
            cur.execute("""
                INSERT INTO content_posts (id, tenant_id, author_id, media_id, title, content, 
                                         content_type, is_public, status, published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (post_id, tenant_id, author_id, actual_media_id, title, content, content_type, is_public, status, published_at))
        
        post = cur.fetchone()
        
        # Add to activity feed
        action_type = "post_created" if status == "published" else "post_submitted_for_approval"
        cur.execute("""
            INSERT INTO activity_feed (id, tenant_id, user_id, action_type, entity_type, entity_id, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (str(uuid4()), tenant_id, author_id, action_type, "content_post", post_id, 
              json.dumps({"title": title, "content_type": content_type, "status": status})))
        
    return post

def get_tenant_posts(con, tenant_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Get published posts for a tenant with author and media info"""
    try:
        with con.cursor(row_factory=dict_row) as cur:
            # First check if visibility column exists
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'content_posts' AND column_name = 'visibility'
            """)
            has_visibility = cur.fetchone() is not None
            log.info(f"Visibility column exists: {has_visibility}")
            
            # Build query with conditional visibility column
            if has_visibility:
                cur.execute("""
                    SELECT 
                        p.*,
                        u.email as author_email,
                        up.display_name as author_name,
                        up.avatar_url as author_avatar,
                        m.filename as media_filename,
                        m.content_type as media_content_type,
                        m.r2_key as media_r2_key,
                        m.external_url as media_external_url,
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
            else:
                # Fallback query without visibility column
                cur.execute("""
                    SELECT 
                        p.*,
                        u.email as author_email,
                        up.display_name as author_name,
                        up.avatar_url as author_avatar,
                        m.filename as media_filename,
                        m.content_type as media_content_type,
                        m.r2_key as media_r2_key,
                        m.external_url as media_external_url,
                        m.thumbnail_url as media_thumbnail,
                        m.duration_seconds as media_duration,
                        CASE WHEN p.is_public THEN 'public' ELSE 'family' END as visibility
                    FROM content_posts p
                    JOIN users u ON p.author_id = u.id
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    LEFT JOIN media_objects m ON p.media_id = m.id
                    WHERE p.tenant_id = %s AND p.status = 'published'
                    ORDER BY p.published_at DESC
                    LIMIT %s OFFSET %s
                """, (tenant_id, limit, offset))
            
            result = cur.fetchall()
            log.info(f"Query returned {len(result)} posts")
            return result
    except Exception as e:
        log.exception(f"Error in get_tenant_posts: {str(e)}")
        raise

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

def get_connected_families(con, tenant_id: str) -> List[Dict[str, Any]]:
    """Get all families connected to this tenant (accepted connections only)"""
    with con.cursor(row_factory=dict_row) as cur:
        cur.execute("""
            SELECT 
                fc.id as connection_id,
                fc.created_at as connected_at,
                CASE 
                    WHEN fc.requesting_tenant_id = %s THEN target_t.id
                    ELSE requesting_t.id
                END as family_id,
                CASE 
                    WHEN fc.requesting_tenant_id = %s THEN target_t.slug
                    ELSE requesting_t.slug
                END as family_slug,
                CASE 
                    WHEN fc.requesting_tenant_id = %s THEN target_t.name
                    ELSE requesting_t.name
                END as family_name,
                fs.family_photo,
                fs.description
            FROM family_connections fc
            JOIN tenants requesting_t ON fc.requesting_tenant_id = requesting_t.id
            JOIN tenants target_t ON fc.target_tenant_id = target_t.id
            LEFT JOIN family_settings fs ON (
                CASE 
                    WHEN fc.requesting_tenant_id = %s THEN target_t.id
                    ELSE requesting_t.id
                END = fs.tenant_id
            )
            WHERE (fc.requesting_tenant_id = %s OR fc.target_tenant_id = %s) 
              AND fc.status = 'accepted'
            ORDER BY fc.created_at DESC
        """, (tenant_id, tenant_id, tenant_id, tenant_id, tenant_id, tenant_id))
        return cur.fetchall()

def get_cross_family_posts(con, viewing_tenant_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Get posts visible to this family from connected families"""
    with con.cursor(row_factory=dict_row) as cur:
        # Get posts from own tenant and connected families
        cur.execute("""
            SELECT DISTINCT
                p.*,
                u.email as author_email,
                up.display_name as author_name,
                up.avatar_url as author_avatar,
                m.filename as media_filename,
                m.content_type as media_content_type,
                m.r2_key as media_r2_key,
                m.thumbnail_url as media_thumbnail,
                m.duration_seconds as media_duration,
                t.slug as family_slug,
                t.name as family_name,
                fs.family_photo as family_photo
            FROM content_posts p
            JOIN users u ON p.author_id = u.id
            JOIN tenants t ON p.tenant_id = t.id
            LEFT JOIN user_profiles up ON u.id = up.user_id
            LEFT JOIN media_objects m ON p.media_id = m.id
            LEFT JOIN family_settings fs ON t.id = fs.tenant_id
            WHERE p.status = 'published' AND (
                -- Own family posts
                p.tenant_id = %s
                OR
                -- Connected family posts that are shared
                (p.tenant_id IN (
                    SELECT CASE 
                        WHEN fc.requesting_tenant_id = %s THEN fc.target_tenant_id
                        ELSE fc.requesting_tenant_id
                    END
                    FROM family_connections fc
                    WHERE (fc.requesting_tenant_id = %s OR fc.target_tenant_id = %s)
                      AND fc.status = 'accepted'
                ) AND EXISTS (
                    SELECT 1 FROM content_visibility cv 
                    WHERE cv.post_id = p.id AND cv.tenant_id = %s
                ))
            )
            ORDER BY p.published_at DESC
            LIMIT %s OFFSET %s
        """, (viewing_tenant_id, viewing_tenant_id, viewing_tenant_id, viewing_tenant_id, 
              viewing_tenant_id, limit, offset))
        return cur.fetchall()

def share_post_with_family(con, post_id: str, target_tenant_id: str, granted_by: str) -> bool:
    """Share a post with a connected family"""
    with con.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO content_visibility (post_id, tenant_id, granted_by)
                VALUES (%s, %s, %s)
                ON CONFLICT (post_id, tenant_id) DO NOTHING
            """, (post_id, target_tenant_id, granted_by))
            return True
        except Exception:
            return False

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
    
    # Debug: log the received request body
    log.info(f"[DEBUG] Received post data: {json.dumps(body, indent=2)}")
    
    # Support both old and new API formats
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    media_id = body.get("media_id")
    
    # New format support
    if not title and content:
        title = content[:50] + ("..." if len(content) > 50 else "")  # Auto-generate title from content
    
    # Handle media from new format
    media = body.get("media")
    media_url = None
    if media and not media_id:
        media_id = media.get("id")
        media_url = media.get("url")
        # If we have a URL but no ID, we'll create the media object in create_content_post
    
    # Also check for direct media_url in body for backward compatibility
    if not media_url and body.get("media_url"):
        media_url = body.get("media_url")
    
    # Debug: log media processing
    log.info(f"[DEBUG] Media processing: media_id={media_id}, media_url={media_url}, media_object={media}")
    
    content_type = body.get("content_type", "video_blog")
    is_public = body.get("is_public", True)
    
    # Map visibility to is_public for new format
    visibility = body.get("visibility", "family")
    if visibility == "public":
        is_public = True
    elif visibility in ["family", "connections"]:
        is_public = False
    else:
        # Default unknown values to family
        visibility = "family"
        is_public = False
    
    # Support "post as" feature - allow posting as another member (e.g., child)
    # Frontend sends author_id when user selects a different member from dropdown
    author_id = body.get("author_id", user["id"])
    log.info(f"[DEBUG] Post author_id from request: {author_id}")
    log.info(f"[DEBUG] Logged-in user ID: {user['id']}")
    log.info(f"[DEBUG] Request body author_id field: {body.get('author_id')}")

    if not title and not content:
        return corsify(jsonify({"ok": False, "error": "content_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            # Get tenant by slug
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                # Verify author_id is a member of the tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (author_id, tenant["id"]))
                author_membership = cur.fetchone()
                if not author_membership:
                    log.warning(f"[DEBUG] author_id {author_id} is not a member of tenant {tenant['id']}")
                    return corsify(jsonify({"ok": False, "error": "author_not_tenant_member"}), origin), 403

            post = create_content_post(con, tenant["id"], author_id, title, content, 
                                     media_id, media_url, content_type, is_public, visibility)
            
            # Enrich post with author details for frontend
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT 
                        u.email as author_email,
                        up.display_name as author_name,
                        up.avatar_url as author_avatar,
                        up.avatar_color
                    FROM users u
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    WHERE u.id = %s
                """, (author_id,))
                author_info = cur.fetchone()
                if author_info:
                    post['author_name'] = author_info.get('author_name') or author_info.get('author_email', 'User')
                    post['author_avatar'] = author_info.get('author_avatar')
                    post['author_avatar_color'] = author_info.get('avatar_color')
            
            audit("post_created", tenant=tenant_slug, post_id=post["id"], title=title)
            return corsify(jsonify({"ok": True, "post": post}), origin)

    except Exception as e:
        log.exception("Failed to create post")
        return corsify(jsonify({"ok": False, "error": "create_failed"}), origin), 500

@app.get("/api/public-feed")
def get_public_feed():
    """Get public posts from all families for the main kinjar.com homepage"""
    origin = request.headers.get("Origin")
    
    limit = min(max(int(request.args.get("limit", "20")), 1), 50)
    offset = int(request.args.get("offset", "0"))

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Get public posts from all families
            cur.execute("""
                SELECT 
                    p.id, p.title, p.content, p.published_at, p.view_count,
                    t.id as family_id, t.slug as family_slug, t.name as family_name,
                    u.email as author_email,
                    up.display_name as author_name,
                    up.avatar_url as author_avatar,
                    up.avatar_color,
                    m.filename as media_filename,
                    m.content_type as media_content_type,
                    m.r2_key as media_r2_key,
                    m.external_url as media_external_url,
                    m.thumbnail_url as media_thumbnail,
                    m.duration_seconds as media_duration,
                    fs.theme_color as family_theme_color
                FROM content_posts p
                JOIN tenants t ON p.tenant_id = t.id
                JOIN users u ON p.author_id = u.id
                LEFT JOIN user_profiles up ON u.id = up.user_id
                LEFT JOIN media_objects m ON p.media_id = m.id
                LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                WHERE p.status = 'published' 
                  AND p.is_public = true
                  AND (fs.is_public = true OR fs.is_public IS NULL)
                ORDER BY p.published_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            
            posts = list(cur.fetchall())

            # Format posts for frontend
            formatted_posts = []
            for post in posts:
                # Create media object if media exists
                media = None
                if post.get("media_filename"):
                    media = {
                        "type": "image" if post["media_content_type"] and "image" in post["media_content_type"] else "video",
                        "url": post["media_external_url"] or f"/media/{post['media_filename']}",
                        "alt": post["title"]
                    }

                formatted_posts.append({
                    "id": post["id"],
                    "familyId": post["family_id"],
                    "familySlug": post["family_slug"],
                    "familyName": post["family_name"],
                    "familyThemeColor": post["family_theme_color"] or "#2563eb",
                    "authorId": None,  # Don't expose user IDs in public feed
                    "authorName": post["author_name"] or post["author_email"].split("@")[0],
                    "authorAvatarColor": post["avatar_color"] or "#3B82F6",
                    "createdAt": post["published_at"].isoformat() if post["published_at"] else None,
                    "content": post["content"],
                    "title": post["title"],
                    "media": media,
                    "visibility": "public",
                    "status": "approved",
                    "reactions": 0,  # TODO: Implement reaction counts
                    "comments": [],  # Don't load comments in feed for performance
                    "tags": []
                })

            return corsify(jsonify({"ok": True, "posts": formatted_posts}), origin)

    except Exception as e:
        log.exception("Failed to get public feed")
        return corsify(jsonify({"ok": False, "error": "feed_failed"}), origin), 500

@app.get("/api/posts")
def list_posts():
    """List posts for a tenant (including cross-family shared content)"""
    origin = request.headers.get("Origin")
    
    tenant_slug = request.args.get("tenant", "")
    include_connected = request.args.get("include_connected", "false").lower() == "true"
    
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

            if include_connected:
                posts = get_cross_family_posts(con, tenant["id"], limit, offset)
            else:
                posts = get_tenant_posts(con, tenant["id"], limit, offset)
            
            # Add signed URLs for media
            try:
                media_s3 = s3_client()
            except StorageNotConfigured as e:
                media_s3 = None
                log.warning("list_posts skipping media URL sign because storage is not configured: %s", e)

            for post in posts:
                if post.get("media_r2_key") and media_s3:
                    try:
                        signed_url = media_s3.generate_presigned_url(
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

@app.post("/api/posts/<post_id>/share")
def share_post(post_id: str):
    """Share a post with connected families"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    target_families = body.get("target_families", [])  # List of family slugs

    if not target_families:
        return corsify(jsonify({"ok": False, "error": "target_families_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Verify post exists and user can share it
                cur.execute("""
                    SELECT p.*, t.slug as family_slug FROM content_posts p
                    JOIN tenants t ON p.tenant_id = t.id
                    WHERE p.id = %s AND p.status = 'published'
                """, (post_id,))
                post = cur.fetchone()
                
                if not post:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                # Check user is member of post's tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], post["tenant_id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "not_post_owner"}), origin), 403

                # Get target tenant IDs and verify connections
                cur.execute("SELECT id, slug FROM tenants WHERE slug = ANY(%s)", (target_families,))
                target_tenants = {row["slug"]: row["id"] for row in cur.fetchall()}
                
                shared_with = []
                failed_shares = []

                for family_slug in target_families:
                    if family_slug not in target_tenants:
                        failed_shares.append({"family": family_slug, "reason": "family_not_found"})
                        continue
                    
                    target_tenant_id = target_tenants[family_slug]
                    
                    # Check if families are connected
                    cur.execute("""
                        SELECT 1 FROM family_connections 
                        WHERE ((requesting_tenant_id = %s AND target_tenant_id = %s)
                               OR (requesting_tenant_id = %s AND target_tenant_id = %s))
                          AND status = 'accepted'
                    """, (post["tenant_id"], target_tenant_id, target_tenant_id, post["tenant_id"]))
                    
                    if not cur.fetchone():
                        failed_shares.append({"family": family_slug, "reason": "not_connected"})
                        continue

                    # Share the post
                    if share_post_with_family(con, post_id, target_tenant_id, user["id"]):
                        shared_with.append(family_slug)
                    else:
                        failed_shares.append({"family": family_slug, "reason": "already_shared"})

            audit("post_shared", post_id=post_id, shared_with=shared_with, 
                  shared_by=user["email"], family=post["family_slug"])
            
            return corsify(jsonify({
                "ok": True,
                "shared_with": shared_with,
                "failed_shares": failed_shares
            }), origin)

    except Exception as e:
        log.exception("Failed to share post")
        return corsify(jsonify({"ok": False, "error": "share_failed"}), origin), 500

@app.get("/api/families/connected")
def list_connected_families():
    """List families connected to current tenant"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
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

            connected_families = get_connected_families(con, tenant["id"])
            return corsify(jsonify({"ok": True, "families": connected_families}), origin)

    except Exception as e:
        log.exception("Failed to list connected families")
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
                    media_s3 = s3_client()
                except StorageNotConfigured as e:
                    media_s3 = None
                    log.warning("get_post skipping media URL sign because storage is not configured: %s", e)

                if media_s3:
                    try:
                        signed_url = media_s3.generate_presigned_url(
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

@app.delete("/api/posts/<post_id>")
def delete_post(post_id: str):
    """Delete a post and associated media/comments."""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    media_record = None

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                        SELECT p.id, p.tenant_id, p.author_id, p.media_id, t.slug AS tenant_slug
                        FROM content_posts p
                        JOIN tenants t ON p.tenant_id = t.id
                        WHERE p.id = %s
                    """,
                    (post_id,),
                )
                post = cur.fetchone()
                if not post or post["tenant_slug"] != tenant_slug:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                is_author = post["author_id"] == user["id"]
                if not is_author:
                    cur.execute(
                        """
                            SELECT role FROM tenant_users
                            WHERE user_id = %s AND tenant_id = %s
                        """,
                        (user["id"], post["tenant_id"]),
                    )
                    membership = cur.fetchone()
                    if not membership or membership["role"] not in {"ADMIN", "OWNER", "ADULT"}:
                        return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                cur.execute(
                    "DELETE FROM content_posts WHERE id = %s RETURNING media_id",
                    (post_id,),
                )
                deleted = cur.fetchone()
                if not deleted:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                media_id = deleted.get("media_id") if isinstance(deleted, dict) else deleted[0]
                if media_id:
                    cur.execute(
                        """
                            UPDATE media_objects
                            SET status = 'deleted', deleted_at = now(), updated_at = now()
                            WHERE id = %s
                            RETURNING r2_key
                        """,
                        (media_id,),
                    )
                    media_record = cur.fetchone()

        media_key = None
        if media_record:
            media_key = media_record.get("r2_key") if isinstance(media_record, dict) else media_record[0]
        if media_key:
            try:
                s3 = s3_client()
                s3.delete_object(Bucket=S3_BUCKET, Key=media_key)
            except StorageNotConfigured as e:
                log.warning("post_delete skipping storage cleanup: %s", e)
            except Exception:
                log.exception("Failed to delete media object %s for post %s", media_key, post_id)

        audit("post_deleted", tenant=tenant_slug, post_id=post_id, deleted_by=user["email"])
        resp = make_response("", 204)
        return corsify(resp, origin)

    except Exception:
        log.exception("Failed to delete post")
        return corsify(jsonify({"ok": False, "error": "delete_failed"}), origin), 500


@app.patch("/api/posts/<post_id>")
def edit_post(post_id: str):
    """Edit a post's content."""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    # Get request data
    data = request.get_json() or {}
    content = data.get("content", "").strip()
    if not content:
        return corsify(jsonify({"ok": False, "error": "content_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Check if post exists and user has permission
                cur.execute(
                    """
                        SELECT p.id, p.tenant_id, p.author_id, p.content, t.slug AS tenant_slug
                        FROM content_posts p
                        JOIN tenants t ON p.tenant_id = t.id
                        WHERE p.id = %s
                    """,
                    (post_id,),
                )
                post = cur.fetchone()

                if not post or post["tenant_slug"] != tenant_slug:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

                # Check if user is the author or has admin permissions
                user_is_author = post["author_id"] == user["id"]
                if not user_is_author:
                    # Check if user has admin permissions for this tenant
                    cur.execute(
                        """
                            SELECT role FROM tenant_users
                            WHERE tenant_id = %s AND user_id = %s
                        """,
                        (post["tenant_id"], user["id"]),
                    )
                    membership = cur.fetchone()
                    if not membership or membership["role"] not in {"ADMIN", "OWNER"}:
                        return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Update the post content
                cur.execute(
                    """
                        UPDATE content_posts
                        SET content = %s, updated_at = now()
                        WHERE id = %s
                        RETURNING *
                    """,
                    (content, post_id),
                )
                updated_post = cur.fetchone()
                con.commit()

                if not updated_post:
                    return corsify(jsonify({"ok": False, "error": "update_failed"}), origin), 500

                # Get additional post details for response
                cur.execute(
                    """
                        SELECT 
                            p.*,
                            u.email as author_email,
                            up.display_name AS author_name,
                            up.avatar_url AS author_avatar,
                            t.name AS tenant_name,
                            t.slug AS tenant_slug
                        FROM content_posts p
                        JOIN users u ON p.author_id = u.id
                        LEFT JOIN user_profiles up ON u.id = up.user_id
                        JOIN tenants t ON p.tenant_id = t.id
                        WHERE p.id = %s
                    """,
                    (post_id,),
                )
                full_post = cur.fetchone()

                if not full_post:
                    # This shouldn't happen but let's handle it gracefully
                    log.error(f"Post {post_id} not found after successful update")
                    return corsify(jsonify({"ok": False, "error": "post_not_found_after_update"}), origin), 500

                # Convert to dict and ensure all values are JSON serializable
                post_dict = dict(full_post)
                
                # Convert datetime objects to ISO strings
                for key, value in post_dict.items():
                    if hasattr(value, 'isoformat'):
                        post_dict[key] = value.isoformat()

                return corsify(jsonify({"ok": True, "post": post_dict}), origin)

    except Exception as e:
        log.exception(f"Failed to edit post {post_id}: {str(e)}")
        # Updated error handling for better post edit reliability
        return corsify(jsonify({"ok": False, "error": "edit_failed", "details": str(e)}), origin), 500


@app.get("/api/posts/<post_id>/comments")
def get_post_comments_endpoint(post_id: str):
    """Get comments for a post"""
    origin = request.headers.get("Origin")
    
    try:
        with_db()
        with pool.connection() as con:
            # Verify post exists
            with con.cursor(row_factory=dict_row) as cur:
                cur.execute("""
                    SELECT p.id FROM content_posts p
                    WHERE p.id = %s AND p.status = 'published'
                """, (post_id,))
                post = cur.fetchone()
                if not post:
                    return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

            # Get comments
            comments = get_post_comments(con, post_id)
            return corsify(jsonify({"ok": True, "comments": comments}), origin)

    except Exception as e:
        log.exception("Failed to get comments")
        return corsify(jsonify({"ok": False, "error": "get_comments_failed"}), origin), 500

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

# ---------------- Post Approval System ----------------

@app.get("/api/posts/pending")
def get_pending_posts():
    """Get posts pending approval (admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)

    tenant_slug = request.headers.get("x-tenant-slug", "")
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "missing_tenant"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Get tenant
            cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
            tenant = cur.fetchone()
            if not tenant:
                return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

            # Check if user is admin
            cur.execute("""
                SELECT role FROM tenant_users 
                WHERE user_id = %s AND tenant_id = %s
            """, (user["id"], tenant["id"]))
            membership = cur.fetchone()
            
            if not membership or membership["role"] not in ["OWNER", "ADMIN"]:
                return corsify(jsonify({"ok": False, "error": "permission_denied"}), origin), 403

            # Get pending posts
            cur.execute("""
                SELECT p.id, p.title, p.content, p.is_public, p.created_at, p.author_id,
                       u.email as author_email,
                       up.display_name as author_name,
                       up.avatar_color,
                       tu.role as author_role
                FROM content_posts p
                JOIN users u ON p.author_id = u.id
                LEFT JOIN user_profiles up ON u.id = up.user_id
                LEFT JOIN tenant_users tu ON u.id = tu.user_id AND tu.tenant_id = p.tenant_id
                WHERE p.tenant_id = %s AND p.status = 'pending_approval'
                ORDER BY p.created_at ASC
            """, (tenant["id"],))
            
            posts = list(cur.fetchall())
            
            # Format response
            formatted_posts = []
            for post in posts:
                formatted_posts.append({
                    "id": post["id"],
                    "familyId": tenant["id"],
                    "authorId": post["author_id"] if "author_id" in post else "",
                    "authorName": post["author_name"] or post["author_email"].split("@")[0],
                    "authorAvatarColor": post["avatar_color"] or "#3B82F6",
                    "title": post["title"],
                    "content": post["content"],
                    "createdAt": post["created_at"].isoformat() if post["created_at"] else None,
                    "visibility": "public" if post["is_public"] else "family",
                    "status": "pending_approval",
                    "reactions": 0,
                    "comments": [],
                    "tags": [],
                    "media": None
                })

            return corsify(jsonify({"ok": True, "posts": formatted_posts}), origin)

    except Exception as e:
        log.exception("Failed to get pending posts")
        return corsify(jsonify({"ok": False, "error": "fetch_failed"}), origin), 500

@app.patch("/api/posts/<post_id>/approve")
def approve_post(post_id: str):
    """Approve or reject a pending post"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    action = data.get("action", "approve")  # approve or reject
    reason = data.get("reason", "")

    if action not in ["approve", "reject"]:
        return corsify(jsonify({"ok": False, "error": "invalid_action"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Get post and verify permissions
            cur.execute("""
                SELECT p.*, t.slug as tenant_slug
                FROM content_posts p
                JOIN tenants t ON p.tenant_id = t.id
                WHERE p.id = %s AND p.status = 'pending_approval'
            """, (post_id,))
            post = cur.fetchone()
            
            if not post:
                return corsify(jsonify({"ok": False, "error": "post_not_found"}), origin), 404

            # Check if user is admin of this family
            cur.execute("""
                SELECT role FROM tenant_users 
                WHERE user_id = %s AND tenant_id = %s
            """, (user["id"], post["tenant_id"]))
            membership = cur.fetchone()
            
            if not membership or membership["role"] not in ["OWNER", "ADMIN"]:
                return corsify(jsonify({"ok": False, "error": "permission_denied"}), origin), 403

            # Update post status
            new_status = "published" if action == "approve" else "rejected"
            cur.execute("""
                UPDATE content_posts 
                SET status = %s, published_at = %s
                WHERE id = %s
            """, (new_status, datetime.datetime.now(datetime.timezone.utc) if action == "approve" else None, post_id))

            # Add to activity feed
            cur.execute("""
                INSERT INTO activity_feed (id, tenant_id, user_id, action_type, entity_type, entity_id, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid4()), post["tenant_id"], user["id"], f"post_{action}d", "content_post", post_id, 
                  json.dumps({"reason": reason, "moderator": user["email"]})))

            con.commit()

            audit(f"post_{action}d", 
                  post_id=post_id, 
                  tenant=post["tenant_slug"],
                  moderator=user["email"],
                  reason=reason)

            return corsify(jsonify({
                "ok": True, 
                "message": f"Post {action}d successfully",
                "newStatus": new_status
            }), origin)

    except Exception as e:
        log.exception(f"Failed to {action} post")
        return corsify(jsonify({"ok": False, "error": f"{action}_failed"}), origin), 500

# ---------------- Family Connection Endpoints ----------------

@app.post("/api/families/connect")
def request_family_connection():
    """Request to connect with another family"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    target_family_slug = body.get("target_family", "").strip()
    request_message = body.get("message", "").strip()

    if not target_family_slug:
        return corsify(jsonify({"ok": False, "error": "target_family_required"}), origin), 400

    # Get requesting tenant from user's current context
    requesting_tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not requesting_tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get both tenant IDs
                cur.execute("SELECT id, slug, name FROM tenants WHERE slug IN (%s, %s)", 
                          (requesting_tenant_slug, target_family_slug))
                tenants = {row["slug"]: row for row in cur.fetchall()}
                
                if requesting_tenant_slug not in tenants:
                    return corsify(jsonify({"ok": False, "error": "requesting_family_not_found"}), origin), 404
                if target_family_slug not in tenants:
                    return corsify(jsonify({"ok": False, "error": "target_family_not_found"}), origin), 404

                requesting_tenant = tenants[requesting_tenant_slug]
                target_tenant = tenants[target_family_slug]

                # Check user is admin/owner of requesting tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER')
                """, (user["id"], requesting_tenant["id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Check if connection already exists
                cur.execute("""
                    SELECT * FROM family_connections 
                    WHERE (requesting_tenant_id = %s AND target_tenant_id = %s)
                       OR (requesting_tenant_id = %s AND target_tenant_id = %s)
                """, (requesting_tenant["id"], target_tenant["id"], target_tenant["id"], requesting_tenant["id"]))
                existing = cur.fetchone()
                
                if existing:
                    return corsify(jsonify({"ok": False, "error": "connection_already_exists", 
                                          "status": existing["status"]}), origin), 409

                # Check target family allows connections
                cur.execute("SELECT allow_connections FROM family_settings WHERE tenant_id = %s", 
                          (target_tenant["id"],))
                settings = cur.fetchone()
                if settings and not settings["allow_connections"]:
                    return corsify(jsonify({"ok": False, "error": "family_not_accepting_connections"}), origin), 403

                # Create connection request
                connection_id = str(uuid4())
                cur.execute("""
                    INSERT INTO family_connections 
                    (id, requesting_tenant_id, target_tenant_id, requested_by, request_message)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING *
                """, (connection_id, requesting_tenant["id"], target_tenant["id"], 
                     user["id"], request_message))
                connection = cur.fetchone()

            audit("family_connection_requested", 
                  requesting_family=requesting_tenant_slug, 
                  target_family=target_family_slug,
                  requested_by=user["email"])
            
            return corsify(jsonify({
                "ok": True, 
                "connection": dict(connection),
                "requesting_family": dict(requesting_tenant),
                "target_family": dict(target_tenant)
            }), origin)

    except Exception as e:
        log.exception("Failed to request family connection")
        return corsify(jsonify({"ok": False, "error": "connection_request_failed"}), origin), 500

@app.get("/api/families/connections")
def list_family_connections():
    """List family connections for current tenant"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
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

                # Get all connections (incoming and outgoing)
                cur.execute("""
                    SELECT 
                        fc.*,
                        CASE 
                            WHEN fc.requesting_tenant_id = %s THEN 'outgoing'
                            ELSE 'incoming'
                        END as direction,
                        CASE 
                            WHEN fc.requesting_tenant_id = %s THEN target_t.slug
                            ELSE requesting_t.slug
                        END as other_family_slug,
                        CASE 
                            WHEN fc.requesting_tenant_id = %s THEN target_t.name
                            ELSE requesting_t.name
                        END as other_family_name,
                        requester.email as requester_email,
                        requester_profile.display_name as requester_name,
                        responder.email as responder_email,
                        responder_profile.display_name as responder_name
                    FROM family_connections fc
                    JOIN tenants requesting_t ON fc.requesting_tenant_id = requesting_t.id
                    JOIN tenants target_t ON fc.target_tenant_id = target_t.id
                    JOIN users requester ON fc.requested_by = requester.id
                    LEFT JOIN users responder ON fc.responded_by = responder.id
                    LEFT JOIN user_profiles requester_profile ON requester.id = requester_profile.user_id
                    LEFT JOIN user_profiles responder_profile ON responder.id = responder_profile.user_id
                    WHERE fc.requesting_tenant_id = %s OR fc.target_tenant_id = %s
                    ORDER BY fc.created_at DESC
                """, (tenant["id"], tenant["id"], tenant["id"], tenant["id"], tenant["id"], tenant["id"]))
                
                connections = [dict(row) for row in cur.fetchall()]

            return corsify(jsonify({"ok": True, "connections": connections}), origin)

    except Exception as e:
        log.exception("Failed to list family connections")
        return corsify(jsonify({"ok": False, "error": "list_connections_failed"}), origin), 500

@app.post("/api/families/connections/<connection_id>/respond")
def respond_to_family_connection(connection_id: str):
    """Accept or decline a family connection request"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    body = request.get_json(silent=True) or {}
    action = body.get("action", "").strip()  # 'accept' or 'decline'
    response_message = body.get("message", "").strip()

    if action not in ["accept", "decline"]:
        return corsify(jsonify({"ok": False, "error": "invalid_action"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get connection request
                cur.execute("""
                    SELECT fc.*, requesting_t.slug as requesting_family, target_t.slug as target_family
                    FROM family_connections fc
                    JOIN tenants requesting_t ON fc.requesting_tenant_id = requesting_t.id
                    JOIN tenants target_t ON fc.target_tenant_id = target_t.id
                    WHERE fc.id = %s AND fc.status = 'pending'
                """, (connection_id,))
                connection = cur.fetchone()
                
                if not connection:
                    return corsify(jsonify({"ok": False, "error": "connection_not_found"}), origin), 404

                # Check user is admin/owner of target tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER')
                """, (user["id"], connection["target_tenant_id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Update connection status
                new_status = "accepted" if action == "accept" else "declined"
                cur.execute("""
                    UPDATE family_connections 
                    SET status = %s, responded_by = %s, responded_at = now(), response_message = %s
                    WHERE id = %s
                    RETURNING *
                """, (new_status, user["id"], response_message, connection_id))
                updated_connection = cur.fetchone()

            audit("family_connection_responded", 
                  connection_id=connection_id,
                  action=action,
                  requesting_family=connection["requesting_family"],
                  target_family=connection["target_family"],
                  responded_by=user["email"])
            
            return corsify(jsonify({"ok": True, "connection": dict(updated_connection)}), origin)

    except Exception as e:
        log.exception("Failed to respond to family connection")
        return corsify(jsonify({"ok": False, "error": "response_failed"}), origin), 500

@app.get("/api/families/settings")
def get_family_settings():
    """Get family settings for current tenant"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id, name FROM tenants WHERE slug = %s", (tenant_slug,))
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

                # Get family settings
                cur.execute("SELECT * FROM family_settings WHERE tenant_id = %s", (tenant["id"],))
                settings = cur.fetchone()
                
                if not settings:
                    # Create default settings
                    cur.execute("""
                        INSERT INTO family_settings (tenant_id) VALUES (%s) RETURNING *
                    """, (tenant["id"],))
                    settings = cur.fetchone()

            return corsify(jsonify({
                "ok": True, 
                "settings": dict(settings),
                "family": {"id": tenant["id"], "name": tenant["name"], "slug": tenant_slug}
            }), origin)

    except Exception as e:
        log.exception("Failed to get family settings")
        return corsify(jsonify({"ok": False, "error": "settings_failed"}), origin), 500

@app.put("/api/families/settings")
def update_family_settings():
    """Update family settings (admin/owner only)"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    body = request.get_json(silent=True) or {}

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                # Check user is admin/owner of tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER')
                """, (user["id"], tenant["id"]))
                membership = cur.fetchone()
                if not membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Update settings (only provided fields)
                update_fields = []
                update_values = []
                
                if "family_photo" in body:
                    update_fields.append("family_photo = %s")
                    update_values.append(body["family_photo"])
                if "theme_color" in body:
                    update_fields.append("theme_color = %s")
                    update_values.append(body["theme_color"])
                if "banner_image" in body:
                    update_fields.append("banner_image = %s")
                    update_values.append(body["banner_image"])
                if "description" in body:
                    update_fields.append("description = %s")
                    update_values.append(body["description"])
                if "is_public" in body:
                    update_fields.append("is_public = %s")
                    update_values.append(body["is_public"])
                if "allow_connections" in body:
                    update_fields.append("allow_connections = %s")
                    update_values.append(body["allow_connections"])

                if not update_fields:
                    return corsify(jsonify({"ok": False, "error": "no_fields_to_update"}), origin), 400

                update_fields.append("updated_at = now()")
                update_fields.append("updated_by = %s")
                update_values.extend([user["id"], tenant["id"]])

                # Upsert settings
                cur.execute(f"""
                    INSERT INTO family_settings (tenant_id, updated_by) VALUES (%s, %s)
                    ON CONFLICT (tenant_id) DO UPDATE SET {', '.join(update_fields)}
                    RETURNING *
                """, [tenant["id"], user["id"]] + update_values)
                
                settings = cur.fetchone()

            audit("family_settings_updated", tenant=tenant_slug, updated_by=user["email"])
            return corsify(jsonify({"ok": True, "settings": dict(settings)}), origin)

    except Exception as e:
        log.exception("Failed to update family settings")
        return corsify(jsonify({"ok": False, "error": "update_failed"}), origin), 500

@app.get("/api/families/members")
def list_family_members():
    """List family members with roles and profiles"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id, name FROM tenants WHERE slug = %s", (tenant_slug,))
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

                # Get all family members with profiles
                cur.execute("""
                    SELECT 
                        u.id, u.email, u.created_at,
                        tu.role,
                        up.display_name, up.avatar_url, up.bio, up.phone
                    FROM tenant_users tu
                    JOIN users u ON tu.user_id = u.id
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    WHERE tu.tenant_id = %s
                    ORDER BY 
                        CASE tu.role 
                            WHEN 'OWNER' THEN 1 
                            WHEN 'ADMIN' THEN 2 
                            WHEN 'MEMBER' THEN 3 
                            ELSE 4 
                        END,
                        up.display_name, u.email
                """, (tenant["id"],))
                
                members = [dict(row) for row in cur.fetchall()]

            return corsify(jsonify({
                "ok": True, 
                "members": members,
                "family": {"id": tenant["id"], "name": tenant["name"], "slug": tenant_slug}
            }), origin)

    except Exception as e:
        log.exception("Failed to list family members")
        return corsify(jsonify({"ok": False, "error": "list_members_failed"}), origin), 500

@app.put("/api/families/members/<member_id>/role")
def update_member_role_legacy(member_id: str):
    """Update a family member's role (admin/owner only) - Legacy endpoint"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    body = request.get_json(silent=True) or {}
    new_role = body.get("role", "").strip()

    if new_role not in TENANT_ROLES:
        return corsify(jsonify({"ok": False, "error": "invalid_role"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                # Check requesting user is admin/owner of tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER')
                """, (user["id"], tenant["id"]))
                requester_membership = cur.fetchone()
                if not requester_membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Get target member info
                cur.execute("""
                    SELECT tu.role, u.email FROM tenant_users tu
                    JOIN users u ON tu.user_id = u.id
                    WHERE tu.user_id = %s AND tu.tenant_id = %s
                """, (member_id, tenant["id"]))
                target_member = cur.fetchone()
                
                if not target_member:
                    return corsify(jsonify({"ok": False, "error": "member_not_found"}), origin), 404

                # Prevent non-owners from changing owner roles
                if (target_member["role"] == "OWNER" or new_role == "OWNER") and requester_membership["role"] != "OWNER":
                    return corsify(jsonify({"ok": False, "error": "cannot_modify_owner"}), origin), 403

                # Update role
                cur.execute("""
                    UPDATE tenant_users SET role = %s 
                    WHERE user_id = %s AND tenant_id = %s
                    RETURNING role
                """, (new_role, member_id, tenant["id"]))
                
                updated_role = cur.fetchone()

            audit("member_role_updated", 
                  tenant=tenant_slug, 
                  member_email=target_member["email"],
                  old_role=target_member["role"],
                  new_role=new_role,
                  updated_by=user["email"])
            
            return corsify(jsonify({
                "ok": True, 
                "member_id": member_id,
                "new_role": updated_role["role"]
            }), origin)

    except Exception as e:
        log.exception("Failed to update member role")
        return corsify(jsonify({"ok": False, "error": "update_role_failed"}), origin), 500

@app.delete("/api/families/members/<member_id>")
def remove_family_member_by_slug(member_id: str):
    """Remove a member from the family (admin/owner only)"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (tenant_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "tenant_not_found"}), origin), 404

                # Check requesting user is admin/owner of tenant
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s AND role IN ('ADMIN', 'OWNER', 'ADULT')
                """, (user["id"], tenant["id"]))
                requester_membership = cur.fetchone()
                if not requester_membership:
                    return corsify(jsonify({"ok": False, "error": "insufficient_permissions"}), origin), 403

                # Get target member info
                cur.execute("""
                    SELECT tu.role, u.email FROM tenant_users tu
                    JOIN users u ON tu.user_id = u.id
                    WHERE tu.user_id = %s AND tu.tenant_id = %s
                """, (member_id, tenant["id"]))
                target_member = cur.fetchone()
                
                if not target_member:
                    return corsify(jsonify({"ok": False, "error": "member_not_found"}), origin), 404

                # Prevent non-owners from removing owners
                if target_member["role"] == "OWNER" and requester_membership["role"] != "OWNER":
                    return corsify(jsonify({"ok": False, "error": "cannot_remove_owner"}), origin), 403

                # Prevent removing yourself if you're the only owner
                if member_id == user["id"] and target_member["role"] == "OWNER":
                    cur.execute("""
                        SELECT COUNT(*) as owner_count FROM tenant_users 
                        WHERE tenant_id = %s AND role = 'OWNER'
                    """, (tenant["id"],))
                    owner_count = cur.fetchone()["owner_count"]
                    
                    if owner_count <= 1:
                        return corsify(jsonify({"ok": False, "error": "cannot_remove_last_owner"}), origin), 403

                # Remove member
                cur.execute("""
                    DELETE FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (member_id, tenant["id"]))

            audit("member_removed", 
                  tenant=tenant_slug, 
                  member_email=target_member["email"],
                  member_role=target_member["role"],
                  removed_by=user["email"])
            
            return corsify(jsonify({"ok": True, "removed_member_id": member_id}), origin)

    except Exception as e:
        log.exception("Failed to remove family member")
        return corsify(jsonify({"ok": False, "error": "remove_member_failed"}), origin), 500

@app.get("/api/families/stats")
def get_family_stats():
    """Get family statistics and activity overview"""
    origin = request.headers.get("Origin")
    user = current_user_row()
    if not user:
        return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    tenant_slug = request.headers.get("x-tenant-slug", "").strip()
    if not tenant_slug:
        return corsify(jsonify({"ok": False, "error": "tenant_required"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id, name, created_at FROM tenants WHERE slug = %s", (tenant_slug,))
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

                # Get various statistics
                stats = {}
                
                # Member count by role
                cur.execute("""
                    SELECT role, COUNT(*) as count FROM tenant_users 
                    WHERE tenant_id = %s GROUP BY role
                """, (tenant["id"],))
                stats["members_by_role"] = {row["role"]: row["count"] for row in cur.fetchall()}
                
                # Total member count
                stats["total_members"] = sum(stats["members_by_role"].values())
                
                # Post statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_posts,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as posts_last_30_days,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as posts_last_7_days,
                        SUM(view_count) as total_views
                    FROM content_posts 
                    WHERE tenant_id = %s AND status = 'published'
                """, (tenant["id"],))
                post_stats = cur.fetchone()
                stats.update(dict(post_stats))
                
                # Media statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_media,
                        SUM(size_bytes) as total_storage_bytes,
                        COUNT(*) FILTER (WHERE content_type LIKE 'image/%') as image_count,
                        COUNT(*) FILTER (WHERE content_type LIKE 'video/%') as video_count
                    FROM media_objects 
                    WHERE tenant = %s AND status = 'uploaded'
                """, (tenant_slug,))
                media_stats = cur.fetchone()
                stats.update(dict(media_stats))
                
                # Connected families count
                cur.execute("""
                    SELECT COUNT(*) as connected_families FROM family_connections 
                    WHERE (requesting_tenant_id = %s OR target_tenant_id = %s) 
                      AND status = 'accepted'
                """, (tenant["id"], tenant["id"]))
                connection_stats = cur.fetchone()
                stats.update(dict(connection_stats))
                
                # Recent activity (last 30 days)
                cur.execute("""
                    SELECT 
                        action_type,
                        COUNT(*) as count,
                        MAX(created_at) as last_occurrence
                    FROM activity_feed 
                    WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
                    GROUP BY action_type
                    ORDER BY count DESC
                """, (tenant["id"],))
                recent_activity = [dict(row) for row in cur.fetchall()]
                stats["recent_activity"] = recent_activity

            return corsify(jsonify({
                "ok": True, 
                "stats": stats,
                "family": {
                    "id": tenant["id"], 
                    "name": tenant["name"], 
                    "slug": tenant_slug,
                    "created_at": tenant["created_at"].isoformat() if tenant["created_at"] else None
                }
            }), origin)

    except Exception as e:
        log.exception("Failed to get family stats")
        return corsify(jsonify({"ok": False, "error": "stats_failed"}), origin), 500

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

@app.get("/api/families/<family_slug>")
def get_family_info(family_slug: str):
    """Get detailed family information including members"""
    origin = request.headers.get("Origin")
    
    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get family basic info
                cur.execute("""
                    SELECT t.id, t.slug, t.name, t.created_at,
                           fs.family_photo, fs.description, fs.theme_color, fs.is_public
                    FROM tenants t
                    LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                    WHERE t.slug = %s
                """, (family_slug,))
                family = cur.fetchone()
                
                if not family:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                tenant_id = family["id"]

                # Fetch full member details
                cur.execute("""
                    SELECT 
                        u.id AS user_id,
                        u.email,
                        tu.role,
                        up.display_name,
                        up.avatar_url,
                        up.avatar_color,
                        up.birthdate,
                        up.bio,
                        up.phone
                    FROM tenant_users tu
                    JOIN users u ON tu.user_id = u.id
                    LEFT JOIN user_profiles up ON up.user_id = u.id
                    WHERE tu.tenant_id = %s
                    ORDER BY 
                        CASE tu.role 
                            WHEN 'OWNER' THEN 0
                            WHEN 'ADMIN' THEN 1
                            WHEN 'ADULT' THEN 2
                            WHEN 'CHILD_16_ADULT' THEN 3
                            WHEN 'CHILD_14_16' THEN 4
                            WHEN 'CHILD_10_14' THEN 5
                            WHEN 'CHILD_5_10' THEN 6
                            WHEN 'CHILD_0_5' THEN 7
                            ELSE 8
                        END,
                        COALESCE(up.display_name, u.email)
                """, (tenant_id,))

                member_rows = cur.fetchall()

                members: List[Dict[str, Any]] = []
                owner_id = None
                admin_ids: List[str] = []

                for row in member_rows:
                    user_id = str(row["user_id"])
                    display_name = row.get("display_name") or (row.get("email") or "").split("@")[0]
                    email = row.get("email")
                    # Hide internal placeholder emails for child accounts
                    if email and email.endswith("@kinjar.internal"):
                        email = ""

                    birthdate_val = row.get("birthdate")
                    birthdate_iso = birthdate_val.isoformat() if birthdate_val else None
                    age = calculate_age(birthdate_val) if birthdate_val else None

                    role = row.get("role") or "MEMBER"
                    if role == "OWNER" and not owner_id:
                        owner_id = user_id
                    if role in ("OWNER", "ADMIN"):
                        admin_ids.append(user_id)

                    members.append({
                        "id": user_id,
                        "userId": user_id,
                        "name": display_name,
                        "email": email,
                        "role": role,
                        "avatarColor": row.get("avatar_color") or "#3B82F6",
                        "avatarUrl": row.get("avatar_url"),
                        "birthdate": birthdate_iso,
                        "age": age,
                        "bio": row.get("bio"),
                        "phone": row.get("phone"),
                        "permissions": get_role_permissions(role),
                        "joinedAt": None,
                        "quote": None,
                        "avatarSeed": user_id,
                    })

                member_count = len(members)

                family_data: Dict[str, Any] = {
                    "id": str(tenant_id),
                    "slug": family["slug"],
                    "name": family["name"],
                    "description": family.get("description") or "",
                    "missionStatement": "",
                    "bannerImage": family.get("family_photo"),
                    "heroImage": family.get("family_photo"),
                    "themeColor": family.get("theme_color") or "#3B82F6",
                    "admins": admin_ids,
                    "members": members,
                    "posts": [],
                    "connections": [],
                    "connectedFamilies": [],
                    "storageUsedMb": 0,
                    "invitesSentThisMonth": 0,
                    "pendingMembers": [],
                    "highlights": [],
                    "isPublic": bool(family.get("is_public")),
                    "subdomain": family.get("slug"),
                    "createdAt": family.get("created_at").isoformat() if family.get("created_at") else None,
                    "ownerId": owner_id,
                    "memberCount": member_count,
                }

                # Provide legacy snake_case key for compatibility with older clients
                family_data["member_count"] = member_count

                return corsify(jsonify({"ok": True, "family": family_data}), origin)

    except Exception as e:
        log.exception("Failed to get family info")
        return corsify(jsonify({"ok": False, "error": "fetch_failed"}), origin), 500

@app.get("/api/families/<family_slug>/posts")
def get_family_posts(family_slug: str):
    """Get posts for a specific family"""
    origin = request.headers.get("Origin")
    
    limit = min(max(int(request.args.get("limit", "20")), 1), 100)
    offset = max(int(request.args.get("offset", "0")), 0)
    
    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Get tenant ID
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (family_slug,))
                tenant = cur.fetchone()
                if not tenant:
                    return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404

                # Get posts for this family
                log.info(f"Getting posts for tenant_id: {tenant['id']}")
                posts = get_tenant_posts(con, tenant["id"], limit, offset)
                log.info(f"Retrieved {len(posts)} posts")
                
                # Add signed URLs for media if storage is configured
                try:
                    media_s3 = s3_client()
                except StorageNotConfigured:
                    media_s3 = None
                    log.warning("Skipping media URL sign because storage is not configured")

                for post in posts:
                    # Handle external URLs (e.g., Vercel Blob) first
                    if post.get("media_external_url"):
                        post["media_url"] = post["media_external_url"]
                    elif post.get("media_r2_key") and media_s3:
                        # For R2 storage, generate signed URLs
                        try:
                            # Use the correct bucket variable
                            bucket = os.getenv("R2_BUCKET", "kinjar-media")
                            signed_url = media_s3.generate_presigned_url(
                                ClientMethod="get_object",
                                Params={"Bucket": bucket, "Key": post["media_r2_key"]},
                                ExpiresIn=3600,
                            )
                            post["media_url"] = signed_url
                        except Exception:
                            log.exception(f"Failed to generate signed URL for {post['media_r2_key']}")

                return corsify(jsonify({"ok": True, "posts": posts}), origin)

    except Exception as e:
        log.exception(f"Failed to get family posts for {family_slug}: {str(e)}")
        return corsify(jsonify({"ok": False, "error": "fetch_failed", "details": str(e)}), origin), 500

# ---------------- New Family Authentication & Management Routes ----------------

@app.post("/families/create")
def create_family():
    """Create a new family with subdomain and admin user"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    family_name = data.get("familyName", "").strip()
    subdomain = data.get("subdomain", "").strip().lower()
    description = data.get("description", "").strip()
    admin_name = data.get("adminName", "").strip()
    admin_email = data.get("adminEmail", "").strip().lower()
    password = data.get("password", "")
    is_public = data.get("isPublic", False)

    # Validation
    if not all([family_name, subdomain, admin_name, admin_email, password]):
        return corsify(jsonify({"ok": False, "error": "Missing required fields"}), origin), 400
    
    if len(password) < 8:
        return corsify(jsonify({"ok": False, "error": "Password must be at least 8 characters"}), origin), 400
    
    if not re.match(r'^[a-z0-9-]+$', subdomain) or len(subdomain) < 3 or len(subdomain) > 20:
        return corsify(jsonify({"ok": False, "error": "Invalid subdomain format"}), origin), 400

    try:
        with_db()
        with pool.connection() as con:
            with con.cursor(row_factory=dict_row) as cur:
                # Check if subdomain/email already exists
                cur.execute("SELECT id FROM tenants WHERE slug = %s", (subdomain,))
                if cur.fetchone():
                    return corsify(jsonify({"ok": False, "error": "Subdomain already taken"}), origin), 400
                
                cur.execute("SELECT id FROM users WHERE email = %s", (admin_email,))
                if cur.fetchone():
                    return corsify(jsonify({"ok": False, "error": "Email already registered"}), origin), 400
                
                # Create user
                user_id = str(uuid4())
                password_hash = ph.hash(password)
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, %s, %s, 'USER') RETURNING *
                """, (user_id, admin_email, password_hash))
                user = cur.fetchone()
                
                # Create user profile
                cur.execute("""
                    INSERT INTO user_profiles (user_id, display_name)
                    VALUES (%s, %s)
                """, (user_id, admin_name))
                
                # Create family (tenant)
                family_id = str(uuid4())
                cur.execute("""
                    INSERT INTO tenants (id, slug, name)
                    VALUES (%s, %s, %s) RETURNING *
                """, (family_id, subdomain, family_name))
                family = cur.fetchone()
                
                # Add user as family admin
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'ADMIN')
                """, (user_id, family_id))
                
                # Create family settings
                cur.execute("""
                    INSERT INTO family_settings (tenant_id, description, is_public, updated_by)
                    VALUES (%s, %s, %s, %s)
                """, (family_id, description, is_public, user_id))

        # Generate JWT token
        now = int(datetime.datetime.utcnow().timestamp())
        token = sign_jwt({"uid": user_id, "iat": now, "exp": now + JWT_TTL_MIN * 60})
        
        # Prepare response data
        user_data = {
            "id": user_id,
            "name": admin_name,
            "email": admin_email,
            "globalRole": "FAMILY_ADMIN",
            "memberships": [{
                "familyId": family_id,
                "familySlug": subdomain,
                "familyName": family_name,
                "role": "ADMIN",
                "joinedAt": datetime.datetime.utcnow().isoformat()
            }],
            "createdAt": datetime.datetime.utcnow().isoformat()
        }
        
        family_data = {
            "id": family_id,
            "slug": subdomain,
            "name": family_name,
            "description": description,
            "isPublic": is_public,
            "subdomain": subdomain,
            "ownerId": user_id,
            "createdAt": datetime.datetime.utcnow().isoformat()
        }

        audit("family_created", family_id=family_id, family_slug=subdomain, admin_email=admin_email)
        
        resp = make_response(jsonify({
            "ok": True,
            "token": token,
            "user": user_data,
            "family": family_data
        }))
        set_session_cookie(resp, token)
        return corsify(resp, origin)

    except Exception as e:
        log.exception("Failed to create family")
        return corsify(jsonify({"ok": False, "error": "creation_failed"}), origin), 500

@app.get("/families/check-subdomain/<subdomain>")
def check_subdomain_availability(subdomain: str):
    """Check if a subdomain is available"""
    origin = request.headers.get("Origin")
    
    subdomain = subdomain.strip().lower()
    if not re.match(r'^[a-z0-9-]+$', subdomain) or len(subdomain) < 3 or len(subdomain) > 20:
        return corsify(jsonify({"ok": False, "available": False, "error": "Invalid subdomain format"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor() as cur:
            cur.execute("SELECT id FROM tenants WHERE slug = %s", (subdomain,))
            exists = cur.fetchone() is not None
            
        return corsify(jsonify({"ok": True, "available": not exists}), origin)

    except Exception as e:
        log.exception("Failed to check subdomain availability")
        return corsify(jsonify({"ok": False, "error": "check_failed"}), origin), 500

@app.get("/families/<family_slug>")
def get_family_by_slug(family_slug: str):
    """Get family information by slug (supports both public and authenticated access)"""
    origin = request.headers.get("Origin")
    
    family_slug = sanitize_tenant(family_slug)
    if not family_slug:
        return corsify(jsonify({"ok": False, "error": "invalid_family_slug"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Get family with settings
            cur.execute("""
                SELECT t.id, t.slug, t.name, t.created_at,
                       fs.description, fs.is_public, fs.theme_color, fs.banner_image, fs.family_photo
                FROM tenants t
                LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                WHERE t.slug = %s
            """, (family_slug,))
            family = cur.fetchone()
            
            if not family:
                return corsify(jsonify({"ok": False, "error": "family_not_found"}), origin), 404
            
            # Get member count (for public info)
            cur.execute("SELECT COUNT(*) as member_count FROM tenant_users WHERE tenant_id = %s", (family["id"],))
            member_count = cur.fetchone()["member_count"]
            
            family_data = {
                "id": family["id"],
                "slug": family["slug"],
                "name": family["name"],
                "description": family["description"],
                "isPublic": family["is_public"],
                "themeColor": family["theme_color"] or "#2563eb",
                "bannerImage": family["banner_image"],
                "familyPhoto": family["family_photo"],
                "memberCount": member_count,
                "createdAt": family["created_at"].isoformat() if family["created_at"] else None
            }
            
            # Add more details if user is authenticated and is a member OR is a global admin
            user = current_user_row()
            if user:
                # Check if user is a member of the family
                cur.execute("""
                    SELECT role FROM tenant_users 
                    WHERE user_id = %s AND tenant_id = %s
                """, (user["id"], family["id"]))
                membership = cur.fetchone()
                # Check if user is a global admin
                is_global_admin = user.get("global_role") in ["ROOT", "ADMIN"]
                if membership or is_global_admin:
                    # User is a member or global admin, include private details
                    cur.execute("""
                        SELECT u.id, up.display_name as name, u.email, tu.role,
                               up.avatar_url, up.bio, up.quote
                        FROM tenant_users tu
                        JOIN users u ON tu.user_id = u.id
                        LEFT JOIN user_profiles up ON u.id = up.user_id
                        WHERE tu.tenant_id = %s
                        ORDER BY tu.role DESC, u.email ASC
                    """, (family["id"],))
                    members = list(cur.fetchall())
                    family_data["members"] = [
                        {
                            "id": m["id"],
                            "name": m["name"] or m["email"].split("@")[0],
                            "email": m["email"],
                            "role": m["role"],
                            "joinedAt": None,
                            "avatarUrl": m["avatar_url"],
                            "bio": m.get("bio"),
                            "quote": m.get("quote")
                        }
                        for m in members
                    ]
                    family_data["userRole"] = membership["role"] if membership else user.get("global_role")

        return corsify(jsonify({"ok": True, "family": family_data}), origin)

    except Exception as e:
        log.exception(f"Failed to get family {family_slug}")
        return corsify(jsonify({"ok": False, "error": "fetch_failed"}), origin), 500

@app.post("/families/invite")
def invite_family_member_new():
    """Invite a member to join a family with specific role"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    family_id = data.get("familyId", "").strip()
    email = data.get("email", "").strip().lower()
    name = data.get("name", "").strip()
    role = data.get("role", "ADULT").strip()

    # Validate role
    valid_roles = ["ADMIN", "ADULT", "CHILD_0_5", "CHILD_5_10", "CHILD_10_14", "CHILD_14_16", "CHILD_16_ADULT"]
    if role not in valid_roles:
        return corsify(jsonify({"ok": False, "error": "Invalid role"}), origin), 400

    if not all([family_id, email, name]):
        return corsify(jsonify({"ok": False, "error": "Missing required fields"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check if user has admin permissions for this family
            cur.execute("""
                SELECT role FROM tenant_users 
                WHERE user_id = %s AND tenant_id = %s AND role = 'ADMIN'
            """, (user["id"], family_id))
            
            if not cur.fetchone() and user["global_role"] != "ROOT":
                return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403

            # Get family info
            cur.execute("SELECT slug, name FROM tenants WHERE id = %s", (family_id,))
            family = cur.fetchone()
            if not family:
                return corsify(jsonify({"ok": False, "error": "Family not found"}), origin), 404

            # Create invitation
            invite_id = str(uuid4())
            invite_token = str(uuid4())
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
            
            cur.execute("""
                INSERT INTO tenant_invitations (id, tenant_id, invited_by, email, role, invite_token, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (invite_id, family_id, user["id"], email, role, invite_token, expires_at))
            invitation = cur.fetchone()

        audit("family_member_invited", 
              family_id=family_id, 
              family_slug=family["slug"], 
              invited_email=email,
              invited_by=user["email"],
              role=role)

        return corsify(jsonify({
            "ok": True,
            "invitation": dict(invitation),
            "message": f"Invitation sent to {email} to join {family['name']}"
        }), origin)

    except Exception as e:
        log.exception("Failed to invite family member")
        return corsify(jsonify({"ok": False, "error": "invitation_failed"}), origin), 500

@app.patch("/families/<family_id>/members/<member_id>/role")
def update_member_role(family_id: str, member_id: str):
    """Update a family member's role"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)

    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "").strip()
    manual_override = data.get("manualOverride", False)

    if new_role not in TENANT_ROLES:
        return corsify(jsonify({"ok": False, "error": "Invalid role"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check permissions - must be OWNER or ADMIN
            cur.execute("""
                SELECT role FROM tenant_users 
                WHERE user_id = %s AND tenant_id = %s
            """, (user["id"], family_id))
            user_membership = cur.fetchone()
            
            if not user_membership or user_membership["role"] not in ["OWNER", "ADMIN"]:
                if user["global_role"] != "ROOT":
                    return corsify(jsonify({"ok": False, "error": "Permission denied"}), origin), 403

            # Get member's current info and profile
            cur.execute("""
                SELECT tu.role as current_role, up.birthdate, up.permissions_manual
                FROM tenant_users tu
                LEFT JOIN user_profiles up ON tu.user_id = up.user_id
                WHERE tu.user_id = %s AND tu.tenant_id = %s
            """, (member_id, family_id))
            member_info = cur.fetchone()
            
            if not member_info:
                return corsify(jsonify({"ok": False, "error": "Member not found"}), origin), 404

            # Age-based validation
            permissions = get_role_permissions(new_role)
            age = None
            if member_info["birthdate"]:
                age = calculate_age(member_info["birthdate"])
                
                # If not manual override, suggest age-appropriate role
                if not manual_override and age is not None:
                    suggested_role = determine_role_from_age(age)
                    if new_role != suggested_role and new_role not in ["OWNER", "ADMIN"]:
                        return corsify(jsonify({
                            "ok": False, 
                            "error": "role_mismatch",
                            "suggestedRole": suggested_role,
                            "age": age,
                            "message": f"Age {age} suggests role {suggested_role}. Use manualOverride to force this role."
                        }), origin), 400

            # Prevent demoting the last owner
            if member_info["current_role"] == "OWNER" and new_role != "OWNER":
                cur.execute("""
                    SELECT COUNT(*) as owner_count 
                    FROM tenant_users 
                    WHERE tenant_id = %s AND role = 'OWNER'
                """, (family_id,))
                owner_count = cur.fetchone()["owner_count"]
                
                if owner_count <= 1:
                    return corsify(jsonify({
                        "ok": False, 
                        "error": "cannot_remove_last_owner",
                        "message": "Cannot remove the last owner. Assign another owner first."
                    }), origin), 400

            # Update role
            cur.execute("""
                UPDATE tenant_users 
                SET role = %s 
                WHERE user_id = %s AND tenant_id = %s
                RETURNING *
            """, (new_role, member_id, family_id))
            
            # Update permissions_manual flag if manual override
            if manual_override:
                cur.execute("""
                    UPDATE user_profiles 
                    SET permissions_manual = true, updated_at = now()
                    WHERE user_id = %s
                """, (member_id,))

        audit("member_role_updated",
              family_id=family_id,
              member_id=member_id,
              old_role=member_info["current_role"],
              new_role=new_role,
              manual_override=manual_override,
              updated_by=user["email"])

        return corsify(jsonify({
            "ok": True, 
            "message": "Role updated successfully",
            "newRole": new_role,
            "permissions": permissions
        }), origin)

    except Exception as e:
        log.exception("Failed to update member role")
        return corsify(jsonify({"ok": False, "error": "update_failed"}), origin), 500

@app.get("/admin/families")
def admin_get_all_families():
    """Get all families (root admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    if user["global_role"] != "ROOT":
        return corsify(jsonify({"ok": False, "error": "Root admin access required"}), origin), 403

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT t.id, t.slug, t.name, t.created_at,
                       fs.description, fs.is_public,
                       COUNT(tu.user_id) as member_count
                FROM tenants t
                LEFT JOIN family_settings fs ON t.id = fs.tenant_id
                LEFT JOIN tenant_users tu ON t.id = tu.tenant_id
                GROUP BY t.id, t.slug, t.name, t.created_at, fs.description, fs.is_public
                ORDER BY t.created_at DESC
            """)
            families = list(cur.fetchall())

        return corsify(jsonify({"ok": True, "families": families}), origin)

    except Exception as e:
        log.exception("Failed to get all families")
        return corsify(jsonify({"ok": False, "error": "fetch_failed"}), origin), 500

@app.get("/admin/users")
def admin_get_all_users():
    """Get all users (root admin only)"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    if user["global_role"] != "ROOT":
        return corsify(jsonify({"ok": False, "error": "Root admin access required"}), origin), 403

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT u.id, u.email, u.global_role, u.created_at,
                       up.display_name as name,
                       COUNT(tu.tenant_id) as family_count
                FROM users u
                LEFT JOIN user_profiles up ON u.id = up.user_id
                LEFT JOIN tenant_users tu ON u.id = tu.user_id
                GROUP BY u.id, u.email, u.global_role, u.created_at, up.display_name
                ORDER BY u.created_at DESC
            """)
            users = list(cur.fetchall())

        return corsify(jsonify({"ok": True, "users": users}), origin)

    except Exception as e:
        log.exception("Failed to get all users")
        return corsify(jsonify({"ok": False, "error": "fetch_failed"}), origin), 500

@app.post("/admin/create-root")
def admin_create_root_admin():
    """Create root admin user (only if no root admin exists)"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()

    if not all([email, password, name]):
        return corsify(jsonify({"ok": False, "error": "Missing required fields"}), origin), 400

    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check if any root admin already exists
            cur.execute("SELECT id FROM users WHERE global_role = 'ROOT' LIMIT 1")
            if cur.fetchone():
                return corsify(jsonify({"ok": False, "error": "Root admin already exists"}), origin), 400

            # Check if email already exists
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return corsify(jsonify({"ok": False, "error": "Email already registered"}), origin), 400

            # Create root admin
            user_id = str(uuid4())
            password_hash = ph.hash(password)
            
            cur.execute("""
                INSERT INTO users (id, email, password_hash, global_role)
                VALUES (%s, %s, %s, 'ROOT') RETURNING *
            """, (user_id, email, password_hash))
            user = cur.fetchone()
            
            # Create user profile
            cur.execute("""
                INSERT INTO user_profiles (user_id, display_name)
                VALUES (%s, %s)
            """, (user_id, name))

        audit("root_admin_created", admin_email=email)
        
        return corsify(jsonify({
            "ok": True,
            "user": {
                "id": user_id,
                "email": email,
                "name": name,
                "globalRole": "ROOT_ADMIN"
            }
        }), origin)

    except Exception as e:
        log.exception("Failed to create root admin")
        return corsify(jsonify({"ok": False, "error": "creation_failed"}), origin), 500

# ---------------- Posts and Media Routes ----------------

@app.route("/media/upload", methods=["POST"])
def upload_media():
    """Upload media file (image/video) for posts"""
    origin = request.headers.get("Origin")
    
    # TODO: Add authentication later
    # user = current_user_row()
    # if not user:
    #     return corsify(jsonify({"ok": False, "error": "unauthorized"}), origin), 401

    try:
        if 'file' not in request.files:
            return corsify(jsonify({"ok": False, "error": "no_file"}), origin), 400
        
        file = request.files['file']
        if file.filename == '':
            return corsify(jsonify({"ok": False, "error": "no_file"}), origin), 400

        # TEMPORARY: Very permissive validation for debugging iPhone video issues
        content_type = file.content_type or mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
        
        log.info(f"[DEBUG] Upload attempt: filename={file.filename}, content_type={content_type}")
        
        # Check if it's definitely allowed
        is_allowed_type = content_type in ALLOWED_CONTENT_TYPES
        
        # For mobile uploads, be very permissive with media file extensions
        if not is_allowed_type and file.filename:
            filename_lower = file.filename.lower()
            is_media_by_extension = (
                filename_lower.endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif', '.bmp', '.tiff')) or
                filename_lower.endswith(('.mp4', '.mov', '.m4v', '.avi', '.webm', '.3gp', '.3gpp', '.mkv', '.flv', '.wmv'))
            )
            # Allow any file with media extension, regardless of MIME type
            if is_media_by_extension:
                is_allowed_type = True
                log.info(f"Allowing file {file.filename} with MIME type {content_type} based on media extension")
        
        # Block obviously non-media files
        if file.filename:
            filename_lower = file.filename.lower()
            is_obviously_not_media = (
                filename_lower.endswith(('.txt', '.doc', '.docx', '.pdf', '.zip', '.rar', '.js', '.html', '.css')) or
                not filename_lower.split('.')[-1].isalpha()  # No extension or weird extension
            )
            if is_obviously_not_media:
                log.warning(f"Blocked obviously non-media file: {file.filename}")
                return corsify(jsonify({"ok": False, "error": "invalid_file_type", "detected_type": content_type}), origin), 400
        
        if not is_allowed_type:
            log.warning(f"Rejected file: {file.filename}, MIME type: {content_type}")
            return corsify(jsonify({"ok": False, "error": "invalid_file_type", "detected_type": content_type}), origin), 400

        # Validate file size (150MB max)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 150 * 1024 * 1024:  # 150MB
            return corsify(jsonify({"ok": False, "error": "file_too_large"}), origin), 400

        # Read file data
        file_data = file.read()
        
        # Upload to Vercel Blob
        try:
            blob_result = upload_to_vercel_blob(file_data, file.filename, content_type)
            
            log.info(f"Successfully uploaded {file.filename} to Vercel Blob: {blob_result['url']}")
            
            return corsify(jsonify({
                "ok": True,
                "url": blob_result['url'],
                "filename": blob_result['filename'],
                "size": blob_result['size'],
                "type": "image" if content_type.startswith('image/') else "video"
            }), origin)
            
        except StorageNotConfigured:
            log.warning("Vercel Blob not configured, falling back to mock URL")
            # Fallback to mock URL if Vercel Blob not configured
            mock_url = f"https://kinjar-api.fly.dev/media/{uuid4()}.{file.filename.split('.')[-1]}"
            return corsify(jsonify({
                "ok": True,
                "url": mock_url,
                "type": "image" if content_type.startswith('image/') else "video"
            }), origin)

    except Exception as e:
        log.exception("Failed to upload media")
        return corsify(jsonify({"ok": False, "error": "upload_failed"}), origin), 500

@app.route("/media/<filename>", methods=["GET"])
def serve_media(filename):
    """Serve uploaded media files (mock endpoint for demo)"""
    origin = request.headers.get("Origin")
    
    # For now, return a placeholder image for demo purposes
    # TODO: Implement actual file serving from S3/R2
    if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
        # Return a placeholder image URL
        placeholder_url = "https://images.unsplash.com/photo-1542744173-8e7e53415bb0?w=800&h=600&fit=crop"
        return redirect(placeholder_url)
    else:
        # For videos, return a 404 for now
        return corsify(jsonify({"ok": False, "error": "file_not_found"}), origin), 404

# ---------------- End Posts and Media Routes ----------------

# ---------------- End New Family Authentication Routes ----------------

@app.post("/families/<family_slug>/invite")
def invite_family_member_by_slug(family_slug: str):
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
@app.route("/media/upload", methods=["OPTIONS"])
@app.route("/upload", methods=["OPTIONS"])
@app.route("/upload/complete", methods=["OPTIONS"])
@app.route("/posts", methods=["OPTIONS"])
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
@app.route("/api/families/<family_slug>", methods=["OPTIONS"])
@app.route("/api/families/<family_slug>/posts", methods=["OPTIONS"])
@app.route("/families/<family_slug>/invite", methods=["OPTIONS"])
@app.route("/families/create", methods=["OPTIONS"])
@app.route("/families/check-subdomain/<subdomain>", methods=["OPTIONS"])
@app.route("/families/<family_slug>", methods=["OPTIONS"])
@app.route("/families/invite", methods=["OPTIONS"])
@app.route("/families/<family_id>/members/<member_id>/role", methods=["OPTIONS"])
@app.route("/admin/families", methods=["OPTIONS"])
@app.route("/admin/users", methods=["OPTIONS"])
@app.route("/admin/create-root", methods=["OPTIONS"])
def options():
    return "", 200

# ---------------- Family Creation ----------------

def options():
    origin = request.headers.get("Origin")
    response = make_response(("", 204))
    return corsify(response, origin)

@app.post("/auth/forgot-password")
def forgot_password():
    """Send password reset email"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    email = (data.get("email") or "").strip().lower()
    if not email:
        return corsify(jsonify({"ok": False, "error": "Email required"}), origin), 400
    
    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Check if user exists
            cur.execute("SELECT id, email FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if not user:
                # Don't reveal if email exists or not for security
                return corsify(jsonify({"ok": True, "message": "If that email exists, a reset link has been sent"}), origin)
            
            # Generate reset token
            reset_token = str(uuid4()).replace('-', '')
            from datetime import datetime, timedelta
            expires_at = datetime.now() + timedelta(hours=1)  # 1 hour expiry
            
            # Store reset token (we'll use tenant_invitations table temporarily)
            cur.execute("""
                INSERT INTO tenant_invitations (
                    id, tenant_id, invited_by, email, role, 
                    invite_token, expires_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'reset_password')
                ON CONFLICT (invite_token) DO UPDATE SET
                expires_at = EXCLUDED.expires_at, status = 'reset_password'
            """, (str(uuid4()), str(uuid4()), user["id"], email, "RESET", reset_token, expires_at))
            
            con.commit()
            
            # TODO: Send reset email with link containing reset_token
            # For now, just return success
            log.info(f"Password reset requested for {email}, token: {reset_token}")
            
            return corsify(jsonify({
                "ok": True, 
                "message": "If that email exists, a reset link has been sent",
                "reset_token": reset_token  # Remove this in production!
            }), origin)
            
    except Exception as e:
        log.error(f"Forgot password failed: {e}")
        return corsify(jsonify({"ok": False, "error": "Request failed"}), origin), 500

@app.post("/auth/reset-password")
def reset_password():
    """Reset password using token"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    token = data.get("token", "")
    new_password = data.get("password", "")
    
    if not token or not new_password or len(new_password) < 8:
        return corsify(jsonify({"ok": False, "error": "Token and password (8+ chars) required"}), origin), 400
    
    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Find valid reset token
            cur.execute("""
                SELECT email, expires_at FROM tenant_invitations
                WHERE invite_token = %s AND status = 'reset_password' AND expires_at > now()
            """, (token,))
            reset_request = cur.fetchone()
            
            if not reset_request:
                return corsify(jsonify({"ok": False, "error": "Invalid or expired reset token"}), origin), 400
            
            # Update password
            pw_hash = ph.hash(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (pw_hash, reset_request["email"]))
            
            # Mark token as used
            cur.execute("UPDATE tenant_invitations SET status = 'used' WHERE invite_token = %s", (token,))
            
            con.commit()
            log.info(f"Password reset completed for {reset_request['email']}")
            
            return corsify(jsonify({"ok": True, "message": "Password reset successfully"}), origin)
            
    except Exception as e:
        log.error(f"Password reset failed: {e}")
        return corsify(jsonify({"ok": False, "error": "Reset failed"}), origin), 500

@app.post("/auth/change-password")
def change_password():
    """Change password for authenticated user"""
    origin = request.headers.get("Origin")
    user, err = require_auth()
    if err:
        return corsify(err, origin)
    
    data = request.get_json(silent=True) or {}
    current_password = data.get("currentPassword", "")
    new_password = data.get("newPassword", "")
    
    if not current_password or not new_password or len(new_password) < 8:
        return corsify(jsonify({"ok": False, "error": "Current and new password (8+ chars) required"}), origin), 400
    
    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Get current user data
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (user["id"],))
            user_data = cur.fetchone()
            
            if not user_data:
                return corsify(jsonify({"ok": False, "error": "User not found"}), origin), 404
            
            # Verify current password
            try:
                ph.verify(user_data["password_hash"], current_password)
            except:
                return corsify(jsonify({"ok": False, "error": "Current password incorrect"}), origin), 400
            
            # Update to new password
            new_pw_hash = ph.hash(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_pw_hash, user["id"]))
            
            con.commit()
            log.info(f"Password changed for user {user['email']}")
            
            return corsify(jsonify({"ok": True, "message": "Password changed successfully"}), origin)
            
    except Exception as e:
        log.error(f"Change password failed: {e}")
        return corsify(jsonify({"ok": False, "error": "Change failed"}), origin), 500

@app.post("/emergency/reset-password")
def emergency_reset_password():
    """Emergency password reset - temporary endpoint"""
    origin = request.headers.get("Origin")
    data = request.get_json(silent=True) or {}
    
    email = (data.get("email") or "").strip().lower()
    new_password = data.get("password", "")
    emergency_key = data.get("key", "")
    
    # Simple emergency key check
    if emergency_key != "kinjar-emergency-2025":
        return corsify(jsonify({"ok": False, "error": "Invalid emergency key"}), origin), 403
    
    if not email or not new_password:
        return corsify(jsonify({"ok": False, "error": "Email and password required"}), origin), 400
    
    try:
        with_db()
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # Update password
            pw_hash = ph.hash(new_password)
            cur.execute("""
                UPDATE users SET password_hash = %s WHERE email = %s
            """, (pw_hash, email))
            
            if cur.rowcount == 0:
                return corsify(jsonify({"ok": False, "error": "User not found"}), origin), 404
            
            con.commit()
            log.info(f"Emergency password reset for {email}")
            
            return corsify(jsonify({
                "ok": True, 
                "message": f"Password reset successfully for {email}"
            }), origin)
            
    except Exception as e:
        log.error(f"Emergency password reset failed: {e}")
        return corsify(jsonify({"ok": False, "error": "Reset failed"}), origin), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
