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

# Auth / Session
JWT_SECRET = env_str("JWT_SECRET")
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
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set")
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
    if origin and (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.after_request
def add_common_headers(resp):
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin")
        if origin and (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,x-api-key,x-tenant-slug,Authorization"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
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
    return s or "family"

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

def create_tenant_and_owner(con, name: str, desired_slug: Optional[str], owner_user_id: str) -> Dict[str, Any]:
    base = slugify_base(desired_slug or name)
    slug = unique_slug(con, base)
    tid = str(uuid4())
    with con.cursor() as cur:
        cur.execute("INSERT INTO tenants (id, slug, name) VALUES (%s,%s,%s)", (tid, slug, name))
        cur.execute("INSERT INTO tenant_users (user_id, tenant_id, role) VALUES (%s,%s,'OWNER')", (owner_user_id, tid))
    return {"id": tid, "slug": slug, "name": name}

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
        tenant = create_tenant_and_owner(con, r["tenant_name"], r["desired_slug"], user["id"])

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

# ---------------- Health ----------------
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

# CORS preflight
@app.route("/presign", methods=["OPTIONS"])
@app.route("/r2/head", methods=["OPTIONS"])
@app.route("/media/signed-get", methods=["OPTIONS"])
@app.route("/media/list", methods=["OPTIONS"])
@app.route("/media/delete", methods=["OPTIONS"])
@app.route("/auth/login", methods=["OPTIONS"])
@app.route("/auth/register", methods=["OPTIONS"])
@app.route("/auth/me", methods=["OPTIONS"])
@app.route("/auth/logout", methods=["OPTIONS"])
@app.route("/signup/request", methods=["OPTIONS"])
@app.route("/admin/signup/requests", methods=["OPTIONS"])
@app.route("/admin/signup/approve", methods=["OPTIONS"])
@app.route("/admin/signup/deny", methods=["OPTIONS"])
def options():
    return make_response(("", 204))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
