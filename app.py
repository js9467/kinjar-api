import os
import re
import json
import uuid
import shutil
import logging
from datetime import datetime
from typing import Tuple, Dict, Any, List, Optional

from flask import Flask, request, jsonify, send_from_directory, abort

# -----------------------
# Config
# -----------------------
PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
ALLOWED_EXTENSIONS = set(os.environ.get("ALLOWED_EXTENSIONS", "jpg,jpeg,png,gif,webp,mp4,mov,avi,txt,json,pdf,mp3,wav,m4a").split(","))

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
SLUG_RE = re.compile(r"^[a-z0-9_-]{1,48}$")

def _ok() -> Dict[str, Any]:
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}

def _err(message: str, status: int = 400) -> Tuple[Dict[str, Any], int]:
    return {"ok": False, "error": message}, status

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def sanitize_slug(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip().lower()
    return s if SLUG_RE.match(s) else None

def tenant_dir(tenant: str) -> str:
    td = os.path.join(DATA_DIR, "tenants", tenant)
    os.makedirs(td, exist_ok=True)
    os.makedirs(os.path.join(td, "uploads"), exist_ok=True)
    os.makedirs(os.path.join(td, "notes"), exist_ok=True)
    os.makedirs(os.path.join(td, "data"), exist_ok=True)
    return td

def family_data_dir(tenant: str) -> str:
    return os.path.join(tenant_dir(tenant), "data")

def json_path(tenant: str, name: str) -> str:
    os.makedirs(family_data_dir(tenant), exist_ok=True)
    return os.path.join(family_data_dir(tenant), name)

def read_json(tenant: str, name: str, default):
    fp = json_path(tenant, name)
    if not os.path.exists(fp):
        return default
    try:
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.warning("read_json error %s: %s", fp, e)
        return default

def write_json(tenant: str, name: str, data):
    fp = json_path(tenant, name)
    tmp = fp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, fp)

def append_jsonl(tenant: str, name: str, obj: Dict[str, Any]):
    fp = json_path(tenant, name)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def read_jsonl(tenant: str, name: str) -> List[Dict[str, Any]]:
    fp = json_path(tenant, name)
    if not os.path.exists(fp):
        return []
    out: List[Dict[str, Any]] = []
    with open(fp, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

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

def parse_date(d: str) -> datetime:
    # Accept "YYYY-MM-DD" or ISO datetime (with or without trailing Z)
    if len(d) == 10 and d[4] == "-" and d[7] == "-":
        return datetime.fromisoformat(d + "T00:00:00+00:00")
    return datetime.fromisoformat(d.replace("Z", "+00:00"))

def compute_age(birthdate_iso: str, now_utc: datetime) -> int:
    try:
        b = datetime.fromisoformat(birthdate_iso)
    except Exception:
        return 0
    years = now_utc.year - b.year - ((now_utc.month, now_utc.day) < (b.month, b.day))
    return max(0, years)

def resolve_tenant_from_request() -> Optional[str]:
    # Priority: X-Family header (from Next proxy), then ?tenant, then JSON body.family
    fam = sanitize_slug(request.headers.get("X-Family"))
    if fam:
        return fam
    fam = sanitize_slug(request.args.get("tenant"))
    if fam:
        return fam
    try:
        data = request.get_json(force=True, silent=True) or {}
        fam = sanitize_slug(data.get("family"))
        if fam:
            return fam
    except Exception:
        pass
    return None

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
# Tenant Notes (simple demo store)
# -----------------------
@app.post("/tenant/<tenant>/note")
def add_note(tenant: str):
    """
    Create/append a simple note for a tenant.
    Body JSON: { "title": "...", "body": "..." }
    """
    tenant = sanitize_slug(tenant)
    if not tenant:
        return _err("Invalid tenant", 400)

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
    tenant = sanitize_slug(tenant)
    if not tenant:
        return _err("Invalid tenant", 400)

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
      - tenant (required)   <-- or send X-Family header and omit tenant
      - file (required)
    Saves to /data/tenants/<tenant>/uploads/<safe_filename>
    """
    tenant = sanitize_slug(request.form.get("tenant")) or resolve_tenant_from_request()
    if not tenant:
        return _err("Missing 'tenant' (form field) or X-Family header", 400)

    if "file" not in request.files:
        return _err("Missing 'file' in form-data", 400)

    file = request.files["file"]
    if file.filename == "":
        return _err("Empty filename", 400)

    from werkzeug.utils import secure_filename
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
    Query params: ?tenant=<tenant>   (or X-Family header)
    """
    tenant = sanitize_slug(request.args.get("tenant")) or resolve_tenant_from_request()
    if not tenant:
        return _err("Missing 'tenant' query param or X-Family header", 400)

    files = list_files_for_tenant(tenant)
    return jsonify({"tenant": tenant, "files": files})

@app.get("/file/<tenant>/<path:filename>")
def get_file(tenant: str, filename: str):
    tenant = sanitize_slug(tenant)
    if not tenant:
        abort(404)
    up_dir = os.path.join(tenant_dir(tenant), "uploads")

    from werkzeug.utils import secure_filename
    safe_name = secure_filename(filename)
    requested = os.path.normpath(os.path.join(up_dir, safe_name))
    if not requested.startswith(up_dir):
        abort(404)
    if not os.path.exists(requested):
        abort(404)
    rel_dir = os.path.relpath(os.path.dirname(requested), up_dir)
    rel_name = os.path.basename(requested)
    serve_dir = up_dir if rel_dir == "." else os.path.join(up_dir, rel_dir)
    return send_from_directory(serve_dir, rel_name, as_attachment=False)

# -----------------------
# Posts (core feed)
# -----------------------
POSTS_FILE = "posts.json"

@app.get("/posts")
def get_posts():
    """
    GET /posts[?public=1]
    Requires X-Family header (or ?tenant=).
    """
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant/family", 400)

    posts = read_json(tenant, POSTS_FILE, [])
    q_public = request.args.get("public")
    if q_public is not None:
        # filter public-only if any value present (e.g., ?public=1)
        posts = [p for p in posts if bool(p.get("public"))]
    # newest first
    posts.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    return jsonify(posts), 200

@app.post("/posts")
def create_post():
    """
    POST /posts
    Body: { kind: "text"|"image", body?, image_url?, public?: bool, author?: str }
    Requires X-Family header (or JSON {family}).
    """
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant/family", 400)

    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON", 400)

    kind = (data.get("kind") or "text").strip()
    if kind not in ("text", "image"):
        return _err("Invalid kind (text|image)", 400)

    body = (data.get("body") or "").strip() or None
    image_url = (data.get("image_url") or "").strip() or None
    if kind == "text" and not body:
        return _err("Text post requires 'body'", 400)
    if kind == "image" and not image_url:
        return _err("Image post requires 'image_url'", 400)

    post = {
        "id": "pst_" + uuid.uuid4().hex[:10],
        "kind": kind,
        "body": body,
        "image_url": image_url,
        "public": bool(data.get("public", False)),
        "author": (data.get("author") or "").strip() or None,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    posts = read_json(tenant, POSTS_FILE, [])
    posts.append(post)
    write_json(tenant, POSTS_FILE, posts)
    return jsonify(post), 201

# -----------------------
# Reactions & Comments (append-only jsonl)
# -----------------------
@app.post("/posts/<post_id>/reactions")
def add_reaction(post_id: str):
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON", 400)
    emoji = (data.get("emoji") or "").strip()
    author_member_id = (data.get("author_member_id") or "").strip() or None
    if not emoji:
        return _err("Missing emoji", 400)
    obj = {
        "id": "rea_" + uuid.uuid4().hex[:6],
        "post_id": post_id,
        "emoji": emoji,
        "author_member_id": author_member_id,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    append_jsonl(tenant, "reactions.jsonl", obj)
    return jsonify(obj), 201

@app.get("/posts/<post_id>/reactions")
def list_reactions(post_id: str):
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    all_rx = read_jsonl(tenant, "reactions.jsonl")
    return jsonify([r for r in all_rx if r.get("post_id") == post_id]), 200

@app.post("/posts/<post_id>/comments")
def add_comment(post_id: str):
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON", 400)
    kind = (data.get("kind") or "text").strip()
    body = (data.get("body") or "").strip() or None
    media_url = (data.get("media_url") or "").strip() or None
    author_member_id = (data.get("author_member_id") or "").strip() or None
    if kind == "text" and not body:
        return _err("Text comment requires 'body'", 400)
    obj = {
        "id": "cmt_" + uuid.uuid4().hex[:6],
        "post_id": post_id,
        "kind": kind,
        "body": body,
        "media_url": media_url,
        "author_member_id": author_member_id,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    append_jsonl(tenant, "comments.jsonl", obj)
    return jsonify(obj), 201

@app.get("/posts/<post_id>/comments")
def list_comments(post_id: str):
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    all_cmts = read_jsonl(tenant, "comments.jsonl")
    out = [c for c in all_cmts if c.get("post_id") == post_id]
    out.sort(key=lambda c: c.get("created_at",""), reverse=True)
    return jsonify(out), 200

# -----------------------
# Members (profiles)
# -----------------------
@app.get("/members")
def list_members():
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    members = read_json(tenant, "members.json", [])
    now = datetime.utcnow()
    for m in members:
        bd = (m.get("birthdate") or "").strip()
        m["age"] = compute_age(bd, now) if bd else None
    return jsonify(members), 200

@app.post("/members")
def create_member():
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON", 400)
    member = {
        "id": "mem_" + uuid.uuid4().hex[:8],
        "display_name": (data.get("display_name") or "").strip() or "Unnamed",
        "role": (data.get("role") or "kid").strip(),
        "birthdate": (data.get("birthdate") or "").strip() or None,
        "avatar_url": (data.get("avatar_url") or "").strip() or None,
        "interests": data.get("interests") or []
    }
    members = read_json(tenant, "members.json", [])
    members.append(member)
    write_json(tenant, "members.json", members)
    return jsonify(member), 201

# -----------------------
# Time Capsules
# -----------------------
@app.get("/capsules")
def list_capsules():
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)

    capsules = read_json(tenant, "capsules.json", [])
    members = {m["id"]: m for m in read_json(tenant, "members.json", [])}
    now = datetime.utcnow()

    changed = False
    for cap in capsules:
        status = cap.get("status") or "locked"
        if status == "unlocked":
            continue
        rtype = cap.get("release_type")
        rval = cap.get("release_value")
        if rtype == "date":
            try:
                if isinstance(rval, str) and now >= parse_date(rval):
                    cap["status"] = "unlocked"
                    changed = True
            except Exception:
                pass
        elif rtype == "age":
            mem = members.get(cap.get("for_member_id"))
            if mem and mem.get("birthdate"):
                age = compute_age(mem["birthdate"], now)
                try:
                    target = int(rval) if not isinstance(rval, int) else rval
                    if age >= target:
                        cap["status"] = "unlocked"
                        changed = True
                except Exception:
                    pass

    if changed:
        write_json(tenant, "capsules.json", capsules)

    capsules.sort(key=lambda c: c.get("created_at",""), reverse=True)
    return jsonify(capsules), 200

@app.post("/capsules")
def create_capsule():
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _err("Invalid JSON", 400)

    cap = {
        "id": "cap_" + uuid.uuid4().hex[:8],
        "title": (data.get("title") or "").strip() or "Untitled",
        "message": (data.get("message") or "").strip() or "",
        "media": data.get("media") or [],
        "release_type": (data.get("release_type") or "date").strip(),  # "date" | "age"
        "release_value": data.get("release_value"),
        "for_member_id": (data.get("for_member_id") or "").strip() or None,
        "guardians": data.get("guardians") or [],
        "public": bool(data.get("public", False)),
        "status": "locked",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    caps = read_json(tenant, "capsules.json", [])
    caps.append(cap)
    write_json(tenant, "capsules.json", caps)
    return jsonify(cap), 201

@app.post("/capsules/<cid>/unlock")
def force_unlock(cid: str):
    tenant = resolve_tenant_from_request()
    if not tenant:
        return _err("Missing tenant", 400)
    caps = read_json(tenant, "capsules.json", [])
    hit = None
    for c in caps:
        if c.get("id") == cid:
            c["status"] = "unlocked"
            hit = c
            break
    if not hit:
        return _err("Not found", 404)
    write_json(tenant, "capsules.json", caps)
    return jsonify(hit), 200

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
