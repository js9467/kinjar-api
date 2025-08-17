import os, sqlite3, datetime
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

APP_DIR   = os.path.dirname(__file__)
DATA_DIR  = os.path.join(APP_DIR, "data")
MEDIA_DIR = os.path.join(DATA_DIR, "media")
os.makedirs(MEDIA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "db.sqlite3")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            family TEXT NOT NULL,
            author TEXT NOT NULL,
            kind TEXT NOT NULL,
            body TEXT,
            media_path TEXT,
            approved INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()

def extract_family(host_header: str) -> str:
    """
    Pulls the left-most subdomain as 'family' when host
    looks like <family>.kinjar.com; otherwise fallback to header X-Family,
    then 'default'.
    """
    family = (request.headers.get("X-Family") or "").strip().lower()
    if family:
        return family
    host = (host_header or "").split(":")[0].lower()
    parts = host.split(".")
    if len(parts) >= 3 and parts[0] not in {"www", "api"}:
        return parts[0]
    return "default"

app = Flask(__name__)

@app.before_first_request
def _startup():
    init_db()

@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.datetime.utcnow().isoformat()}

@app.get("/")
def root():
    return jsonify({"service": "kinjar-flask", "message": "hello 👋", "docs": "/help"})

@app.get("/help")
def help_doc():
    return {
        "routes": {
            "GET /health": "Liveness check",
            "GET /posts": "List approved posts for current family",
            "POST /posts": "Create a post (multipart/form-data)",
            "GET /media/<path>": "Serve uploaded media"
        },
        "notes": "Set subdomain <family>.kinjar.com or header X-Family to scope posts."
    }

@app.get("/posts")
def list_posts():
    family = extract_family(request.headers.get("Host"))
    conn = get_db()
    rows = conn.execute(
        "SELECT id,family,author,kind,body,media_path,approved,created_at "
        "FROM posts WHERE family=? ORDER BY id DESC",
        (family,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/posts")
def create_post():
    # Accepts multipart/form-data
    family = extract_family(request.headers.get("Host"))
    author = (request.form.get("author") or "parent").strip()[:50]
    kind   = (request.form.get("kind") or "text").strip()[:20]  # text|photo|audio
    body   = (request.form.get("body") or "").strip()[:4000]

    media_rel = None
    upload = request.files.get("file")
    if upload and upload.filename:
        safe = secure_filename(upload.filename)
        ts   = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        fname = f"{ts}_{safe}"
        fam_dir = os.path.join(MEDIA_DIR, family)
        os.makedirs(fam_dir, exist_ok=True)
        path = os.path.join(fam_dir, fname)
        upload.save(path)
        media_rel = f"{family}/{fname}"

    conn = get_db()
    now = datetime.datetime.utcnow().isoformat()
    cur = conn.execute(
        "INSERT INTO posts (family,author,kind,body,media_path,approved,created_at) "
        "VALUES (?,?,?,?,?,1,?)",
        (family, author, kind, body, media_rel, now),
    )
    conn.commit()
    return {"id": cur.lastrowid, "family": family, "media_path": media_rel, "created_at": now}

@app.get("/media/<path:rel>")
def media(rel: str):
    # rel should look like "<family>/<filename>"
    parts = rel.split("/", 1)
    if len(parts) != 2:
        return {"error": "bad path"}, 400
    fam, fname = parts
    d = os.path.join(MEDIA_DIR, fam)
    return send_from_directory(d, fname, as_attachment=False, max_age=3600)
