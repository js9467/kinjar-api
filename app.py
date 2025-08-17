
from fastapi import FastAPI, UploadFile, Form, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.hash import bcrypt
from datetime import datetime
import os, re, secrets, shutil

# --- Paths & DB ---
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
MEDIA_DIR = os.path.join(DATA_DIR, "media")
os.makedirs(MEDIA_DIR, exist_ok=True)
DB_URL = f"sqlite:///{os.path.join(DATA_DIR, 'db.sqlite3')}"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# --- Models ---
class Family(Base):
    __tablename__ = "families"
    id = Column(Integer, primary_key=True)
    slug = Column(String(64), unique=True, index=True)
    name = Column(String(160))
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    email = Column(String(120))
    pw_hash = Column(String(128))
    pin = Column(String(6))
    birthdate = Column(DateTime, nullable=True)

class Membership(Base):
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True)
    family_id = Column(Integer, ForeignKey("families.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    role = Column(String(10), default="kid")  # "parent" | "kid"
    family = relationship("Family")
    user = relationship("User")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    family_id = Column(Integer, ForeignKey("families.id"), index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    kind = Column(String(20), default="text")  # text | photo | audio | gizmo_text | gizmo_event
    body = Column(Text)
    media_path = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    approved = Column(Boolean, default=False)
    author = relationship("User")

Base.metadata.create_all(bind=engine)

# --- App & CORS ---
app = FastAPI(title="Kinjar API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://kinjar.com", "https://*.kinjar.com"],
    allow_methods=["*"], allow_headers=["*"], allow_credentials=True,
)
app.mount("/media", StaticFiles(directory=MEDIA_DIR), name="media")

# --- DI ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- Tenant helpers ---
IGNORED_SUBS = {"www"}
def extract_slug(host: str) -> str | None:
    host = (host or "").split(":")[0].lower()
    parts = host.split(".")
    if len(parts) < 3: return None
    sub = parts[0]
    if sub in IGNORED_SUBS: return None
    return sub

def require_family(request: Request, db: Session) -> Family:
    # Support X-Family header (for direct API calls / localhost)
    header = request.headers.get("x-family")
    fam = None
    if header:
        fam = db.query(Family).filter_by(slug=header.lower()).first()
    if not fam:
        slug = extract_slug(request.headers.get("host"))
        if slug:
            fam = db.query(Family).filter_by(slug=slug).first()
    if not fam:
        raise HTTPException(400, "No family in subdomain. Use https://<family>.kinjar.com or send X-Family.")
    return fam

# --- Schemas ---
class LoginParent(BaseModel):
    email: str; password: str
class LoginKid(BaseModel):
    name: str; pin: str
class FamilyCreate(BaseModel):
    name: str; slug: str
    parent_name: str; parent_email: str; parent_password: str

# --- Auth helpers ---
def require_user_in_family(db: Session, token: str | None, fam: Family):
    # tokens: "parent:<family_id>:<user_id>" or "kid:<family_id>:<user_id>"
    if not token or token.count(":") != 2:
        raise HTTPException(401, "Auth required")
    typ, fam_id, user_id = token.split(":", 2)
    if int(fam_id) != fam.id:
        raise HTTPException(403, "Wrong family")
    user = db.query(User).get(int(user_id))
    if not user: raise HTTPException(401, "User not found")
    mem = db.query(Membership).filter_by(family_id=fam.id, user_id=user.id).first()
    if not mem: raise HTTPException(403, "No membership in this family")
    return user, mem.role

def save_media_for_family(family_id: int, upload: UploadFile) -> str:
    ext = os.path.splitext(upload.filename or "")[1].lower()
    name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}{ext}"
    fam_dir = os.path.join(MEDIA_DIR, str(family_id))
    os.makedirs(fam_dir, exist_ok=True)
    with open(os.path.join(fam_dir, name), "wb") as f:
        shutil.copyfileobj(upload.file, f)
    return f"{family_id}/{name}"

# --- Admin: create a family + first parent ---
@app.post("/admin/families/create")
def create_family(payload: FamilyCreate, db: Session = Depends(get_db)):
    slug = payload.slug.lower().strip()
    if not re.fullmatch(r"[a-z0-9-]{2,64}", slug):
        raise HTTPException(400, "Bad slug")
    if db.query(Family).filter_by(slug=slug).first():
        raise HTTPException(409, "Slug exists")
    fam = Family(slug=slug, name=payload.name); db.add(fam); db.commit()
    parent = User(name=payload.parent_name, email=payload.parent_email, pw_hash=bcrypt.hash(payload.parent_password))
    db.add(parent); db.commit()
    db.add(Membership(family_id=fam.id, user_id=parent.id, role="parent")); db.commit()
    return {"ok": True, "slug": fam.slug, "family_id": fam.id}

# --- Auth (per family) ---
@app.post("/auth/login/parent")
def login_parent(payload: LoginParent, request: Request, db: Session = Depends(get_db)):
    fam = require_family(request, db)
    user = (db.query(User).join(Membership, Membership.user_id==User.id)
            .filter(Membership.family_id==fam.id, Membership.role=="parent", User.email==payload.email).first())
    if not user or not bcrypt.verify(payload.password, user.pw_hash):
        raise HTTPException(401, "Bad credentials")
    return {"token": f"parent:{fam.id}:{user.id}", "name": user.name, "role": "parent", "family": fam.slug}

@app.post("/auth/login/kid")
def login_kid(payload: LoginKid, request: Request, db: Session = Depends(get_db)):
    fam = require_family(request, db)
    user = (db.query(User).join(Membership, Membership.user_id==User.id)
            .filter(Membership.family_id==fam.id, Membership.role=="kid", User.name==payload.name).first())
    if not user or user.pin != payload.pin:
        raise HTTPException(401, "Bad PIN")
    age = 0
    if user.birthdate:
        age = (datetime.utcnow().date() - user.birthdate.date()).days // 365
    stage = 0 if age < 5 else 1 if age < 9 else 2 if age < 14 else 3 if age < 18 else 4
    return {"token": f"kid:{fam.id}:{user.id}", "name": user.name, "role": "kid", "stage": stage, "family": fam.slug}

# --- Posts (scoped by family) ---
@app.get("/posts")
def list_posts(request: Request, include_pending: bool=False, db: Session = Depends(get_db)):
    fam = require_family(request, db)
    q = db.query(Post).filter(Post.family_id==fam.id).order_by(Post.created_at.desc())
    if not include_pending: q = q.filter_by(approved=True)
    posts = q.all()
    return [{
        "id": p.id, "author": p.author.name, "kind": p.kind, "body": p.body,
        "media_url": f"/media/{p.media_path}" if p.media_path else None,
        "approved": p.approved, "created_at": p.created_at.isoformat()
    } for p in posts]

@app.post("/posts")
def create_post(
    request: Request,
    kind: str = Form("text"), body: str = Form(""),
    file: UploadFile | None = None,
    token: str | None = Form(None),
    db: Session = Depends(get_db)
):
    fam = require_family(request, db)
    user, role = require_user_in_family(db, token, fam)
    media_rel = save_media_for_family(fam.id, file) if file else None
    p = Post(family_id=fam.id, author_id=user.id, kind=kind, body=body[:4000], media_path=media_rel, approved=(role=="parent"))
    db.add(p); db.commit()
    return {"id": p.id, "status": "approved" if p.approved else "pending"}

@app.post("/posts/{post_id}/approve")
def approve_post(post_id: int, token: str, request: Request, db: Session = Depends(get_db)):
    fam = require_family(request, db)
    user, role = require_user_in_family(db, token, fam)
    if role != "parent": raise HTTPException(403, "Parent only")
    p = db.query(Post).filter_by(id=post_id, family_id=fam.id).first()
    if not p: raise HTTPException(404)
    p.approved = True; db.commit()
    return {"ok": True}
