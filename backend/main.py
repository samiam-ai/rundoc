import os, sqlite3, hashlib, secrets, datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import anthropic
import stripe
import jwt

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY            = os.getenv("SECRET_KEY", secrets.token_hex(32))
ANTHROPIC_API_KEY     = os.getenv("ANTHROPIC_API_KEY", "")
STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID       = os.getenv("STRIPE_PRICE_ID", "")
BASE_URL              = os.getenv("BASE_URL", "http://localhost:8000")
DB_PATH               = os.getenv("DB_PATH", "rundoc.db")
FREE_LIMIT            = 5

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            email                  TEXT UNIQUE NOT NULL,
            password_hash          TEXT NOT NULL,
            password_salt          TEXT NOT NULL,
            created_at             TEXT DEFAULT (datetime('now')),
            stripe_customer_id     TEXT,
            stripe_subscription_id TEXT,
            subscription_status    TEXT DEFAULT 'free'
        );
        CREATE TABLE IF NOT EXISTS documents (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            doc_type   TEXT NOT NULL,
            month_key  TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()

# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return dk.hex()

def create_token(user_id: int, email: str) -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    return jwt.encode({"sub": str(user_id), "email": email, "exp": exp},
                      SECRET_KEY, algorithm="HS256")

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_token(authorization[7:])
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (int(payload["sub"]),)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(user)

# ── App lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Models ────────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class GenerateRequest(BaseModel):
    notes: str
    doc_type: str   # runbook | incident_report | sop
    company_name: str
    tone: str       # internal | client

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
def register(req: RegisterRequest):
    email = req.email.lower().strip()
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    salt = secrets.token_hex(16)
    ph   = hash_password(req.password, salt)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (email, password_hash, password_salt) VALUES (?,?,?)",
                     (email, ph, salt))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return {"token": create_token(user["id"], user["email"]),
                "email": user["email"], "subscription_status": "free"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")
    finally:
        conn.close()

@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = req.email.lower().strip()
    conn  = get_db()
    user  = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if not user or hash_password(req.password, user["password_salt"]) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"token": create_token(user["id"], user["email"]),
            "email": user["email"],
            "subscription_status": user["subscription_status"]}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    month_key = datetime.datetime.utcnow().strftime("%Y-%m")
    conn  = get_db()
    count = conn.execute("SELECT COUNT(*) FROM documents WHERE user_id=? AND month_key=?",
                         (user["id"], month_key)).fetchone()[0]
    conn.close()
    return {"email": user["email"],
            "subscription_status": user["subscription_status"],
            "docs_this_month": count,
            "free_limit": FREE_LIMIT}

# ── Generation prompts ────────────────────────────────────────────────────────
TONE_DESC = {
    "internal": "Internal — use direct, technical language for IT staff. Assume technical knowledge. No fluff.",
    "client":   "Client-Facing — use clear, professional language for non-technical stakeholders. Avoid jargon. Be reassuring and polished.",
}

PROMPTS = {
    "runbook": """\
You are an expert technical writer creating a professional IT Runbook for {company}.
Tone: {tone}

Convert the rough notes below into a well-structured Runbook.
Return ONLY clean HTML using: h1 h2 h3 p ul ol li table thead tbody tr th td strong em code pre hr.
Include only sections supported by the notes — do not invent steps or details.

Typical sections (include what applies):
1. Overview / Purpose
2. Scope & Audience
3. Prerequisites
4. Procedure (numbered steps, use <ol><li> — sub-steps as nested lists)
5. Verification / Testing
6. Troubleshooting
7. Rollback Procedure
8. References

Start with <h1>[Descriptive Title]</h1>. Do not wrap in <html><body>.""",

    "incident_report": """\
You are an expert technical writer creating a professional IT Incident Report for {company}.
Tone: {tone}

Convert the rough notes below into a well-structured Incident Report.
Return ONLY clean HTML using: h1 h2 h3 p ul ol li table thead tbody tr th td strong em code pre hr.
Include only sections supported by the notes — do not invent facts.

Typical sections (include what applies):
1. Incident Summary (severity, dates, systems affected)
2. Timeline of Events
3. Impact Assessment
4. Root Cause Analysis
5. Resolution Steps Taken
6. Preventive Measures & Action Items
7. Lessons Learned

Start with <h1>Incident Report: [Brief Description]</h1>. Do not wrap in <html><body>.""",

    "sop": """\
You are an expert technical writer creating a professional Standard Operating Procedure (SOP) for {company}.
Tone: {tone}

Convert the rough notes below into a well-structured SOP.
Return ONLY clean HTML using: h1 h2 h3 p ul ol li table thead tbody tr th td strong em code pre hr.
Include only sections supported by the notes — do not invent procedures.

Typical sections (include what applies):
1. Purpose
2. Scope
3. Roles & Responsibilities
4. Procedure (numbered, detailed steps — use <ol><li>)
5. Quality Control / Verification
6. Exceptions & Edge Cases
7. Related Documents
8. Revision History (placeholder table with Version / Date / Author / Change columns)

Start with <h1>SOP: [Descriptive Title]</h1>. Do not wrap in <html><body>.""",
}

DOC_LABELS = {
    "runbook":         "Runbook",
    "incident_report": "Incident Report",
    "sop":             "Standard Operating Procedure",
}

# ── Generate endpoint ─────────────────────────────────────────────────────────
@app.post("/api/generate")
def generate(req: GenerateRequest, user=Depends(current_user)):
    month_key = datetime.datetime.utcnow().strftime("%Y-%m")
    doc_key   = req.doc_type.lower().strip()

    if doc_key not in PROMPTS:
        raise HTTPException(status_code=400, detail="Invalid document type")

    conn = get_db()
    if user["subscription_status"] != "active":
        count = conn.execute("SELECT COUNT(*) FROM documents WHERE user_id=? AND month_key=?",
                             (user["id"], month_key)).fetchone()[0]
        if count >= FREE_LIMIT:
            conn.close()
            raise HTTPException(status_code=402,
                                detail=f"Free limit of {FREE_LIMIT} documents/month reached. Upgrade to continue.")

    tone_desc = TONE_DESC.get(req.tone, TONE_DESC["internal"])
    system    = PROMPTS[doc_key].format(tone=tone_desc,
                                        company=req.company_name.strip() or "the organization")
    try:
        client  = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": f"Rough notes:\n\n{req.notes.strip()}"}],
        )
        html_body = message.content[0].text
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Generation error: {e}")

    conn.execute("INSERT INTO documents (user_id, doc_type, month_key) VALUES (?,?,?)",
                 (user["id"], doc_key, month_key))
    conn.commit()
    conn.close()

    return {
        "html":       html_body,
        "doc_label":  DOC_LABELS.get(doc_key, doc_key),
        "company":    req.company_name.strip(),
        "generated":  datetime.datetime.utcnow().strftime("%B %d, %Y"),
    }

# ── Stripe endpoints ──────────────────────────────────────────────────────────
@app.post("/api/stripe/create-checkout")
def create_checkout(user=Depends(current_user)):
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            success_url=f"{BASE_URL}/app.html?upgraded=1",
            cancel_url=f"{BASE_URL}/app.html",
            customer_email=user["email"],
            metadata={"user_id": str(user["id"])},
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stripe/portal")
def customer_portal(user=Depends(current_user)):
    stripe.api_key = STRIPE_SECRET_KEY
    if not user["stripe_customer_id"]:
        raise HTTPException(status_code=400, detail="No active subscription found")
    try:
        session = stripe.billing_portal.Session.create(
            customer=user["stripe_customer_id"],
            return_url=f"{BASE_URL}/app.html",
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    stripe.api_key = STRIPE_SECRET_KEY
    payload    = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    conn = get_db()
    t    = event["type"]
    obj  = event["data"]["object"]

    if t == "checkout.session.completed":
        uid = obj.get("metadata", {}).get("user_id")
        if uid:
            conn.execute("""UPDATE users SET stripe_customer_id=?, stripe_subscription_id=?,
                            subscription_status='active' WHERE id=?""",
                         (obj.get("customer"), obj.get("subscription"), int(uid)))
            conn.commit()

    elif t in ("customer.subscription.deleted", "customer.subscription.paused"):
        conn.execute("UPDATE users SET subscription_status='free' WHERE stripe_subscription_id=?",
                     (obj["id"],))
        conn.commit()

    elif t == "customer.subscription.updated":
        status = "active" if obj["status"] == "active" else "free"
        conn.execute("UPDATE users SET subscription_status=? WHERE stripe_subscription_id=?",
                     (status, obj["id"]))
        conn.commit()

    conn.close()
    return {"ok": True}

# ── Serve frontend (must be last) ─────────────────────────────────────────────
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
