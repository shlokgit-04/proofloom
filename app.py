"""ProofLoom — retrieval-augmented answers with every run anchored on a
tamper-evident, hash-chained ledger. RAG (LangChain splitter + TF-IDF retrieval)
orchestrated by a LangGraph pipeline, with a blockchain-style audit anchor."""
import json, os, re, sqlite3, time
from flask import Flask, jsonify, request, send_from_directory
from accounts import hash_password, verify_password, issue_token, read_token
import ledger, llm, rag, graph as g

DB_PATH = os.environ.get("PROOFLOOM_DB", "proofloom.db")
MAX_DOC_CHARS = 60_000
MAX_QUESTION_CHARS = 600

app = Flask(__name__, static_folder="static", static_url_path="/static", template_folder="templates")

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
        pw TEXT NOT NULL, name TEXT DEFAULT '', token_version INTEGER DEFAULT 1, created_at REAL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS documents(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        title TEXT NOT NULL, text TEXT NOT NULL, created_at REAL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS runs(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        question TEXT NOT NULL, answer TEXT NOT NULL, mode TEXT NOT NULL,
        model TEXT, citations TEXT, block_id INTEGER, created_at REAL)""")
    ledger.init_ledger(conn)
    return conn

def _genesis():
    conn = db()
    if not conn.execute("SELECT 1 FROM blocks LIMIT 1").fetchone():
        ledger.append(conn, "genesis", {"service": "proofloom", "purpose": "tamper-evident answer audit"})
    conn.close()
_genesis()

def public_user(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"]}

def auth_user(conn):
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    payload = read_token(token)
    if not payload:
        return None
    u = conn.execute("SELECT * FROM users WHERE id=?", (payload["uid"],)).fetchone()
    if not u or u["token_version"] != payload["tv"]:
        return None
    return u

_email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

_rate = {}
def rate_ok(key, limit, window):
    now = time.time()
    hits = [t for t in _rate.get(key, []) if now - t < window]
    if len(hits) >= limit:
        _rate[key] = hits
        return False
    hits.append(now); _rate[key] = hits
    return True

@app.get("/")
def index():
    return send_from_directory("templates", "index.html")
@app.get("/login")
def login_page():
    return send_from_directory("templates", "login.html")
@app.get("/register")
def register_page():
    return send_from_directory("templates", "register.html")
@app.get("/privacy")
def privacy():
    return send_from_directory("templates", "privacy.html")
@app.get("/about")
def about():
    return send_from_directory("templates", "about.html")

@app.post("/api/auth/register")
def register():
    if not rate_ok("reg:" + (request.remote_addr or "?"), 10, 300):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    password = str(d.get("password", ""))
    name = str(d.get("name", "")).strip()[:60]
    if not _email_re.match(email) or len(password) < 8:
        return jsonify({"error": "Valid email and a password of at least 8 characters required."}), 400
    conn = db()
    try:
        conn.execute("INSERT INTO users(email, pw, name, created_at) VALUES(?,?,?,?)", (email, hash_password(password), name, time.time()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "That email is already registered."}), 409
    u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    token = issue_token(u["id"], u["token_version"])
    conn.close()
    return jsonify({"token": token, "user": {"id": u["id"], "email": email, "name": name}})

@app.post("/api/auth/login")
def login():
    if not rate_ok("log:" + (request.remote_addr or "?"), 10, 300):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    d = request.get_json(silent=True) or {}
    email, password = str(d.get("email", "")).strip().lower(), str(d.get("password", ""))
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not verify_password(password, u["pw"]):
        conn.close()
        return jsonify({"error": "Invalid email or password."}), 401
    token = issue_token(u["id"], u["token_version"])
    conn.close()
    return jsonify({"token": token, "user": public_user(u)})

@app.get("/api/auth/me")
def me():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    out = {"user": public_user(u)}
    out["llm"] = {"configured": llm.configured(), "models": llm.free_models()[:20]}
    conn.close()
    return jsonify(out)

@app.post("/api/auth/logout")
def logout():
    return jsonify({"ok": True})

@app.delete("/api/auth/me")
def delete_account():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    conn.execute("UPDATE users SET token_version=token_version+1, pw=?, email=? WHERE id=?",
                 (hash_password(os.urandom(16).hex()), f"deleted-{u['id']}@invalid.local", u["id"]))
    conn.execute("DELETE FROM documents WHERE user_id=?", (u["id"],))
    conn.execute("DELETE FROM runs WHERE user_id=?", (u["id"],))
    ledger.append(conn, "account_deleted", {"user_hash": ledger.canonical({"u": u["id"]})[:12]}, u["id"])
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/docs")
def docs_list():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    rows = conn.execute("SELECT id, title, length(text) AS chars, created_at FROM documents WHERE user_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    conn.close()
    return jsonify({"docs": [dict(r) for r in rows]})

@app.post("/api/docs")
def docs_add():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    d = request.get_json(silent=True) or {}
    title = str(d.get("title", "")).strip()[:120]
    text = str(d.get("text", ""))
    if not title or not text.strip():
        conn.close()
        return jsonify({"error": "Title and document text required."}), 400
    if len(text) > MAX_DOC_CHARS:
        conn.close()
        return jsonify({"error": f"Document too large (max {MAX_DOC_CHARS} characters)."}), 400
    cur = conn.execute("INSERT INTO documents(user_id, title, text, created_at) VALUES(?,?,?,?)", (u["id"], title, text, time.time()))
    n_chunks = len(rag.split_text(text))
    conn.commit()
    doc_id = cur.lastrowid
    conn.close()
    return jsonify({"doc": {"id": doc_id, "title": title, "chunks": n_chunks}}), 201

@app.delete("/api/docs/<int:doc_id>")
def docs_delete(doc_id):
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    row = conn.execute("SELECT id FROM documents WHERE id=? AND user_id=?", (doc_id, u["id"])).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found."}), 404
    conn.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.post("/api/query")
def query():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    if not rate_ok("q:" + str(u["id"]), 30, 300):
        conn.close()
        return jsonify({"error": "Slow down a little and try again."}), 429
    d = request.get_json(silent=True) or {}
    question = str(d.get("question", "")).strip()
    model = str(d.get("model", "")).strip()
    if not question or len(question) > MAX_QUESTION_CHARS:
        conn.close()
        return jsonify({"error": "A question of 1-600 characters is required."}), 400
    rows = conn.execute("SELECT id, title, text FROM documents WHERE user_id=?", (u["id"],)).fetchall()
    chunks = []
    for r in rows:
        for ch in rag.split_text(r["text"]):
            chunks.append({"doc_id": r["id"], "doc_title": r["title"], "text": ch, "hash": rag.chunk_hash(ch)})
    hits = rag.retrieve(chunks, question)
    state = g.run_query(conn, u["id"], question, hits, model)
    cur = conn.execute("INSERT INTO runs(user_id, question, answer, mode, model, citations, block_id, created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (u["id"], question, state["answer"], state["mode"], state.get("model") or None,
                        json.dumps(state["citations"]), state["block"].get("block_id"), time.time()))
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return jsonify({"run_id": run_id, "answer": state["answer"], "mode": state["mode"],
                    "citations": state["citations"], "graded": state["graded"],
                    "retrieved": len(state["chunks"]), "block": {k: state["block"].get(k) for k in ("block_id", "idx", "block_hash")}})

@app.get("/api/runs")
def runs():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    rows = conn.execute("SELECT id, question, answer, mode, block_id, created_at FROM runs WHERE user_id=? ORDER BY id DESC LIMIT 50", (u["id"],)).fetchall()
    conn.close()
    return jsonify({"runs": [dict(r) for r in rows]})

@app.get("/api/ledger")
def ledger_list():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    blocks = ledger.list_blocks(conn)
    conn.close()
    return jsonify({"blocks": blocks})

@app.get("/api/ledger/verify")
def ledger_verify():
    conn = db()
    u = auth_user(conn)
    if not u:
        conn.close()
        return jsonify({"error": "Not signed in."}), 401
    result = ledger.verify(conn)
    conn.close()
    return jsonify(result)

@app.get("/api/health")
def health():
    conn = db()
    ok = conn.execute("SELECT 1 FROM blocks LIMIT 1").fetchone() is not None
    conn.close()
    return jsonify({"ok": True, "service": "proofloom", "ledger": "up" if ok else "empty", "llm": llm.configured()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
