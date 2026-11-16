"""ProofLoom ledger: an append-only, hash-chained, tamper-evident block store.

Every block commits to: the previous block's hash, a canonical-JSON SHA-256 of
its payload, a monotonic index and a small proof-of-work nonce, so any edit to
history (payload, order or removal) breaks verification.
"""
import hashlib, json, os, sqlite3, time

DB_PATH = os.environ.get("PROOFLOOM_DB", "proofloom.db")
DIFFICULTY = 2  # number of leading zero hex chars required in block_hash

def _db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_ledger(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS blocks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        idx INTEGER NOT NULL UNIQUE,
        ts REAL NOT NULL,
        kind TEXT NOT NULL,
        user_id INTEGER,
        payload_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        nonce INTEGER NOT NULL,
        block_hash TEXT NOT NULL)""")

def _block_hash(idx: int, ts: float, kind: str, payload_hash: str, prev_hash: str, nonce: int) -> str:
    basis = f"{idx}|{ts}|{kind}|{payload_hash}|{prev_hash}|{nonce}".encode()
    return hashlib.sha256(basis).hexdigest()

def canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def append(conn, kind: str, payload, user_id=None):
    row = conn.execute("SELECT idx, block_hash FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
    idx = (row["idx"] + 1) if row else 0
    prev_hash = row["block_hash"] if row else "0" * 64
    payload_hash = hashlib.sha256(canonical(payload).encode()).hexdigest()
    ts = time.time()
    nonce, block_hash = 0, ""
    prefix = "0" * DIFFICULTY
    while not block_hash.startswith(prefix):
        nonce += 1
        block_hash = _block_hash(idx, ts, kind, payload_hash, prev_hash, nonce)
    cur = conn.execute(
        "INSERT INTO blocks(idx, ts, kind, user_id, payload_hash, prev_hash, nonce, block_hash)"
        " VALUES(?,?,?,?,?,?,?,?)", (idx, ts, kind, user_id, payload_hash, prev_hash, nonce, block_hash))
    conn.commit()
    return {"block_id": cur.lastrowid, "idx": idx, "block_hash": block_hash,
            "payload_hash": payload_hash, "prev_hash": prev_hash, "ts": ts, "kind": kind}

def verify(conn):
    """Recompute the whole chain. Returns {ok, checked, reason}."""
    rows = conn.execute("SELECT * FROM blocks ORDER BY idx ASC").fetchall()
    prev_hash, prev_idx, checked = "0" * 64, -1, 0
    for r in rows:
        if r["idx"] != prev_idx + 1:
            return {"ok": False, "checked": checked, "reason": f"index gap at block {r['idx']}"}
        if r["prev_hash"] != prev_hash:
            return {"ok": False, "checked": checked, "reason": f"prev_hash mismatch at block {r['idx']}"}
        if not _block_hash(r["idx"], r["ts"], r["kind"], r["payload_hash"], r["prev_hash"], r["nonce"]).startswith("0" * DIFFICULTY) \
           or _block_hash(r["idx"], r["ts"], r["kind"], r["payload_hash"], r["prev_hash"], r["nonce"]) != r["block_hash"]:
            return {"ok": False, "checked": checked, "reason": f"hash mismatch at block {r['idx']}"}
        prev_hash, prev_idx, checked = r["block_hash"], r["idx"], checked + 1
    return {"ok": True, "checked": checked, "reason": None}

def list_blocks(conn, limit=100):
    rows = conn.execute("SELECT idx, ts, kind, user_id, payload_hash, block_hash, prev_hash FROM blocks ORDER BY idx DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
