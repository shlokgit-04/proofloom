"""ProofLoom accounts: PBKDF2 password hashing + signed stateless tokens."""
import base64, hashlib, hmac, json, os, secrets, sqlite3, time

SECRET_KEY = os.environ.get("PROOFLOOM_SECRET_KEY") or secrets.token_urlsafe(48)
TOKEN_TTL = 30 * 24 * 3600

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + "$" + dk.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def _sig(msg: bytes) -> str:
    return hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()

def issue_token(user_id: int, token_version: int) -> str:
    payload = json.dumps({"uid": user_id, "tv": token_version, "exp": int(time.time()) + TOKEN_TTL}, separators=(",", ":"))
    body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return "v1." + body + "." + _sig(body.encode())

def read_token(token: str):
    if not token or not token.startswith("v1."):
        return None
    try:
        _, body, sig = token.split(".", 2)
        if not hmac.compare_digest(_sig(body.encode()), sig):
            return None
        pad = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
        if payload["exp"] < time.time():
            return None
        return payload
    except Exception:
        return None
