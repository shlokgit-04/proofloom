"""Optional OpenRouter client. Zero-cost only: :free models, allowlisted server-side.
When no key is configured, callers must degrade gracefully (ProofLoom composes
answers extractively instead of generatively)."""
import os, time, requests

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
CACHE_TTL = 3600
_cache = {"ts": 0, "models": []}
FALLBACK_FREE_MODELS = ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-flash-exp:free", "mistralai/mistral-small-3.2-24b-instruct:free"]

def configured() -> bool:
    return bool(OPENROUTER_API_KEY)

def free_models() -> list:
    if not configured():
        return []
    if time.time() - _cache["ts"] < CACHE_TTL and _cache["models"]:
        return _cache["models"]
    try:
        r = requests.get("https://openrouter.ai/api/v1/models", timeout=15)
        r.raise_for_status()
        ids = [m["id"] for m in r.json().get("data", []) if str(m.get("id", "")).endswith(":free")]
        _cache.update({"ts": time.time(), "models": sorted(ids)[:60] or list(FALLBACK_FREE_MODELS)})
    except Exception:
        _cache.update({"ts": time.time(), "models": list(FALLBACK_FREE_MODELS)})
    return _cache["models"]

def chat(model: str, system: str, user: str) -> dict:
    """Returns {ok, text, error}. Enforces the free-model allowlist."""
    if not configured():
        return {"ok": False, "error": "not_configured"}
    if model not in free_models():
        return {"ok": False, "error": "Pick one of the available free models."}
    try:
        r = requests.post("https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
            json={"model": model, "max_tokens": 700,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            timeout=60)
        if r.status_code == 429:
            return {"ok": False, "error": "The free model is rate-limited right now. Try again in a minute."}
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        return {"ok": True, "text": text}
    except Exception:
        return {"ok": False, "error": "The model call failed. Try again."}
