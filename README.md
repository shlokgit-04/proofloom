# ProofLoom

Retrieval-augmented answers with provable provenance: every answer is anchored as a block on a tamper-evident, hash-chained ledger the account owner can verify with one click.

Four threads, one fabric:

- **RAG** — per-account knowledge base; documents chunked and retrieved by TF-IDF cosine ranking with cited chunks.
- **LangChain** — document splitting via `langchain-text-splitters` (RecursiveCharacterTextSplitter) and document primitives (`langchain-core`).
- **LangGraph** — the answer pipeline is a real state graph: `retrieve -> grade -> compose -> anchor`, with an LLM relevance grader when a zero-cost model key is configured and a deterministic heuristic otherwise.
- **Blockchain** — an append-only ledger (SQLite) where each block commits to the previous block's hash, a canonical-JSON SHA-256 of its payload, its kind, and a small proof-of-work nonce; `/api/ledger/verify` recomputes the entire chain and detects any edit, reorder or removal.

## Modes

Generative answers use OpenRouter `:free` models only, allowlisted server-side, with graceful 429 handling. With no key configured the pipeline runs fully extractive (sentences lifted from retrieved chunks, clearly labelled `extractive`), so the product works end to end at zero cost and zero external calls.

## Security

- PBKDF2 (260,000 iterations) password hashing; signed 30-day session tokens with per-user token versioning.
- Per-user authorization on every document, run and ledger route; cross-account reads return 404.
- Input validation and length caps on documents and questions; rate limits on auth and query endpoints.
- CSP, X-Frame-Options DENY, nosniff and referrer-policy headers on every response.
- No secrets in the repo: `PROOFLOOM_SECRET_KEY` and optional `OPENROUTER_API_KEY` are host environment variables.

## Run

```bash
pip install -r requirements.txt
python app.py            # development
gunicorn app:app --bind 0.0.0.0:$PORT   # production
```

`pytest tests/test_web.py` covers auth, per-user scoping, the full query run (answer + citations + ledger block), ledger tamper detection, account deletion and page health.

made by [Shlok V.](https://shlok.is-a.dev)
