"""ProofLoom retrieval: chunk with LangChain's splitter, retrieve with TF-IDF cosine."""
import hashlib, json, math, re, sqlite3
from collections import Counter
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

CHUNK_SIZE, CHUNK_OVERLAP, TOP_K = 700, 120, 5

def split_text(text: str) -> list:
    splitter = RecursiveCharacterTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP, separators=["\n\n", "\n", ". ", " ", ""])
    return [d.page_content for d in splitter.split_documents([Document(page_content=text)])] or ([text] if text.strip() else [])

def chunk_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]

_TOKEN = re.compile(r"[a-z0-9]{2,}")

def tokenize(s: str) -> list:
    return _TOKEN.findall(s.lower())

def retrieve(chunks: list, question: str, top_k: int = TOP_K) -> list:
    """chunks: [{id, text, doc_title, doc_id}]. Returns top_k [{..., score, terms}] via TF-IDF cosine."""
    q_tokens = tokenize(question)
    if not chunks or not q_tokens:
        return []
    def tf(tokens):
        c = Counter(tokens)
        return {t: n / len(tokens) for t, n in c.items()}
    docs_tf = [tf(tokenize(c["text"])) for c in chunks]
    n_docs = len(chunks)
    df = Counter()
    for d in docs_tf:
        df.update(d.keys())
    def idf(t):
        return math.log((n_docs + 1) / (df.get(t, 0) + 1)) + 1.0
    weights = []
    for d in docs_tf:
        weights.append({t: v * idf(t) for t, v in d.items()})
    q_w = {t: 1.0 * idf(t) for t in set(q_tokens)}
    scored = []
    for i, w in enumerate(weights):
        dot = sum(v * q_w.get(t, 0.0) for t, v in w.items())
        nw = math.sqrt(sum(v * v for v in w.values())) or 1.0
        nq = math.sqrt(sum(v * v for v in q_w.values())) or 1.0
        scored.append({"score": dot / (nw * nq), "terms": sorted(set(q_tokens) & set(w.keys()))})
    order = sorted(range(len(scored)), key=lambda i: scored[i]["score"], reverse=True)[:top_k]
    hits = []
    for i in order:
        if scored[i]["score"] <= 0:
            continue
        c = dict(chunks[i]); c["score"] = round(scored[i]["score"], 4); c["terms"] = scored[i]["terms"]
        hits.append(c)
    return hits
