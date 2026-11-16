"""ProofLoom answer pipeline as a LangGraph state machine.

retrieve -> grade -> compose -> anchor
  grade:   LLM relevance check when a key is configured, else TF-IDF overlap heuristic
  compose: grounded generative answer when a key is configured, else extractive
           (sentences lifted from the retrieved chunks, clearly labelled)
  anchor:  writes the answer + chunk hashes to the tamper-evident ledger
"""
import re
from langgraph.graph import StateGraph, END
from typing import TypedDict, List
import llm, rag
from ledger import append as ledger_append

SYSTEM_GRADE = ("You grade retrieved evidence for a question. Answer with exactly one word: "
                "RELEVANT if any chunk helps answer the question, else IRRELEVANT.")
SYSTEM_COMPOSE = ("You answer ONLY from the numbered context chunks provided. Cite chunks inline like [1], [2]. "
                  "If the context does not contain the answer, say exactly: 'Not in your knowledge base.' "
                  "Be concise and factual. Never invent facts.")

class RunState(TypedDict):
    question: str
    chunks: list
    graded: str
    answer: str
    citations: list
    mode: str
    model: str
    block: dict
    _conn: object
    _user_id: int

def _heuristic_grade(chunks, question):
    q = set(rag.tokenize(question))
    best = max((len(set(rag.tokenize(c["text"])) & q) for c in chunks), default=0)
    return "RELEVANT" if best >= 2 else "IRRELEVANT"

def _extractive_compose(chunks, question):
    q_terms = set(rag.tokenize(question))
    sents = []
    for c in chunks:
        for s in re.split(r"(?<=[.!?])\s+", c["text"]):
            s = s.strip()
            if len(s) < 30:
                continue
            overlap = len(set(rag.tokenize(s)) & q_terms)
            if overlap:
                sents.append((overlap, s, c["n"]))
    sents.sort(key=lambda x: (-x[0], x[2]))
    picked, seen = [], set()
    for _, s, n in sents:
        if s not in seen:
            picked.append(f"{s} [{n}]")
            seen.add(s)
        if len(picked) >= 4:
            break
    if not picked:
        return "Not in your knowledge base."
    return " ".join(picked)

def n_retrieve(state: RunState) -> RunState:
    return {**state, "chunks": state["chunks"]}  # chunks retrieved before the graph starts

def n_grade(state: RunState) -> RunState:
    chunks = state["chunks"]
    if not chunks:
        return {**state, "graded": "IRRELEVANT", "mode": state["mode"]}
    model = state.get("model") or ""
    if llm.configured() and model:
        prompt = "Question: " + state["question"] + "\n\nChunks:\n" + "\n".join(f"[{c['n']}] {c['text'][:600]}" for c in chunks)
        res = llm.chat(model, SYSTEM_GRADE, prompt)
        if res["ok"]:
            word = (res["text"] or "").strip().upper()
            return {**state, "graded": "RELEVANT" if "RELEVANT" in word and "IRRELEVANT" not in word else "IRRELEVANT"}
    return {**state, "graded": _heuristic_grade(chunks, state["question"])}

def n_compose(state: RunState) -> RunState:
    if state["graded"] != "RELEVANT" or not state["chunks"]:
        return {**state, "answer": "Not in your knowledge base.", "citations": []}
    model = state.get("model") or ""
    if llm.configured() and model:
        prompt = "Question: " + state["question"] + "\n\nContext chunks:\n" + "\n".join(f"[{c['n']}] {c['text']}" for c in state["chunks"])
        res = llm.chat(model, SYSTEM_COMPOSE, prompt)
        if res["ok"]:
            return {**state, "answer": res["text"],
                    "citations": [{"n": c["n"], "doc": c["doc_title"], "hash": c["hash"]} for c in state["chunks"]],
                    "mode": "generative"}
    ans = _extractive_compose(state["chunks"], state["question"])
    used = sorted({int(m) for m in re.findall(r"\[(\d+)\]", ans)})
    return {**state, "answer": ans, "mode": "extractive",
            "citations": [{"n": c["n"], "doc": c["doc_title"], "hash": c["hash"]} for c in state["chunks"] if c["n"] in used]}

def n_anchor(state: RunState) -> RunState:
    conn = state["_conn"]
    payload = {"question": state["question"], "answer": state["answer"], "mode": state["mode"],
               "citations": state["citations"], "chunk_hashes": [c["hash"] for c in state["chunks"]],
               "model": state.get("model") or None}
    block = ledger_append(conn, "answer", payload, state["_user_id"])
    return {**state, "block": block}

def build_graph():
    g = StateGraph(RunState)
    g.add_node("retrieve", n_retrieve)
    g.add_node("grade", n_grade)
    g.add_node("compose", n_compose)
    g.add_node("anchor", n_anchor)
    g.set_entry_point("retrieve")
    g.add_edge("retrieve", "grade")
    g.add_edge("grade", "compose")
    g.add_edge("compose", "anchor")
    g.add_edge("anchor", END)
    return g.compile()

GRAPH = build_graph()

def run_query(conn, user_id: int, question: str, chunks: list, model: str = ""):
    """chunks: retrieved hits from rag.retrieve(). Returns final state."""
    numbered = [{**c, "n": i + 1} for i, c in enumerate(chunks)]
    state = {"question": question, "chunks": numbered, "graded": "", "answer": "", "citations": [],
             "mode": "generative" if (llm.configured() and model) else "extractive", "model": model,
             "block": {}, "_conn": conn, "_user_id": user_id}
    return GRAPH.invoke(state)
