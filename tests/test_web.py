import json, os, sqlite3, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PROOFLOOM_DB"] = "/tmp/pl_test_{:.0f}.db".format(time.time() * 1000)
import pytest
from app import app as flask_app

@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c

def reg(c, email):
    r = c.post("/api/auth/register", json={"email": email, "password": "Str0ng-Pass!9", "name": "T"})
    assert r.status_code == 200
    return r.get_json()["token"]

def H(tok):
    return {"Authorization": "Bearer " + tok}

def test_auth_flow(client):
    tok = reg(client, "a@test.local")
    assert tok.startswith("v1.")
    assert client.post("/api/auth/login", json={"email": "a@test.local", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "a@test.local", "password": "Str0ng-Pass!9"}).status_code == 200
    r = client.get("/api/auth/me", headers=H(tok))
    assert r.status_code == 200 and r.get_json()["user"]["email"] == "a@test.local"
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers=H(tok[:-2] + "xx")).status_code == 401

def test_docs_and_query_end_to_end(client):
    tok = reg(client, "b@test.local")
    h = H(tok)
    assert client.post("/api/docs", headers=h, json={"title": "", "text": "x"}).status_code == 400
    r = client.post("/api/docs", headers=h, json={"title": "Spec", "text": "ProofLoom rate limits are 10 requests per minute. Deployments run on free hosting with gunicorn."})
    assert r.status_code == 201
    doc = r.get_json()["doc"]
    assert doc["chunks"] >= 1
    r = client.post("/api/query", headers=h, json={"question": "What are the rate limits?"})
    assert r.status_code == 200
    body = r.get_json()
    assert "10 requests per minute" in body["answer"]
    assert body["mode"] == "extractive"
    assert body["citations"], "citations must exist"
    assert body["block"]["block_hash"]
    assert client.post("/api/query", headers=h, json={"question": "What is the capital of France?"}).status_code == 200
    r2 = client.post("/api/query", headers=h, json={"question": "Who is the president of Atlantis?"})
    assert "Not in your knowledge base" in r2.get_json()["answer"]
    assert client.get("/api/query").status_code == 405
    assert client.post("/api/query", json={"question": "hi"}).status_code == 401
    assert client.post("/api/query", headers=h, json={"question": ""}).status_code == 400
    assert client.get("/api/runs", headers=h).get_json()["runs"]
    assert client.get("/api/ledger", headers=h).get_json()["blocks"]
    assert client.get("/api/ledger/verify", headers=h).get_json()["ok"] is True

def test_ledger_tamper_detection(client):
    tok = reg(client, "c@test.local")
    h = H(tok)
    assert client.get("/api/ledger/verify", headers=h).get_json()["ok"] is True
    conn = sqlite3.connect(os.environ["PROOFLOOM_DB"])
    conn.execute("UPDATE blocks SET kind='tampered' WHERE idx=(SELECT MAX(idx) FROM blocks)")
    conn.commit(); conn.close()
    v = client.get("/api/ledger/verify", headers=h).get_json()
    assert v["ok"] is False and "hash mismatch" in (v["reason"] or "")

def test_docs_scoped_per_user(client):
    t1, t2 = reg(client, "d1@test.local"), reg(client, "d2@test.local")
    client.post("/api/docs", headers=H(t1), json={"title": "D1", "text": "alpha beta " * 50})
    assert client.post("/api/query", headers=H(t2), json={"question": "alpha beta"}).get_json()["answer"].startswith("Not in your knowledge base")
    docs1 = client.get("/api/docs", headers=H(t1)).get_json()["docs"]
    assert client.delete("/api/docs/%d" % docs1[0]["id"], headers=H(t2)).status_code == 404

def test_delete_account(client):
    tok = reg(client, "e@test.local")
    h = H(tok)
    client.post("/api/docs", headers=h, json={"title": "T", "text": "some text for deletion test " * 20})
    assert client.delete("/api/auth/me", headers=h).get_json()["ok"] is True
    assert client.get("/api/auth/me", headers=h).status_code == 401

def test_pages_and_health(client):
    for path in ("/", "/login", "/register", "/privacy", "/about", "/api/health"):
        assert client.get(path).status_code == 200, path
