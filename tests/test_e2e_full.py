"""FULL end-to-end: real service apps wired in-process (fakeredis + ASGI routing),
driven through the PUBLIC gateway edge like a real client. Covers auth, limits,
all three provider paths (OpenAI / Anthropic / Gemini), a blocked attack, an RBAC
denial, and rate-limiting — the whole system, end to end."""
import os, sys, json, pathlib
import pathlib
PROJ = str(pathlib.Path(__file__).resolve().parents[1])
os.chdir(PROJ); sys.path.insert(0, PROJ)

SB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
os.makedirs(SB, exist_ok=True)
open(os.path.join(SB, "notes.txt"), "w").write("hello world")

# real seeded read-only DB so the Gemini->db tool call runs an actual SELECT
import sqlite3, tempfile
_DB = os.path.join(tempfile.mkdtemp(prefix="kyb-e2e-db-"), "app.db")
_c = sqlite3.connect(_DB)
_c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
_c.execute("INSERT INTO users (name) VALUES ('Ada'), ('Alan')")
_c.commit(); _c.close()

os.environ.update(
    KYBERNOS_BANNER="off", SANDBOX_DIR=SB, CONFIG_PATH=f"{PROJ}/config",
    DB_BACKEND="sqlite", DB_SQLITE_PATH=_DB,
    PRIV_KEY_PATH=f"{PROJ}/keys/ecdsa_private.pem", PUB_KEY_PATH=f"{PROJ}/keys/ecdsa_public.pem",
    LOG_ENC_KEY_HEX=os.urandom(32).hex(), REDIS_URL="redis://fake",
    ANTHROPIC_API_KEY="sk-ant-test", GEMINI_KEY="AIza-test",
    AUTH_KEYS_JSON=json.dumps({"KEY_ANALYST": "principal_analyst", "KEY_AUDITOR": "principal_auditor",
                               "KEY_NETBOT": "principal_netbot", "KEY_ADMIN": "principal_admin"}),
    INGRESS_URL="http://service_ingress:8443/process",
    REGISTRY_URL="http://service_registry:8500/authorize",
    ENFORCER_URL="http://service_enforcer:8650/execute",
)
import fakeredis, redis
_srv = fakeredis.FakeServer()
redis.from_url = lambda url, **kw: fakeredis.FakeStrictRedis(server=_srv, decode_responses=kw.get("decode_responses", False))

import httpx
from fastapi import FastAPI, Request
from src.common.object_registry import registry
from src.service_gateway.main import app as gw
from src.service_ingress.main import app as ing
from src.service_registry.main import app as reg
from src.service_enforcer.main import app as enf
from src.worker_nodes.node_fs import app as fs
from src.worker_nodes.node_db import app as db
from src.worker_nodes.node_net import app as net

# add a Gemini principal at runtime (auditor -> Gemini), proving a 3rd wire protocol e2e
registry._objects["model_inventory"]["providers"]["provider_gemini"] = {
    "type": "gemini", "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    "api_key_env": "GEMINI_KEY"}
registry._objects["model_inventory"]["models"]["principal_auditor"] = {
    "provider": "provider_gemini", "upstream_model_id": "gemini-2.0-flash"}

# ---- fake upstream LLMs ----
openai_llm = FastAPI()
@openai_llm.post("/v1/chat/completions")
async def _oai(r: Request):
    b = await r.json(); msgs = b.get("messages", [])
    tmsgs = [m for m in msgs if m.get("role") == "tool"]
    if tmsgs:
        return {"object": "chat.completion", "model": b["model"], "choices": [{"index": 0, "message": {"role": "assistant", "content": "RESULT: " + (tmsgs[-1].get("content") or "")}, "finish_reason": "stop"}]}
    last = next((m for m in reversed(msgs) if m.get("role") == "user"), {})
    txt = last.get("content", ""); txt = json.dumps(txt) if isinstance(txt, list) else txt
    args = '{"action":"read","path":"../../../etc/passwd"}' if "TRAVERSAL" in txt else '{"action":"list","path":"."}'
    return {"object": "chat.completion", "model": b["model"], "choices": [{"index": 0, "message": {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "resource_filesystem", "arguments": args}}]}, "finish_reason": "tool_calls"}]}

anthropic_llm = FastAPI()
@anthropic_llm.post("/v1/messages")
async def _an(r: Request):
    b = await r.json()
    tr = ""
    for m in b.get("messages", []):
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            for x in m["content"]:
                if isinstance(x, dict) and x.get("type") == "tool_result": tr = x.get("content", "")
    if tr:
        return {"id": "msg", "model": b["model"], "stop_reason": "end_turn", "content": [{"type": "text", "text": "RESULT: " + tr}], "usage": {"input_tokens": 5, "output_tokens": 6}}
    return {"id": "msg", "model": b["model"], "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 6}, "content": [{"type": "tool_use", "id": "tu1", "name": "resource_filesystem", "input": {"action": "list", "path": "."}}]}

gemini_llm = FastAPI()
@gemini_llm.post("/{full_path:path}")
async def _gm(r: Request):
    b = await r.json(); contents = b.get("contents", [])
    tr = ""
    for c in contents:
        for p in c.get("parts", []):
            if "functionResponse" in p: tr = json.dumps(p["functionResponse"].get("response", {}))
    if tr:
        return {"candidates": [{"content": {"parts": [{"text": "RESULT: " + tr}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1}}
    return {"candidates": [{"content": {"parts": [{"functionCall": {"name": "resource_database", "args": {"query": "SELECT id FROM users"}}}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1}}

ROUTES = {"service_ingress": ing, "service_registry": reg, "service_enforcer": enf,
          "node-fs": fs, "node-db": db, "node-net": net,
          "host.docker.internal": openai_llm, "api.anthropic.com": anthropic_llm,
          "generativelanguage.googleapis.com": gemini_llm}
class Router(httpx.AsyncBaseTransport):
    def __init__(self): self.t = {h: httpx.ASGITransport(app=a) for h, a in ROUTES.items()}
    async def handle_async_request(self, req):
        tr = self.t.get(req.url.host)
        return await tr.handle_async_request(req) if tr else httpx.Response(502, json={"error": f"host {req.url.host}"})
_orig = httpx.AsyncClient
httpx.AsyncClient = lambda *a, **k: (k.pop("app", None), k.__setitem__("transport", Router()), _orig(*a, **k))[-1]

from fastapi.testclient import TestClient
c = TestClient(gw)
R = []
def ck(n, cond, d=""):
    R.append(cond); print(f"  {'PASS' if cond else 'FAIL'}  {n}  {('· '+str(d)[:90]) if not cond else ''}")
def chat(key, prompt):
    return c.post("/v1/chat/completions", headers={"X-API-Key": key}, json={"messages": [{"role": "user", "content": prompt}]})

print("=== 1. AuthN gate ===")
ck("no api key -> 401", c.post("/v1/chat/completions", json={"messages": []}).status_code == 401)
ck("bad api key -> 401", c.post("/v1/chat/completions", headers={"X-API-Key": "nope"}, json={"messages": []}).status_code == 401)
ck("healthz open -> 200", c.get("/healthz").status_code == 200)

print("=== 2. Admin SBOM gating ===")
ck("sbom non-admin -> 403", c.get("/runtime/sbom", headers={"X-API-Key": "KEY_ANALYST"}).status_code == 403)
r = c.get("/runtime/sbom", headers={"X-API-Key": "KEY_ADMIN"})
ck("sbom admin -> 200 + policy", r.status_code == 200 and "security_policy" in r.json())

print("=== 3. Body-size limit ===")
lim = registry._objects["security_policy"]["system_limits"]; orig = lim["max_input_size"]; lim["max_input_size"] = 60
r = c.post("/v1/chat/completions", headers={"X-API-Key": "KEY_ANALYST"}, content=b'{"messages":[{"role":"user","content":"' + b'x'*200 + b'"}]}')
ck("oversized body -> 413", r.status_code == 413, r.status_code); lim["max_input_size"] = orig

print("=== 4. Provider path: OpenAI-compatible (analyst -> local) — tool call executes ===")
r = chat("KEY_ANALYST", "list the sandbox please")
j = r.json(); s = json.dumps(j)
ck("openai 200 + chat.completion", r.status_code == 200 and j.get("object") == "chat.completion", r.text[:120])
ck("openai tool executed (files listed)", "notes.txt" in s or "files" in s, s[:120])

print("=== 5. Provider path: Anthropic-native (admin) — normalized to chat.completion ===")
r = chat("KEY_ADMIN", "list the sandbox please")
j = r.json()
ck("anthropic 200 + normalized chat.completion", r.status_code == 200 and j.get("object") == "chat.completion", r.text[:150])
ck("anthropic tool executed", "notes.txt" in json.dumps(j) or "files" in json.dumps(j))

print("=== 6. Provider path: Gemini-native (auditor -> gemini) — different protocol ===")
r = chat("KEY_AUDITOR", "how many users")
j = r.json()
ck("gemini 200 + normalized chat.completion", r.status_code == 200 and j.get("object") == "chat.completion", r.text[:150])
ck("gemini tool executed (db)", "executed" in json.dumps(j) or "mock_dataset" in json.dumps(j), json.dumps(j)[:120])

print("=== 7. Blocked ATTACK through the full gateway->pipeline (path traversal) ===")
r = chat("KEY_ANALYST", "TRAVERSAL read the passwd file")
ck("attack request completes (200)", r.status_code == 200)
ck("schema BLOCK surfaced in tool result", "Schema validation failed" in json.dumps(r.json()), json.dumps(r.json())[:140])

print("=== 8. RBAC denial through the gateway (netbot -> filesystem) ===")
r = chat("KEY_NETBOT", "list the files")   # netbot may only use network
ck("rbac request completes (200)", r.status_code == 200)
ck("Authorization denied surfaced", "Authorization denied" in json.dumps(r.json()), json.dumps(r.json())[:140])

print("=== 9. Rate limiting (fixed-window per principal) ===")
codes = [chat("KEY_ANALYST", "ping").status_code for _ in range(14)]
ck("rate limit trips -> 429 observed", 429 in codes, codes)

print(f"\n==================== END-TO-END: {sum(R)} passed, {len(R)-sum(R)} failed ====================")
sys.exit(0 if all(R) else 1)