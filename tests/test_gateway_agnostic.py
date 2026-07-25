"""End-to-end: drive the REAL gateway over BOTH provider paths (OpenAI-compatible
and Anthropic-native) through the REAL security pipeline, in-process."""
import os, sys, json, pathlib

PROJ = str(pathlib.Path(__file__).resolve().parents[1])
os.chdir(PROJ); sys.path.insert(0, PROJ)

SB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox")
os.makedirs(SB, exist_ok=True)
open(os.path.join(SB, "notes.txt"), "w").write("hello world")

os.environ.update(
    SANDBOX_DIR=SB, CONFIG_PATH=f"{PROJ}/config",
    PRIV_KEY_PATH=f"{PROJ}/keys/ecdsa_private.pem", PUB_KEY_PATH=f"{PROJ}/keys/ecdsa_public.pem",
    LOG_ENC_KEY_HEX=os.urandom(32).hex(), REDIS_URL="redis://fake",
    ANTHROPIC_API_KEY="sk-ant-test",
    AUTH_KEYS_JSON=json.dumps({"KEY_ANALYST": "principal_analyst", "KEY_ADMIN": "principal_admin"}),
    INGRESS_URL="http://service_ingress:8443/process",
    REGISTRY_URL="http://service_registry:8500/authorize",
    ENFORCER_URL="http://service_enforcer:8650/execute",
)
import fakeredis, redis
_srv = fakeredis.FakeServer()
redis.from_url = lambda url, **kw: fakeredis.FakeStrictRedis(server=_srv, decode_responses=kw.get("decode_responses", False))

import httpx
from fastapi import FastAPI, Request
from src.service_gateway.main import app as gw
from src.service_ingress.main import app as ing
from src.service_registry.main import app as reg
from src.service_enforcer.main import app as enf
from src.worker_nodes.node_fs import app as fs
from src.worker_nodes.node_db import app as db
from src.worker_nodes.node_net import app as net

# fake OpenAI-compatible LLM (used by principal_analyst -> provider_local @ host.docker.internal)
openai_llm = FastAPI()
@openai_llm.post("/v1/chat/completions")
async def _oai(r: Request):
    b = await r.json()
    if any(m.get("role") == "tool" for m in b.get("messages", [])):
        return {"id": "cmpl", "object": "chat.completion", "model": b["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "openai: file read via tool"}, "finish_reason": "stop"}]}
    return {"id": "cmpl", "object": "chat.completion", "model": b["model"], "choices": [{"index": 0, "message": {"role": "assistant",
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "resource_filesystem", "arguments": '{"action":"list","path":"."}'}}]}, "finish_reason": "tool_calls"}]}

# fake Anthropic Messages API (used by principal_admin -> provider_anthropic @ api.anthropic.com)
anthropic_llm = FastAPI()
@anthropic_llm.post("/v1/messages")
async def _an(r: Request):
    b = await r.json()
    # tool_result comes back as a user message with a tool_result content block
    got_result = any(m.get("role") == "user" and isinstance(m.get("content"), list)
                     and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in m["content"]) for m in b.get("messages", []))
    if got_result:
        return {"id": "msg", "model": b["model"], "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "anthropic: file read via tool"}], "usage": {"input_tokens": 5, "output_tokens": 6}}
    return {"id": "msg", "model": b["model"], "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 6},
            "content": [{"type": "tool_use", "id": "tu1", "name": "resource_filesystem", "input": {"action": "list", "path": "."}}]}

ROUTES = {"service_ingress": ing, "service_registry": reg, "service_enforcer": enf,
          "node-fs": fs, "node-db": db, "node-net": net,
          "host.docker.internal": openai_llm, "api.anthropic.com": anthropic_llm}

class Router(httpx.AsyncBaseTransport):
    def __init__(self): self.t = {h: httpx.ASGITransport(app=a) for h, a in ROUTES.items()}
    async def handle_async_request(self, req):
        tr = self.t.get(req.url.host)
        return await tr.handle_async_request(req) if tr else httpx.Response(502, json={"error": f"host {req.url.host}"})
_orig = httpx.AsyncClient
httpx.AsyncClient = lambda *a, **k: (k.pop("app", None), k.__setitem__("transport", Router()), _orig(*a, **k))[-1]

from fastapi.testclient import TestClient
c = TestClient(gw)
results = []
def check(n, cond, d=""): results.append(cond); print(f"  {'PASS' if cond else 'FAIL'}  {n}  {d if not cond else ''}")

print("=== OpenAI-compatible path (principal_analyst -> local) ===")
r = c.post("/v1/chat/completions", headers={"X-API-Key": "KEY_ANALYST"},
           json={"messages": [{"role": "user", "content": "list the sandbox"}]})
j = r.json()
check("openai path 200", r.status_code == 200, r.text[:120])
check("openai edge shape = chat.completion", j.get("object") == "chat.completion", str(j)[:120])
check("openai final content after tool", "openai: file read" in json.dumps(j))

print("=== Anthropic-native path (principal_admin -> anthropic) ===")
r = c.post("/v1/chat/completions", headers={"X-API-Key": "KEY_ADMIN"},
           json={"messages": [{"role": "user", "content": "list the sandbox"}]})
j = r.json()
check("anthropic path 200", r.status_code == 200, r.text[:200])
check("anthropic edge normalized to chat.completion", j.get("object") == "chat.completion", str(j)[:160])
check("anthropic final content after tool", "anthropic: file read" in json.dumps(j))

print(f"\n==================== TOTAL: {sum(results)} passed, {len(results)-sum(results)} failed ====================")
sys.exit(0 if all(results) else 1)
