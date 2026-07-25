"""In-process security-pipeline harness for kybernos.

Wires the REAL service apps together with fakeredis (shared token store) and an
ASGI router (so inter-service httpx calls resolve in-process). Fires adversarial
probes directly at the pipeline -> deterministic, no live LLM.
"""
import os, sys, json, asyncio, tempfile

import pathlib
PROJ = str(pathlib.Path(__file__).resolve().parents[1])
os.chdir(PROJ); sys.path.insert(0, PROJ)

# --- real sandbox dir so the "valid list" ALLOW probe is a genuine 200, not a
#     node-error masked as success (the enforcer no longer launders 4xx -> 200). ---
_SANDBOX = tempfile.mkdtemp(prefix="kyb-sandbox-")
with open(os.path.join(_SANDBOX, "notes.txt"), "w") as _f:
    _f.write("hello from the sandbox")

# --- real (seeded) read-only sqlite so the "valid select" probe runs an actual
#     query against a real DB, not a canned mock response. ---
import sqlite3 as _sqlite3
_DB = os.path.join(tempfile.mkdtemp(prefix="kyb-db-"), "app.db")
_c = _sqlite3.connect(_DB)
_c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
_c.execute("INSERT INTO users (name, email) VALUES ('Ada', 'ada@example.com'), ('Alan', 'alan@example.com')")
_c.commit(); _c.close()

# --- env BEFORE importing any src module ---
os.environ.update(
    CONFIG_PATH=f"{PROJ}/config",
    SANDBOX_DIR=_SANDBOX,
    DB_BACKEND="sqlite", DB_SQLITE_PATH=_DB,
    PRIV_KEY_PATH=f"{PROJ}/keys/ecdsa_private.pem",
    PUB_KEY_PATH=f"{PROJ}/keys/ecdsa_public.pem",
    LOG_ENC_KEY_HEX=os.urandom(32).hex(),
    AUTH_KEYS_JSON=json.dumps({
        "KEY_ANALYST": "principal_analyst", "KEY_AUDITOR": "principal_auditor",
        "KEY_NETBOT": "principal_netbot", "KEY_ADMIN": "principal_admin"}),
    REDIS_URL="redis://fake", RATE_LIMIT_FAIL_CLOSED="false",
    INGRESS_URL="http://service_ingress:8443/process",
    REGISTRY_URL="http://service_registry:8500/authorize",
    ENFORCER_URL="http://service_enforcer:8650/execute",
)

# --- shared fakeredis across all services ---
import fakeredis, redis
_server = fakeredis.FakeServer()
redis.from_url = lambda url, **kw: fakeredis.FakeStrictRedis(server=_server, decode_responses=kw.get("decode_responses", False))

# --- import the real apps ---
import httpx
from src.service_gateway.main import app as gateway_app
from src.service_ingress.main import app as ingress_app
from src.service_registry.main import app as registry_app
from src.service_enforcer.main import app as enforcer_app
from src.worker_nodes.node_fs import app as fs_app
from src.worker_nodes.node_db import app as db_app
from src.worker_nodes.node_net import app as net_app

# fake upstream LLM that requests one tool call then answers (host-routed)
from fastapi import FastAPI, Request
llm_app = FastAPI()
@llm_app.post("/v1/chat/completions")
async def _llm(r: Request):
    body = await r.json()
    if any(m.get("role") == "tool" for m in body.get("messages", [])):
        return {"choices": [{"message": {"role": "assistant", "content": "done"}}]}
    return {"choices": [{"message": {"role": "assistant", "tool_calls": [
        {"id": "c1", "function": {"name": "resource_network", "arguments": "{\"url\":\"https://ok.example.com\"}"}}]}}]}

ROUTES = {
    "service_ingress": ingress_app, "service_registry": registry_app,
    "service_enforcer": enforcer_app, "node-fs": fs_app, "node-db": db_app,
    "node-net": net_app, "host.docker.internal": llm_app, "api.openai.com": llm_app,
}

class Router(httpx.AsyncBaseTransport):
    def __init__(self): self.t = {h: httpx.ASGITransport(app=a) for h, a in ROUTES.items()}
    async def handle_async_request(self, req):
        tr = self.t.get(req.url.host)
        if tr is None:
            return httpx.Response(502, json={"error": f"external host {req.url.host} blocked"})
        return await tr.handle_async_request(req)

_orig = httpx.AsyncClient
def _patched(*a, **k):
    k.pop("app", None); k["transport"] = Router(); return _orig(*a, **k)
httpx.AsyncClient = _patched

# node-net now does REAL DNS + a REAL egress fetch. In-process we (a) stub DNS to
# a public IP so its SSRF guard passes for the test's valid host, and (b) serve
# that host from the router. We are testing the PIPELINE's allow/deny here — the
# connector's own SSRF/read-only guards have dedicated tests in test_connectors.py.
from src.worker_nodes import node_net as _net
_net._resolve = lambda host, port: {"93.184.216.34"}
_ext = FastAPI()
@_ext.get("/{path:path}")
def _ext_get(path): return {"fetched_ok": True, "data": "external-response"}
ROUTES["api.example.com"] = _ext
ROUTES["ok.example.com"] = _ext

# ---------------------------------------------------------------- probes
async def pipeline(principal, resource, payload):
    """POST straight to ingress/process (bypasses gateway auth + LLM)."""
    async with httpx.AsyncClient(base_url="http://service_ingress:8443") as c:
        r = await c.post("/process", json={"principal": principal, "resource": resource, "payload": payload})
        return r.status_code, r.text

PROBES = [
    # (category, name, principal, resource, payload, expect)  expect: ALLOW|BLOCK
    ("FS", "valid list",           "principal_analyst", "resource_filesystem", {"action":"list","path":"."}, "ALLOW"),
    # BH-2 regression: a worker-node 404 must surface as BLOCK, not be laundered
    # into a 200 with the error dict handed to the model as if it were content.
    ("FS", "read missing file",    "principal_analyst", "resource_filesystem", {"action":"read","path":"nope.txt"}, "BLOCK"),
    ("FS", "traversal ../etc",     "principal_analyst", "resource_filesystem", {"action":"read","path":"../../../etc/passwd"}, "BLOCK"),
    ("FS", "absolute /etc/shadow", "principal_analyst", "resource_filesystem", {"action":"read","path":"/etc/shadow"}, "BLOCK"),
    ("RBAC","auditor->fs (denied)","principal_auditor", "resource_filesystem", {"action":"list","path":"."}, "BLOCK"),
    ("RBAC","netbot->db (denied)", "principal_netbot",  "resource_database",   {"query":"SELECT a FROM t"}, "BLOCK"),
    ("RBAC","analyst->net(denied)","principal_analyst", "resource_network",    {"url":"https://x.com"}, "BLOCK"),
    ("SQLi","valid select",        "principal_analyst", "resource_database",   {"query":"SELECT id FROM users"}, "ALLOW"),
    ("SQLi","drop table",          "principal_analyst", "resource_database",   {"query":"DROP TABLE users"}, "BLOCK"),
    ("SQLi","union select",        "principal_analyst", "resource_database",   {"query":"SELECT a FROM t UNION SELECT u,p FROM users"}, "BLOCK"),
    ("SQLi","stacked ; drop",      "principal_analyst", "resource_database",   {"query":"SELECT a FROM t; DROP TABLE x"}, "BLOCK"),
    ("SSRF","valid https",         "principal_netbot",  "resource_network",    {"url":"https://api.example.com/data"}, "ALLOW"),
    ("SSRF","aws metadata",        "principal_netbot",  "resource_network",    {"url":"http://169.254.169.254/latest/meta-data"}, "BLOCK"),
    ("SSRF","localhost",           "principal_netbot",  "resource_network",    {"url":"https://localhost/admin"}, "BLOCK"),
    ("SSRF","internal 10.x",       "principal_netbot",  "resource_network",    {"url":"https://10.0.0.5/x"}, "BLOCK"),
]

async def run_pipeline_probes():
    print("\n=== PIPELINE PROBES (principal+resource+payload -> ALLOW/BLOCK) ===")
    p=f=0
    for cat,name,pr,res,pl,exp in PROBES:
        code,txt = await pipeline(pr,res,pl)
        got = "ALLOW" if code==200 else "BLOCK"
        ok = got==exp
        p += ok; f += (not ok)
        reason = "" if code==200 else f"[{code}] {txt[:70]}"
        print(f"  {'PASS' if ok else 'FAIL'}  {cat:5} {name:22} exp={exp:5} got={got:5} {reason}")
    return p,f

# ---------------------------------------------------------------- gateway auth
from fastapi.testclient import TestClient
def run_gateway_auth():
    print("\n=== GATEWAY AUTH / SBOM ===")
    gc = TestClient(gateway_app)
    cases=[]
    r = gc.post("/v1/chat/completions", json={"messages":[]}); cases.append(("no api key -> 401", r.status_code==401, r.status_code))
    r = gc.post("/v1/chat/completions", headers={"X-API-Key":"WRONG"}, json={"messages":[]}); cases.append(("bad api key -> 401", r.status_code==401, r.status_code))
    r = gc.get("/runtime/sbom", headers={"X-API-Key":"KEY_ANALYST"}); cases.append(("sbom non-admin -> 403", r.status_code==403, r.status_code))
    r = gc.get("/runtime/sbom", headers={"X-API-Key":"KEY_ADMIN"}); cases.append(("sbom admin -> 200", r.status_code==200, r.status_code))
    r = gc.get("/healthz"); cases.append(("healthz open -> 200", r.status_code==200, r.status_code))
    p=f=0
    for name,ok,code in cases:
        p+=ok; f+=(not ok); print(f"  {'PASS' if ok else 'FAIL'}  {name:26} (got {code})")
    return p,f

# ---------------------------------------------------------------- unit: firewall DOTALL + schema
def run_units():
    print("\n=== UNIT: firewall newline-bypass + sandbox resolver ===")
    from src.common.securio_binding import securio
    p=f=0
    # FMT_OVERFLOW newline bypass (was exploitable pre-DOTALL)
    payload = "A"*5000 + "\n" + "B"*5000
    try:
        securio.inspect_payload(payload); ok=False; why="not blocked"
    except ValueError as e: ok=True; why=str(e)
    p+=ok; f+=(not ok); print(f"  {'PASS' if ok else 'FAIL'}  9k payload w/ newline blocked  ({why[:40]})")
    # sandbox resolver
    from src.worker_nodes import node_fs
    root = os.path.realpath(node_fs.SANDBOX_DIR)
    # Invariant: _resolve must NEVER return a path outside the sandbox root.
    # (Absolute paths like /etc/shadow are neutralized to sandbox-relative and
    #  are also rejected upstream by the schema's ^(?!/) pattern.)
    for path in [".", "a.txt", "../../etc/passwd", "/etc/shadow", "sub/../ok.txt", "....//....//etc"]:
        try:
            resolved = node_fs._resolve(path)
            inside = resolved == root or resolved.startswith(root + os.sep)
        except Exception:
            inside = True  # rejected outright = safe
        p += inside; f += (not inside)
        print(f"  {'PASS' if inside else 'FAIL'}  sandbox _resolve({path!r}) stays inside root")
    return p,f

async def main():
    tp=tf=0
    for fn in (run_units, run_gateway_auth):
        a,b = fn(); tp+=a; tf+=b
    a,b = await run_pipeline_probes(); tp+=a; tf+=b
    print(f"\n==================== TOTAL: {tp} passed, {tf} failed ====================")
    sys.exit(1 if tf else 0)

asyncio.run(main())
