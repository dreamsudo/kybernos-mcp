# MCP v6 (Kybernos) — Interface Contract for Skepsis

> Extracted from the **actual code** in this repo. Product brand: **Kybernos — Zero-Trust Gateway for AI Agents, by Psypher Labs**. Python package/dir name: `kybernos`; service app titles declare `version="6.0"`; container image tag `mcp-universal:6.0`.
> Every claim below is quoted from a real file at the cited path. Where the code is missing, mock, or self-contradictory, it is called out in **§13 Gaps & uncertainties** rather than invented.

---

## 1. Identity & run (services + ports)

**Version / commit.** No git commit exists yet — `HEAD` is unborn (repo has never been committed), so **no commit hash can be quoted**. Version is declared only in code: `FastAPI(..., version="6.0")` in every service, image tag `mcp-universal:6.0` (`deploy/k8s/30-core.yaml`), and `docker build ... -t mcp-universal:6.0` (`README.md:372`). Note one stale artifact: `scripts/pipeline_orchestrator.sh` emits an SBOM stub claiming `"name": "mcp_universal_system", "version": "5.1.0"` — that script is a theatrical `echo` stub, not a real gate (see §13).

**The 8 services** (from `deploy/docker/docker-compose.yml`), all built from one image (`deploy/docker/Dockerfile`, `python:3.11-slim`, non-root `svcuser` uid 1000, `read_only: true` rootfs):

| Service (compose name) | k8s name | Port | uvicorn target | Role |
|---|---|---|---|---|
| `service_gateway` | `service-gateway` | **8000** (published) | `src.service_gateway.main:app` | OpenAI-compatible edge; API-key→principal; runs the tool loop |
| `service_ingress` | `service-ingress` | **8443** (internal) | `src.service_ingress.main:app` | Pipeline orchestrator; encrypted audit log |
| `service_registry` | `service-registry` | **8500** | `src.service_registry.main:app` | RBAC allow-list check; **mints** ES256 capability tokens |
| `service_enforcer` | `service-enforcer` | **8650** | `src.service_enforcer.main:app` | **Verifies** token; schema + firewall + egress DLP; calls worker |
| `node-fs` | (`20-workers.yaml`) | **8620** | `src.worker_nodes.node_fs:app` | Sandboxed filesystem worker (real) |
| `node-db` | | **8610** | `src.worker_nodes.node_db:app` | SQL worker — **MOCK**, returns canned data |
| `node-net` | | **8630** | `src.worker_nodes.node_net:app` | HTTP worker — **MOCK**, returns canned data |
| `redis_store` | `redis-store` | **6379** | `redis:7-alpine` (`read_only`, tmpfs `/data`) | Token validity + rate-limit buckets |

Worker ports are also the source of truth in `config/resource_catalog.yaml` (`http://node-fs:8620`, `http://node-db:8610`, `http://node-net:8630`). Only `service_gateway` publishes a host port (`8000:8000`); ingress `:8443` is **internal only** in compose — it is *not* the TLS edge. TLS termination in k8s is an nginx `Ingress` (`deploy/k8s/60-ingress.yaml`) fronting `service-gateway:8000`.

**Stand it up.**
```bash
# Docker (dev)
./scripts/gen_keys.sh                     # ES256 keypair + audit key + API keys (nothing committed)
cd deploy/docker && docker compose up --build
# gateway on http://localhost:8000

# Kubernetes
docker build -f deploy/docker/Dockerfile -t mcp-universal:6.0 .
# load image into cluster, then:
bash deploy/k8s/apply.sh                  # applies 00-namespace..60-ingress into ns mcp-secure
```

**How secrets are generated** (`scripts/gen_keys.sh`):
- `keys/ecdsa_private.pem` / `keys/ecdsa_public.pem` — `openssl ecparam -name prime256v1` (P-256), private key `chmod 600`. Used for ES256 token signing.
- `deploy/docker/.env` — `LOG_ENC_KEY_HEX=$(openssl rand -hex 32)` (32-byte AES-256 audit key) + `REMOTE_API_KEY=` placeholder.
- `secrets/api_keys.json` — four keys `mcp_$(openssl rand -hex 24)` mapped to `principal_analyst | principal_auditor | principal_netbot | principal_admin`; printed once, `chmod 600`.
- k8s equivalents: `mcp-keys` Secret (PEMs), `mcp-log-key` Secret (`LOG_ENC_KEY_HEX`), `mcp-config` ConfigMap.

---

## 2. Gateway API

**Yes, OpenAI-compatible.** The edge is OpenAI Chat Completions. Entry point `src/service_gateway/main.py`.

**Endpoints:**
- `POST /v1/chat/completions` — main entry; requires auth. (`main.py:124`)
- `GET  /healthz` — open, `{"status":"ok"}`. (`main.py:112`)
- `GET  /runtime/sbom` — admin-only policy dump; `403` unless the principal has `admin: true`. (`main.py:117`)

**Authenticated principal derivation — never from `body.model`.** Identity comes *only* from the API key. Header precedence (`src/common/auth.py:45` `extract_key`): `X-API-Key` first, else `Authorization: Bearer <key>`. Lookup is constant-time-ish via `hmac.compare_digest` against `secrets/api_keys.json` (or `AUTH_KEYS_JSON` env). The resolved principal then drives model selection, the tool allow-list, and RBAC. The request body's `model` field is **read for nothing identity-related** — `_resolve_provider(principal)` looks up the model in `config/model_inventory.yaml` keyed by *principal*, not by any client-supplied value (`main.py:58`). The docstring is explicit: *"Identity: derived ONLY from the API key, never from the request body."* (`main.py:26-28`). A principal with no provisioned model gets `403 No model provisioned` (`main.py:64`).

**Tool-call submission.** The client does **not** submit tool calls directly. The client sends normal OpenAI `messages`; the gateway injects the principal's allowed tools as OpenAI `function` tools (`_tool_schema`, `main.py:75`), runs a **bounded agentic loop** (`MAX_TOOL_ROUNDS=4`), and for every tool call the model emits, routes it into the security pipeline via `_route_tool_call(principal, name, arguments)` → `POST {INGRESS_URL}` with body `{"principal", "resource", "payload"}` (`main.py:101`). The `principal` sent downstream is always the authenticated identity, never anything from the model/client. Provider wire-format is abstracted by adapters (`src/common/providers.py`): `type: anthropic|bedrock|vertex|gemini` use native APIs, everything else is OpenAI-compatible. Final replies are always re-shaped to OpenAI (`to_openai_response`).

**Real request:**
```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: mcp_<analyst_key>" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"List the files in the sandbox."}]}'
```
**Real response** (OpenAI ChatCompletion shape; for Anthropic/Gemini backends it is synthesized by `to_openai_response`, `providers.py:189`):
```json
{
  "id": "chatcmpl-anthropic",
  "object": "chat.completion",
  "model": "claude-opus-4-8",
  "choices": [
    {"index": 0,
     "message": {"role": "assistant", "content": "The sandbox contains: notes.txt"},
     "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 812, "completion_tokens": 34, "total_tokens": 846}
}
```
Size/limit guards on the edge: `413` if raw body > `max_input_size` (512 KB), `429` on rate limit (`max_requests_per_min: 10`, Redis bucket `rl:{principal}:{minute}`), `400` invalid JSON, `401` bad/missing key, `502` on upstream/model errors.

---

## 3. Request lifecycle + enforcer check order

**Path:** `client → gateway → ingress → registry → enforcer → worker node → (back up)`.

1. **Gateway** (`service_gateway/main.py`) — authenticate API key → principal; resolve provider/model; call the LLM; for each tool call `POST http://service_ingress:8443/process` with `{"principal","resource","payload"}`.
2. **Ingress** (`service_ingress/main.py:28`) — audit-logs the inbound body (`_persist_log("INGRESS", body)`), then:
   - `POST {REGISTRY_URL}` (`/authorize`) with the same body; non-200 ⇒ propagate as auth-denied.
   - `POST {ENFORCER_URL}` (`/execute`) with `{"resource": token_data["resource"], "payload": body.payload}` and header `Authorization: Bearer <token>`.
   - On enforcer non-200: `_persist_log("EGRESS_DENIED", {...})` and propagate. On success: `_persist_log("EGRESS", result)` and return.
3. **Registry** (`service_registry/main.py:19`) — RBAC allow-list check (`principal`'s `allowed_resources` must contain `resource`, else `403`); mints an ES256 capability token; records `valid_token:{jti}` in Redis with the TTL; returns `{"token","resource"}`.
4. **Enforcer** (`service_enforcer/main.py:36`) — verifies the token and runs the authoritative controls (exact order below), then calls the worker.
5. **Worker node** — `POST {endpoint}/run` with the validated `payload`; returns JSON.

**Exact enforcer check order** (`service_enforcer/main.py`, verbatim control flow):

| # | Check | Code | Failure |
|---|---|---|---|
| 1 | **Verify capability token** — signature + required claims | `securio.verify_jwt(token)` | `401 Invalid or expired token` |
| 2 | **Replay / revocation** — `jti` must still be live in Redis | `redis_conn.get(f"valid_token:{claims['jti']}")` | `401 Token revoked or expired` |
| 3 | **Scope match** — token scope == requested resource | `claims["scope"] != resource_id` | `403 Scope mismatch` |
| 4 | **Resource exists** in catalog | `registry.resources.get(resource_id)` | `404 Resource definition missing` |
| 5 | **JSON-Schema validation** (authoritative) | `Draft202012Validator.validate(payload)` | `400 Schema validation failed: …` (or `500` if schema failed to compile ⇒ fail closed) |
| 6 | **Firewall** (inbound denylist, defense-in-depth) | `securio.inspect_payload(str(payload))` | `400 Firewall Violation: <rule_id>` |
| 7 | **Run worker** | `POST {endpoint}/run` (`timeout=tool_def["timeout"]`) | `502 Execution node failed` (on exception / non-JSON) |
| 8 | **Egress DLP** (scan output) — gated by `EGRESS_DLP=true` | `securio.inspect_payload(str(data))` | `502 Response blocked by egress DLP: …` |
| 9 | **Output size cap** | `len(str(data)) > max_output_size` | returns `{"status":"partial","data":<truncated>}` |

> Note vs. the informal "verify→scope→schema→firewall→run→egress→size" summary: the **real** order inserts the Redis **replay/revocation** check at step 2 (between verify and scope) and a resource-existence lookup at step 4. Steps 5→6 are schema-then-firewall as expected. (See §13 on worker status codes.)

---

## 4. Capability token (ES256 claims)

Minted by the **registry** (`service_registry/main.py:32-44`), verified by the **enforcer** (`service_enforcer/main.py:38-47`) via `securio` (`src/common/securio_binding.py`).

**Exact claims** (all set in `payload`, `main.py:34`):

| Claim | Meaning | Source |
|---|---|---|
| `sub` | principal (authenticated identity) | `body.principal` |
| `scope` | the single granted resource id | `body.resource` |
| `jti` | replay id — `os.urandom(16).hex()` (32 hex chars) | random |
| `iat` | issued-at (unix) | `int(time.time())` |
| `nbf` | not-before (== iat) | `now` |
| `exp` | expiry — `now + token_ttl` (**30 s** default) | `now + ttl` |

**Minting** (`main.py:43-44`):
```python
redis_conn.setex(f"valid_token:{jti}", ttl, 1)          # validity window in Redis
return {"token": securio.sign_jwt(payload), "resource": resource}
```

**Signing / verifying** (`securio_binding.py:58-68`):
```python
def sign_jwt(self, payload):  return jwt.encode(payload, self._priv(), algorithm="ES256")
def verify_jwt(self, token):
    return jwt.decode(token, self._pub(),
        algorithms=["ES256"],                             # pinned: no alg-confusion
        options={"require": ["exp", "jti", "scope", "sub"]},
        leeway=5)
```
Key security properties: **alg pinned to ES256** (blocks `alg:none` / RS↔HS confusion), required claims `exp, jti, scope, sub` enforced, 5 s leeway. Keys are P-256 PEMs read once from `PRIV_KEY_PATH` / `PUB_KEY_PATH` (registry signs → needs private; enforcer verifies → needs public).

**`jti` replay / revocation.** On mint, `SETEX valid_token:{jti} <ttl> 1`. The enforcer requires that key to still exist (step 2); when it expires (≤30 s) or is deleted, the token is dead even if the JWT `exp` were somehow still valid. **Revocation = `DEL valid_token:{jti}`** in Redis. (The window is time-boxed, not strictly single-use — the key is not deleted on first use; see §13.)

**Real (redacted) decoded payload:**
```json
{
  "sub": "principal_analyst",
  "scope": "resource_filesystem",
  "jti": "9f2c1a0b7e4d6f38a1c2b3d4e5f60718",
  "iat": 1753430400,
  "nbf": 1753430400,
  "exp": 1753430430
}
```
JOSE header: `{"alg":"ES256","typ":"JWT"}`.

---

## 5. RBAC / access_policy

File: `config/access_policy.yaml`. Loaded as `registry.access_list` → `access_policy["access_control_list"]` (`object_registry.py:38`). This is the **authoritative** allow-list (checked in registry `/authorize` *and* mirrored by the gateway's `_tool_schema` when advertising tools). Roles map to scopes by listing `allowed_resources`; each resource id becomes exactly one token `scope`.

**Schema** (per principal): `allowed_resources: [<resource_id>, ...]`, plus optional `admin: true` (unlocks `/runtime/sbom`).

**Real example (verbatim):**
```yaml
access_control_list:
  principal_analyst:                     # read files + DB, no network
    allowed_resources:
      - "resource_filesystem"
      - "resource_database"
  principal_auditor:                     # DB only (read-only role)
    allowed_resources:
      - "resource_database"
  principal_netbot:                      # network only
    allowed_resources:
      - "resource_network"
  principal_admin:                       # full + SBOM disclosure
    admin: true
    allowed_resources:
      - "resource_filesystem"
      - "resource_database"
      - "resource_network"
```
For Skepsis: define e.g. `principal_skepsis_red` / `principal_skepsis_blue` here with disjoint `allowed_resources` (e.g. red gets `resource_kali_nmap`, blue gets only read/`resource_database`). Admin is *still* subject to schema + firewall — `admin:true` only adds SBOM visibility, not a control bypass.

---

## 6. resource_catalog (declare a tool)

File: `config/resource_catalog.yaml`. Loaded as `registry.resources` → `resource_catalog["resources"]` (`object_registry.py:36`). Each entry keyed by resource id. The enforcer precompiles one `Draft202012Validator` per resource **at startup** (`service_enforcer/main.py:21-28`); a schema that fails to compile ⇒ that resource **fails closed** at request time (`500`).

**Per-tool structure:**
```yaml
resources:
  <resource_id>:
    endpoint: "http://<worker-host>:<port>"   # enforcer POSTs {endpoint}/run
    timeout: <float seconds>                   # httpx timeout for the worker call
    description: "<shown to the model as the tool description>"
    schema:                                    # JSON Schema (Draft 2020-12), AUTHORITATIVE
      type: "object"
      properties: { ... }
      additionalProperties: false              # REQUIRED — reject unknown keys
      required: [ ... ]
```

**Real example — `resource_filesystem` (verbatim, this is the template to copy for Kali tools):**
```yaml
  resource_filesystem:
    endpoint: "http://node-fs:8620"
    timeout: 5.0
    description: "Secure sandboxed file I/O. Restricted to specific file types."
    schema:
      type: "object"
      properties:
        action:
          type: "string"
          enum: ["read", "list", "write"]
        path:
          type: "string"
          pattern: "^(?!/)(?!.*\\.\\.)[a-zA-Z0-9_/.-]+(\\.txt|\\.json|\\.log|\\.md|/)?$"
        content:
          type: "string"
          maxLength: 10240
          pattern: "^[\\x20-\\x7E\\n\\r\\t]*$"    # printable ASCII, no NULs
      additionalProperties: false
      required: ["action", "path"]
```
Two more real ones exist: `resource_database` (query `pattern: "(?i)^(SELECT|SHOW|DESCRIBE)\\s+...FROM\\s+..."`, `maxLength: 512`) and `resource_network` (`url` `pattern: "^https://[a-zA-Z0-9.-]+..."`, `enum` method `["GET"]`). Because the validator uses the class directly (not `jsonschema.validate`), **Python inline flags like `(?i)` are honored** and the metaschema self-check is skipped (`service_enforcer/main.py:19-20`). The top-level property names you declare here **become the JSON keys posted to the worker's `/run`** — design them to match your worker's request body (see §8).

---

## 7. security_policy (firewall rules)

File: `config/security_policy.yaml`. Two top-level blocks:
- `system_limits` → `registry.limits`: `max_input_size: 524288`, `max_output_size: 4096`, `token_ttl: 30`, `max_requests_per_min: 10`.
- `semantic_firewall` → `registry.security["semantic_firewall"]`: the rule list.

**Rule format** (one YAML mapping per rule): `{ id: "<RULE_ID>", regex: "<python regex>", action: "BLOCK" }`. Compiled in `securio._compile_firewall` with `re.DOTALL` (so newline-splitting can't bypass length/anchored rules). A rule missing `id`/`rule_id` or `regex` is skipped with a warning. `inspect_payload(content)` raises `ValueError("Firewall Violation: <id>")` on the first `BLOCK` rule whose regex matches. **Only `action: "BLOCK"` is enforced** — any other action value is currently a no-op (see §13). The same firewall runs twice per request: on the **inbound payload** (enforcer step 6) and on the **tool output** (egress DLP, step 8).

**Real rules (verbatim samples across sections):**
```yaml
- { id: "SQLI_UNION",   regex: "(?i)UNION\\s+(ALL\\s+)?SELECT", action: "BLOCK" }
- { id: "SQLI_STACKED", regex: ";\\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)", action: "BLOCK" }
- { id: "RCE_DEVTCP",   regex: "(?i)/dev/(tcp|udp)/", action: "BLOCK" }
- { id: "RCE_NMAP",     regex: "(?i)nmap", action: "BLOCK" }
- { id: "LFI_ETC_FILES",regex: "(?i)/etc/(passwd|shadow|group|hosts|issue|hostname|network|fstab|crontab|sudoers)", action: "BLOCK" }
- { id: "DLP_AWS_KEYS",  regex: "(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})", action: "BLOCK" }
- { id: "SSRF_METADATA_AWS", regex: "(?i)169\\.254\\.169\\.254", action: "BLOCK" }
- { id: "AI_IGNORE",    regex: "(?i)(ignore previous instructions|disregard all prior)", action: "BLOCK" }
```
**Add a rule:** append a mapping to `semantic_firewall` and restart the enforcer/ingress (config is loaded once at boot). **Actual rule count = 112** (verified `grep -cE '^\s*- \{ id:'`): SQLI 29, RCE 28, LFI 20, DLP 14, SSRF 7, FMT 8, AI 6. The in-file section comments claim 30/30/25/20/10/10/10 = 135 and are **inaccurate** (see §13).

> ⚠️ For `node-kali`: many of these rules (`RCE_NMAP`, `RCE_NET_TOOLS`, `RCE_SHELL_BIN`, `RCE_PIPES`, `LFI_*`, `SSRF_*`) will **block legitimate Kali tool arguments**. You will need a per-resource firewall exemption path or a distinct enforcer profile for `node-kali`, because today `inspect_payload` is global and resource-agnostic (§13).

---

## 8. Worker-node contract (template for node-kali)

A worker is a standalone FastAPI app exposing exactly two routes. The enforcer calls it (`service_enforcer/main.py:81-83`):
```python
async with httpx.AsyncClient(timeout=tool_def["timeout"]) as client:
    resp = await client.post(f"{tool_def['endpoint']}/run", json=payload)
    data = resp.json()
```
**Contract a worker MUST implement:**
- `GET /healthz` → `{"status":"ok"}` (used by k8s readiness/liveness probes).
- `POST /run` → accepts the **validated `payload`** (the exact object that passed the resource's JSON Schema; top-level keys == the schema's `properties`), returns a JSON object.
- The enforcer sends the payload as the JSON body **as-is**. So the worker's FastAPI `Body(...)` parameters must line up with the schema's top-level property names. `node-db`/`node-net` use `Body(..., embed=True)` (single key `{"query": ...}` / `{"url": ...}`); `node-fs` uses multiple non-embedded `Body` fields (`action`, `path`, `content`).
- The enforcer does **not** call `raise_for_status()`. A worker HTTP 4xx/5xx **that still returns JSON** is surfaced to the caller as a normal `200` result containing that JSON body; only a thrown exception / non-JSON response becomes `502 Execution node failed` (§13). Design failures as JSON fields if you want them to survive, or rely on the enforcer's schema/firewall to reject bad input before it reaches you.

**node-fs contract (the template — `src/worker_nodes/node_fs.py`, verbatim behavior):**
```python
SANDBOX_DIR = os.getenv("SANDBOX_DIR", "/app/data/sandbox")

def _resolve(path: str) -> str:
    """Resolve inside sandbox, refusing any escape (realpath + os.sep prefix)."""
    root = os.path.realpath(SANDBOX_DIR)
    target = os.path.realpath(os.path.join(root, path.lstrip("/")))
    if target != root and not target.startswith(root + os.sep):
        raise HTTPException(403, "Sandbox violation")     # sibling dir like sandbox_evil also rejected
    return target

@app.post("/run")
def fs_op(action: str = Body(...), path: str = Body(""), content: str = Body(None)):
    if action == "list":  return {"files": os.listdir(_resolve(path or "."))}   # 400 if not a dir
    target = _resolve(path)
    if action == "read":  return {"content": open(target).read()}              # 404 / 400
    if action == "write":                                                       # 400 if content is None
        os.makedirs(os.path.dirname(target), exist_ok=True)
        open(target, "w").write(content)
        return {"status": "written", "bytes": len(content)}
    raise HTTPException(400, "Invalid action")
```
**Sandboxing hook = `_resolve()`**: `os.realpath` resolves symlinks and `..`, and the `root + os.sep` prefix check defeats sibling-prefix escapes (`/app/data/sandbox_evil`). This is the model to copy for `node-kali` — e.g. confine tool working dirs/output to a jailed root, and enforce your own destination allow-list (as `node-net`'s TODO notes: "block SSRF to internal/metadata IPs, pin HTTPS … the node must fail closed on its own").

**node-kali skeleton (follow this shape):**
```python
# src/worker_nodes/node_kali.py
from fastapi import FastAPI, Body, HTTPException
app = FastAPI(title="Kybernos · node-kali", version="6.0")

@app.get("/healthz")
def healthz(): return {"status": "ok"}

@app.post("/run")
def kali_op(tool: str = Body(...), target: str = Body(...), args: list = Body(default=[])):
    # 1. re-validate target against your own allow-list (defense-in-depth; do not trust upstream only)
    # 2. run the tool in a sandbox/namespace with a hard timeout
    # 3. return structured JSON: {"tool":..., "target":..., "stdout":..., "exit_code":...}
    ...
```
…plus a `resource_kali_<tool>` entry in `resource_catalog.yaml` (`endpoint: "http://node-kali:86xx"`, tight `schema` with `additionalProperties:false`), an `allowed_resources` grant in `access_policy.yaml`, and a compose/k8s service on a new port.

---

## 9. Audit JSONL schema (INGRESS/EGRESS)

**Important:** there is **no `.jsonl` file on disk**. Audit entries are emitted by **ingress** (`service_ingress/main.py:18-21`) as **encrypted log lines to stdout**:
```python
def _persist_log(phase, data):
    blob = securio.encrypt_audit_log({"phase": phase, "data": data})
    logger.info("SECURE_LOG::%s", blob)
```
`encrypt_audit_log` (`securio_binding.py:71-81`): `AESGCM(bytes.fromhex(LOG_ENC_KEY_HEX))`, random 12-byte nonce, `base64(nonce || ciphertext)`. Returns `"ERR_NO_KEY"` if no key configured, `"ERR_ENCRYPTION_FAILED"` on error (never crashes the request path). So the **audit stream = container/stdout log lines matching `SECURE_LOG::<base64>`**; `scripts/forensic_auditor.py:196` scrapes them with regex `SECURE_LOG::([a-zA-Z0-9+/=]+)` and decrypts (`data=b64decode; nonce=data[:12]; ct=data[12:]; AESGCM.decrypt`).

**Decrypted plaintext schema** (one JSON object per line — this is what Skepsis's blue plane / evidence ledger consumes after decrypt):
```
{ "phase": <string>, "data": <object> }
```
`phase` ∈ `INGRESS | EGRESS | EGRESS_DENIED`:
- **INGRESS** — `data` = the inbound tool-call: `{"principal", "resource", "payload"}`.
- **EGRESS** — `data` = the enforcer's returned result (worker output, e.g. `{"content": "..."}` or `{"status":"partial","data":"..."}`).
- **EGRESS_DENIED** — `data` = `{"status": <http code>, "detail": <enforcer error text>}`.

**Real (redacted) decrypted lines:**
```json
{"phase":"INGRESS","data":{"principal":"principal_analyst","resource":"resource_filesystem","payload":{"action":"read","path":"notes.txt"}}}
{"phase":"EGRESS","data":{"content":"project notes ...redacted..."}}
{"phase":"EGRESS_DENIED","data":{"status":400,"detail":"Firewall Violation: SQLI_DROP"}}
```
(JSON is serialized with `default=str`, so non-JSON-native values degrade to strings.) There is no dedicated INGRESS/EGRESS *field set* beyond `{phase, data}` — the discriminator is `phase`, and the shape of `data` depends on it. For a stable ledger, key on `phase` and index `data.principal` / `data.resource`.

---

## 10. securio APIs

`src/common/securio_binding.py` — class `SecurioEnforcer`, module singleton `securio`. Reusable independently; it only depends on `pyjwt[crypto]`, `cryptography`, and the config registry (for firewall rules).

| Function | Signature | Purpose |
|---|---|---|
| `sign_jwt` | `sign_jwt(payload: dict) -> str` | ES256 sign with `PRIV_KEY_PATH` P-256 key |
| `verify_jwt` | `verify_jwt(token: str) -> dict` | ES256 verify (alg pinned; require `exp,jti,scope,sub`; leeway 5) |
| `encrypt_audit_log` | `encrypt_audit_log(data: dict) -> str` | AES-256-GCM; returns `base64(nonce(12) ‖ ciphertext)`; `"ERR_NO_KEY"`/`"ERR_ENCRYPTION_FAILED"` on failure |
| `inspect_payload` | `inspect_payload(content: str) -> None` | Semantic-firewall denylist; raises `ValueError("Firewall Violation: <id>")` |
| `_compile_firewall` | (internal) | Compiles `semantic_firewall` rules with `re.DOTALL` |

**Decryption is not in `securio`** — the reference decryptor lives in `scripts/forensic_auditor.py:decrypt_log(blob, key)` (`b64decode → nonce=[:12], ct=[12:] → AESGCM(key).decrypt`). Key material: `PRIV_KEY_PATH` (default `/app/keys/ecdsa_private.pem`), `PUB_KEY_PATH` (`/app/keys/ecdsa_public.pem`), `LOG_ENC_KEY_HEX` (32-byte hex). Reusable pattern for Skepsis: instantiate `SecurioEnforcer` directly, or lift the three primitives (ES256 sign/verify via `pyjwt`, AES-256-GCM via `cryptography.hazmat...AESGCM`) verbatim.

---

## 11. Config pack locations

All under `config/`, loaded at boot by `RuntimeRegistry` (`src/common/object_registry.py`): every `*.yaml|*.yml` is `yaml.safe_load`ed and keyed by filename-without-extension. **Process env is deliberately NOT registered**, so `/runtime/sbom` cannot leak secrets (`object_registry.py:11-15`).

| File | Registry accessor | Contents |
|---|---|---|
| `config/access_policy.yaml` | `registry.access_list` = `access_policy.access_control_list` | RBAC allow-list + `admin` flags (§5) |
| `config/model_inventory.yaml` | `registry.models` = `model_inventory` | `providers:` (type/endpoint/api_key_env) + `models:` (principal → provider + `upstream_model_id`) |
| `config/resource_catalog.yaml` | `registry.resources` = `resource_catalog.resources` | Tool declarations: `endpoint`, `timeout`, `description`, `schema` (§6) |
| `config/security_policy.yaml` | `registry.security` / `registry.limits` | `system_limits` + `semantic_firewall` (§7) |

Mount points: compose mounts `../../config:/app/config:ro` (all services), `../../keys:/app/keys:ro` (registry+enforcer), `../../secrets:/app/secrets:ro` (gateway). k8s: ConfigMap `mcp-config` → `/app/config`, Secrets `mcp-keys`/`mcp-log-key`. `CONFIG_PATH` env overrides the directory (default `/app/config`).

---

## 12. Assurance / test commands

**Full suite (one command):**
```bash
bash scripts/run_tests.sh            # or: --keep-going
```
Runs 5 stages (`scripts/run_tests.sh`): `0· static` (py_compile all sources + YAML validity + corpus load), `1· providers` (adapter units), `2· security pipeline (ZTA)`, `3· gateway agnostic`, `4· end-to-end`. Uses `.venv` if present, forces `KYBERNOS_BANNER=off`.

**The 26 security assertions** = `tests/test_security_pipeline.py`, run standalone:
```bash
python3 tests/test_security_pipeline.py
```
It wires the **real** service apps in-process (fakeredis shared token store + an ASGI `Router` transport so inter-service httpx calls resolve without a network), fires a fake LLM, and asserts **26 checks** (verified by counting): **14** pipeline probes (`PROBES`, FS/RBAC/SQLi/SSRF ALLOW-vs-BLOCK) + **5** gateway auth/SBOM checks (`run_gateway_auth`) + **7** unit checks (`run_units`: 1 firewall newline-bypass + 6 sandbox `_resolve` invariants). Prints `TOTAL: <p> passed, <f> failed` and exits non-zero on any failure — i.e. the "26/26" is a green run of this file.

**Adversarial corpus harness** (the ~3,903 probes):
```bash
# bring the stack up, then replay the verified corpus against LIVE ingress:
python scripts/probe_pipeline.py --base http://localhost:8443
python scripts/probe_pipeline.py --base http://localhost:8443 --category PATH_TRAVERSAL   # filter
python scripts/probe_pipeline.py --base http://localhost:8443 --limit 200                 # cap
# k8s: kubectl -n mcp-secure port-forward svc/service-ingress 8443:8443
```
`scripts/probe_pipeline.py` loads `tests/corpus/probe_corpus.json`, POSTs each `pipeline_probes` entry to `/process`, and compares the live ALLOW/BLOCK to the recorded `verdict`; any mismatch = a **regression** (exit 1). It expands `<REPEAT:c:n>` markers (capped 20 000).

**Where ground-truth verdicts live:** `tests/corpus/probe_corpus.json` (JSON), structure:
- `meta`: `{ "pipeline_verified": 2867, "prompt": 1036, "categories": 30, "false_positives": 0, "bypass_candidates": 53 }`.
- `pipeline_probes` (**2867**): each `{name, principal, resource, payload, expect, control, category, verdict, hypothesis_ok}` — **`verdict` is the ground-truth** ALLOW/BLOCK established against the real pipeline; `control` names the enforcing layer (`schema` | `firewall` | `rbac` | …).
- `prompt_probes` (**1036**): each `{name, prompt, expect, atlas, category}` (`atlas` = MITRE ATLAS technique id, e.g. `AML.T0051.000`). **Total = 2867 + 1036 = 3903.**
- Companion notes: `tests/corpus/coverage_report.md`, `tests/corpus/TRIAGE.md` (documents the 28→0 false-positive tightening, the accepted residual `bypass_candidates`, and the DLP-payload redaction).

There is a second, separate harness `scripts/forensic_auditor.py` (+ `scripts/test_definitions.json`, 10 categories) that runs against a **live Docker stack**, decrypts the `SECURE_LOG::` audit stream, and writes `audit_artifacts/<run>/audit_report.txt|audit_data.json`. It expects `sudo docker compose` and the audit key (see §13 caveat).

---

## 13. Gaps & uncertainties

1. **No git history / no commit id.** `HEAD` is unborn; nothing is committed. Version is only the string `"6.0"` in code + image tag. Cannot cite a commit hash.
2. **Firewall count comment is wrong.** Section headers in `security_policy.yaml` claim 30/30/25/20/10/10/10 = 135; the file actually contains **112** rules (SQLI 29, RCE 28, LFI 20, DLP 14, SSRF 7, FMT 8, AI 6). The "112-rule firewall" figure is correct; the per-section comments are not.
3. **Audit key path mismatch — the forensic harness will not find the key as shipped.** Services read `LOG_ENC_KEY_HEX` (env, written to `deploy/docker/.env` by `gen_keys.sh`). But `forensic_auditor.py` loads the key from a **file** `keys/log_enc.key` (`load_key()` → `bytes.fromhex(open(...).read())`), which `gen_keys.sh` **never creates**. To use the forensic auditor you must manually write the hex key to `keys/log_enc.key`. (The audit *encryption* path in the services is fine; only the decrypt tool's key discovery is inconsistent.)
4. **No literal JSONL audit file.** "Audit JSONL" is an idealization: entries are `SECURE_LOG::<base64>` **log lines**, decrypted to `{phase, data}` objects. Skepsis must scrape stdout/container logs and decrypt; there is no append-only file writer in the code.
5. **Enforcer does not propagate worker HTTP status.** It does `resp.json()` without `raise_for_status()`. A worker returning `403 {"detail":"Sandbox violation"}` is surfaced to the caller as a normal `200` result body `{"detail":"Sandbox violation"}`; only exceptions/non-JSON become `502`. Plan `node-kali` failure signaling as JSON fields, not status codes.
6. **`node-db` and `node-net` are MOCKS.** Both return canned data with `"_warning":"MOCK NODE"` and carry TODOs (read-only DB user / parameterized queries for db; SSRF-safe egress allow-list for net). They are not production connectors. `node-fs` is real.
7. **Firewall is global, `BLOCK`-only, resource-agnostic.** `inspect_payload` applies **all 112 rules** to every payload/output regardless of resource, and only honors `action: "BLOCK"` (other actions are silently no-ops). The code itself states the firewall is **defense-in-depth only** — RBAC + JSON-Schema are authoritative (`securio_binding.py:15-20`). For `node-kali` you will need a resource-scoped firewall profile or exemptions, since Kali arguments will trip `RCE_*`/`SSRF_*`/`LFI_*` rules.
8. **Token is time-boxed, not strictly single-use.** `valid_token:{jti}` is set with `SETEX ttl` but is **not deleted on first use**, so within the ≤30 s window a token could be replayed. Revocation works (`DEL`), and the window is short, but "single-use" is aspirational (the code comment says "single-use-style"). Confirm before relying on one-shot semantics.
9. **`secrets/api_keys.json` in the tree holds placeholder keys** (`KEY_ANALYST` … `KEY_ADMIN`) matching the test harness, **not** real generated `mcp_<hex>` keys. Run `gen_keys.sh` before any real deployment.
10. **`scripts/pipeline_orchestrator.sh` is a stub.** It only `echo`s CI phase names and writes a hardcoded CycloneDX SBOM claiming version `5.1.0` / `mcp_universal_system`. It is not a real supply-chain gate and contradicts the 6.0/Kybernos naming everywhere else.
11. **Ingress `:8443` is not TLS.** Despite the port number, `service_ingress` is a plaintext internal FastAPI/uvicorn service. TLS is terminated by the k8s nginx `Ingress` in front of `service-gateway:8000`; in docker-compose there is no TLS at all (only `8000` is published).
12. **Rate limiter fails open by default.** On Redis error, requests pass unless `RATE_LIMIT_FAIL_CLOSED=true` (`service_gateway/main.py:52-55`). The `valid_token` replay check has no such fallback — if Redis is down, the enforcer denies (fails closed).
13. **The large manuals** (`USER_MANUAL.md` ~186 KB, `DEVELOPER_MANUAL.md` ~256 KB, `README.md`) are derived prose, not consulted for the facts above — everything here is quoted from source/config. If a manual disagrees with code, trust the code.
