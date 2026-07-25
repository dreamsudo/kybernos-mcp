# KYBERNOS — Integration Interface Contract (for Skepsis / `node-kali`)

Extracted from the actual code (not idealized). Repo: `kybernos/`. All endpoints,
schemas, claims, and examples below are real; runtime examples were produced by
running the code. Where something is missing or a gotcha, it is called out in
**§7 Gaps & uncertainties** — read that section before implementing.

Pipeline (each tool call): `gateway → ingress → registry(/authorize, mint token) → enforcer(/execute) → worker(/run)`.

---

## 1. Worker-node contract (`node_fs` template for `node-kali`)

**The enforcer calls the worker at `POST {endpoint}/run`.** `endpoint` comes from the
resource's `resource_catalog` entry (see §2). Source: `src/service_enforcer/main.py:82-84`:

```python
async with httpx.AsyncClient(timeout=tool_def["timeout"]) as client:
    resp = await client.post(f"{tool_def['endpoint']}/run", json=payload)
    data = resp.json()
```

### Request body — what the worker receives
**The raw, already-validated `payload` object, and NOTHING else.** No principal, no
scope, no jti, no auth header, no tool-name wrapper. The tool identity is *implicit
in which endpoint was called*. The args have already passed JSON-Schema validation
(§2) and the inbound firewall before the worker is ever hit.

Real `node_fs` `/run` calls (captured live):

```
POST /run   {"action": "list",  "path": "."}
  -> HTTP 200   {"files": ["notes.txt"]}

POST /run   {"action": "write", "path": "report.txt", "content": "hi"}
  -> HTTP 200   {"status": "written", "bytes": 2}

POST /run   {"action": "read",  "path": "../../../etc/passwd"}
  -> HTTP 403   {"detail": "Sandbox violation"}

POST /run   {"action": "read",  "path": "missing.txt"}
  -> HTTP 404   {"detail": "Not found"}
```

### Response body the worker must return
- **Success:** HTTP `200` with **any JSON object** you like — the enforcer passes it
  back verbatim (subject to egress-DLP + size cap, §6). `node_fs` uses `{"files":[...]}`,
  `{"content":"..."}`, `{"status":"written","bytes":N}`.
- **Error/denial:** raise a FastAPI `HTTPException(status, detail)` → serializes to
  `{"detail": <detail>}` with your status code. **Confirmed: the enforcer now
  surfaces worker `4xx/5xx` instead of laundering to `200`** (`main.py:93-97`):

  ```python
  if resp.status_code != 200:
      detail = data.get("detail") if isinstance(data, dict) else str(data)
      raise HTTPException(resp.status_code if resp.status_code >= 400 else 502,
                          f"Worker node error: {detail}")
  ```
  So a `node-kali` `403`/`400`/`500` propagates out as a real failure the model sees.
  **Only `200` is treated as success.** (A `3xx` is remapped to `502`.)

### `/healthz` contract
`GET /healthz` → `200 {"status": "ok"}`. Used by Docker/K8s readiness probes.
**Best practice (node_fs does this):** return `503` if the node can't actually
serve — node_fs returns `503 {"detail":"sandbox not ready"}` when its sandbox root
isn't a writable dir, so orchestration doesn't route to a broken node.

### Safety hooks a worker MUST implement itself
Workers are the only components holding the dangerous capability, so **each worker
fails closed on its own** — it does not trust that upstream validation is sufficient.
`node_fs`'s hook is the root-escape check (`src/worker_nodes/node_fs.py`):

```python
def _resolve(path: str) -> str:
    root = os.path.realpath(SANDBOX_DIR)
    target = os.path.realpath(os.path.join(root, path.lstrip("/")))   # resolves symlinks + ..
    if target != root and not target.startswith(root + os.sep):
        raise HTTPException(403, "Sandbox violation")
    return target
```

Peers for reference: `node_db` enforces SELECT/WITH-only + read-only session;
`node_net` enforces public-IP-only + HTTPS-only + no-redirects. **`node-kali` must
implement its own equivalent** (allowlist of binaries, arg sanitization, target-scope
enforcement, resource/time caps) — the schema + firewall upstream are defense-in-depth,
not a substitute.

### FastAPI body-binding gotcha (this was a real bug — get it right)
The enforcer POSTs the payload as a top-level JSON object. How you declare the handler
params determines whether FastAPI accepts it:
- **Multiple fields** → use one `Body(...)` per field (FastAPI auto-embeds them as
  top-level keys). `node_fs`: `def fs_op(action: str = Body(...), path: str = Body(""), content: str = Body(None))`.
- **Single field** → you MUST use `Body(..., embed=True)`, else FastAPI expects the raw
  scalar, not `{"field": ...}`. `node_db`: `def db_op(query: str = Body(..., embed=True))`.
  (A missing `embed=True` returns `422`, which — before the enforcer fix — got masked as `200`.)

### `node-kali` skeleton (copy this)
```python
import os, logging
from fastapi import FastAPI, Body, HTTPException
app = FastAPI(title="Kybernos · node-kali", version="1.0")
logger = logging.getLogger("node-kali")
ALLOWED = {"nmap", "gobuster", "sqlmap"}          # your binary allowlist

@app.get("/healthz")
def healthz(): return {"status": "ok"}

@app.post("/run")
def run(tool: str = Body(...), args: list = Body(default=[]), target: str = Body("")):
    if tool not in ALLOWED:
        raise HTTPException(403, f"tool not permitted: {tool}")   # -> enforcer surfaces 403
    # ... your own scope/target/arg validation here (fail closed) ...
    # ... execute with a hard timeout; capture stdout ...
    return {"tool": tool, "exit_code": 0, "stdout": "...", "truncated": False}
```

---

## 2. resource_catalog — declare a tool + route it to a worker

**File:** `config/resource_catalog.yaml` (YAML). Loaded at boot into
`registry.resources` via `object_registry.py` (`resources = catalog["resources"]`).

**Shape:** top-level `resources:` map; each key is the **resource id** (this string is
*also the token `scope`*, see §3). Per-resource fields:

| Field | Meaning |
|---|---|
| `endpoint` | **Routing.** Base URL of the worker; enforcer calls `{endpoint}/run`. This is what binds `resource X → node-kali`. |
| `timeout` | Seconds the **enforcer** waits on the worker call (per-resource). |
| `description` | Also surfaced to the model as the tool description. |
| `schema` | JSON-Schema (Draft 2020-12) validated **authoritatively** by the enforcer against the payload. |

Real entry (copy as template — this is `resource_filesystem`):

```yaml
resources:
  resource_filesystem:
    endpoint: "http://node-fs:8620"          # <-- routes to the worker
    timeout: 5.0
    description: "Secure sandboxed file I/O. Restricted to specific file types."
    schema:
      type: "object"
      properties:
        action: { type: "string", enum: ["read", "list", "write"] }
        path:   { type: "string", pattern: "^(?!/)(?!.*\\.\\.)[a-zA-Z0-9_/.-]+(\\.txt|\\.json|\\.log|\\.md|/)?$" }
        content:{ type: "string", maxLength: 10240, pattern: "^[\\x20-\\x7E\\n\\r\\t]*$" }
      additionalProperties: false            # confirmed: set on all resources
      required: ["action", "path"]
```

- **`additionalProperties: false`** is present on every resource — unknown args are
  rejected (`400`). Keep it on `node-kali` resources.
- **Per-field `maxLength`** is set inside each property (`content` 10240, `query` 512,
  `url` 256). This bounds **input args only**, not worker output (see §6).
- **Routing a new tool to `node-kali`:** add a resource with `endpoint: "http://node-kali:8640"`.
  **Multiple resources may share one endpoint** — e.g. `resource_kali_nmap` and
  `resource_kali_sqlmap` can both point at `node-kali`, which dispatches on the payload.
  This is also how you get **distinct scopes for RBAC** (red vs blue — see §3/§5).

Example `node-kali` resources:
```yaml
  resource_kali_recon:                       # grant to blue/analyst principals
    endpoint: "http://node-kali:8640"
    timeout: 300.0                           # nmap is slow — BUT see §7 ingress 30s ceiling
    description: "Passive/active recon (nmap, whatweb) against in-scope targets."
    schema:
      type: "object"
      properties:
        tool:   { type: "string", enum: ["nmap", "whatweb"] }
        target: { type: "string", maxLength: 253, pattern: "^[a-zA-Z0-9_.:-]+$" }
        args:   { type: "array", items: { type: "string", maxLength: 64 }, maxItems: 20 }
      additionalProperties: false
      required: ["tool", "target"]
  resource_kali_exploit:                     # grant ONLY to red principals
    endpoint: "http://node-kali:8640"
    timeout: 600.0
    description: "Active exploitation (sqlmap, hydra) against in-scope targets."
    schema: { ... }
```

---

## 3. Capability token — ES256 claims, minting, single-use across a workflow

### Claims (exact)
Minted in `src/service_registry/main.py:34-41`. Real (redacted) decoded payload:

```json
{
  "sub":   "principal_analyst",             // authenticated principal (from API key)
  "scope": "resource_filesystem",           // == the resource id being authorized
  "jti":   "660b6a23e00195e15a9a0680823ded56",  // os.urandom(16).hex()
  "iat":   1784952703,
  "nbf":   1784952703,
  "exp":   1784952733                        // iat + token_ttl (default 30s)
}
```
JWT header: `{"alg":"ES256","typ":"JWT"}`. No other claims. `scope` is a **flat exact
string equal to the resource id** — there is no hierarchical grammar; the enforcer does
`claims["scope"] != resource_id → 403` (`enforcer/main.py:56`). **To scope red vs blue,
you use distinct resource ids + RBAC (§5), not scope wildcards.**

### Minting (registry) — `POST /authorize`
Input JSON `{"principal": <str>, "resource": <str>}` (principal is server-set, never
client-supplied). It (1) RBAC-checks `resource ∈ access_list[principal].allowed_resources`
(`403` otherwise), (2) mints the JWT, (3) `SETEX valid_token:{jti} = 1` with TTL =
`token_ttl` (30s), (4) returns `{"token": "<jwt>", "resource": "<resource>"}`.

### Verifying (enforcer) — `securio_binding.py:61-68`
```python
jwt.decode(token, PUB_KEY, algorithms=["ES256"],           # alg pinned — no confusion
           options={"require": ["exp","jti","scope","sub"]}, leeway=5)  # 5s clock skew
```
Then a **single-use consume**: `redis_conn.getdel(f"valid_token:{jti}")` — if it returns
nothing, `401 "Token revoked, expired, or already used"`. Then `scope == resource` check.

### Single-use × multi-step workflow (nmap → gobuster → sqlmap)
**Each tool call needs its own fresh token — and the gateway does this automatically.**
There is no session and no batching. Every call runs the full `ingress → /authorize
(fresh mint) → /execute (getdel consume)` cycle, so RBAC is re-checked on *every* call.
A 3-step Kali workflow = 3 independent mint→consume cycles. The agent/Skepsis does **not**
manage tokens — it just makes 3 tool calls; the gateway's bounded agentic loop
(`MAX_TOOL_ROUNDS`, default 4) mints per call. **Caveat:** the token is consumed
(`getdel`) *before* the worker runs, so if a Kali tool errors/times out, that token is
already spent — a retry is simply a new tool call (new mint), which is automatic. Also:
`token_ttl` is 30s, so mint→execute must complete within 30s of minting (this is the
authorize→execute window, not the tool runtime — but see the ingress timeout in §7).

---

## 4. Audit JSONL schema (INGRESS / EGRESS)

**Reality check:** there is **no `.jsonl` file, no rotation, and no stream/tail API.**
Audit events are emitted as **Python log lines to stdout** by `src/service_ingress/main.py`:

```python
def _persist_log(phase, data):
    blob = securio.encrypt_audit_log({"phase": phase, "data": data})
    logger.info("SECURE_LOG::%s", blob)      # one line per event, to the ingress log/stdout
```

Three phases are emitted, all from ingress (`main.py:31,46,51`):
- `INGRESS` — the full inbound `{principal, resource, payload}` (logged before auth).
- `EGRESS` — the successful tool result (the worker's response object).
- `EGRESS_DENIED` — `{"status": <code>, "detail": <text>}` when the enforcer returns non-200.

### On-disk form = **ciphertext**, not plaintext JSON
`encrypt_audit_log` (`securio_binding.py:71-81`): `base64( nonce[12] || AES-256-GCM(
json.dumps({"phase","data"}) ) )`, key = `LOG_ENC_KEY_HEX` (32-byte hex). If the key is
unset it emits the literal `ERR_NO_KEY`. So a consumer sees lines like:

```
SECURE_LOG::mXGLI/nwj02yd//xAegTaXXzno1LOkhfBZ2uze1I....   (base64 ciphertext)
```

### How a consumer reads it (decrypt round-trip, verified)
```python
import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
raw = base64.b64decode(line_after_prefix)
nonce, ct = raw[:12], raw[12:]
entry = json.loads(AESGCM(bytes.fromhex(LOG_ENC_KEY_HEX)).decrypt(nonce, ct, None))
```

Decrypted entries (real):
```json
{"phase":"INGRESS","data":{"principal":"principal_analyst","resource":"resource_filesystem","payload":{"action":"list","path":"."}}}
{"phase":"EGRESS","data":{"files":["notes.txt"]}}
{"phase":"EGRESS_DENIED","data":{"status":403,"detail":"Worker node error: Sandbox violation"}}
```
**Field types:** `phase` ∈ {`INGRESS`,`EGRESS`,`EGRESS_DENIED`} (str); `data` is an
arbitrary object — for INGRESS it is exactly `{principal:str, resource:str, payload:obj}`;
for EGRESS it is the worker's result object; for EGRESS_DENIED it is `{status:int, detail:str}`.
There is **no timestamp, request-id, or principal inside EGRESS** — see §7.

---

## 5. RBAC / access_policy (role → scope mapping)

**File:** `config/access_policy.yaml` (YAML) → `registry.access_list` =
`access_policy["access_control_list"]`. Real content:

```yaml
access_control_list:
  principal_analyst:
    allowed_resources: ["resource_filesystem", "resource_database"]
  principal_auditor:
    allowed_resources: ["resource_database"]
  principal_netbot:
    allowed_resources: ["resource_network"]
  principal_admin:
    admin: true                                   # also unlocks GET /runtime/sbom
    allowed_resources: ["resource_filesystem", "resource_database", "resource_network"]
```

- Map = `principal → { allowed_resources: [resource_id, ...], admin?: bool }`.
- **Enforced twice:** the gateway only advertises the principal's allowed resources as
  tools, and the registry re-checks `resource ∈ allowed_resources` at every `/authorize`
  (`403` otherwise). Optional `admin: true` gates the `/runtime/sbom` disclosure endpoint.
- **For Skepsis red/blue:** define principals like `principal_red`, `principal_blue`; grant
  `resource_kali_exploit` only to red, `resource_kali_recon` to both. Scope == resource id,
  so this *is* the red/blue capability boundary.

### Principal derivation (never trusts the client)
`src/common/auth.py` — `ApiKeyAuthenticator`. The API key comes from the `X-API-Key`
header (or `Authorization: Bearer <key>`), matched constant-time (`hmac.compare_digest`)
against a `{api_key: principal}` map loaded from `AUTH_KEYS_JSON` (env) or `AUTH_KEYS_PATH`
(default `/app/secrets/api_keys.json`, a mounted Secret). **Confirmed: identity is ONLY the
resolved principal; `body.model` / any client-supplied identity is never trusted** (that was
the documented v1–v5 flaw). Unknown key → `401`.

---

## 6. Schema vs firewall size limits (large Kali output)

### Check order (enforcer, `execute_tool`)
1. verify token (§3) → 2. `getdel` single-use → 3. `scope == resource` → 4. **JSON-Schema
validate the payload** (`400` on fail) → 5. **inbound firewall** `inspect_payload(str(payload))`
(`400`) → 6. **run worker** `{endpoint}/run` → 6b. surface worker non-200 → 7. **egress-DLP
firewall** `inspect_payload(str(data))` (`502`) → 8. **output size cap** (truncate).

### Where each limit lives
| Limit | Value | File / location | Applies to | Per-resource? |
|---|---|---|---|---|
| per-field `maxLength` | e.g. `content` 10240 | `resource_catalog.yaml` schema | **input args only** | ✅ yes |
| `max_input_size` | 524288 (512 KiB) | `security_policy.yaml → system_limits` | whole request body (gateway) | ❌ global |
| `FMT_OVERFLOW` | `.{8193,}` → BLOCK | `security_policy.yaml → semantic_firewall` | `str(payload)` **and** `str(data)` (in + egress) | ❌ **global** |
| `max_output_size` | 4096 | `security_policy.yaml → system_limits` | worker output (truncates) | ❌ **global** |

### The large-output problem, precisely
Kali stdout is big. It hits the **output** path (steps 7–8):
- **Step 7 (egress DLP):** runs the *whole firewall* over `str(data)`, including
  `FMT_OVERFLOW = .{8193,}`. **Any worker output > 8192 chars → `502 "Response blocked by
  egress DLP: Firewall Violation: FMT_OVERFLOW"`.** This is a hard block, not a truncation.
- **Step 8 (size cap):** even if it passed, `max_output_size = 4096` → the enforcer returns
  `{"status":"partial","data": str(data)[:4096]}` (silent truncation to 4 KiB).

**So today, large tool output is doubly constrained, and both knobs are GLOBAL — there is
no per-resource override.** To allow big `node-kali` output you must do one (or more) of:
1. **Raise `FMT_OVERFLOW`'s threshold** in `security_policy.yaml` (e.g. `.{1048577,}`) —
   affects *every* resource. This is the deferred design decision "BH-7" (see `tests/corpus/TRIAGE.md`).
2. **Raise `max_output_size`** in `system_limits` (e.g. to 1 MiB) — global; it truncates rather than blocks.
3. **`EGRESS_DLP=false`** (enforcer env) — skips step 7 entirely (disables output secret-scanning
   globally — heavy hammer; you lose DLP on *all* resources).

**Recommended for Skepsis:** have `node-kali` **cap/paginate its own stdout** and return a
bounded field (like `node_net`'s `truncated` flag) so you don't rely on raising global limits;
if you need full output, the clean fix is a **per-resource output policy in Kybernos** — which
does not exist yet (§7).

---

## 7. Gaps & uncertainties (read before implementing `node-kali`)

1. **Worker gets NO identity/context.** `/run` receives only the validated `payload` —
   no principal, scope, jti, or headers. `node-kali` **cannot tell red from blue** from the
   request. Encode that distinction in **separate resource ids** (`resource_kali_recon` vs
   `resource_kali_exploit`) gated by RBAC (§5). If `node-kali` needs the caller identity for
   its *own* logging/scoping, Kybernos must be changed to forward it (not currently done).

2. **⚠️ Hardcoded 30 s timeout in ingress will strangle long Kali tools.**
   `src/service_ingress/main.py` wraps *both* the registry and enforcer calls in
   `httpx.AsyncClient(timeout=30.0)` — a literal, not configurable. So even if a resource's
   `timeout` is `600.0` and the enforcer waits, **ingress aborts the whole call at 30 s**.
   nmap/sqlmap/hydra routinely exceed this. **This is a required Kybernos change for Skepsis:**
   make the ingress→enforcer timeout configurable (and ≥ the resource `timeout`). Chain of
   timeouts today: gateway→ingress `UPSTREAM_TIMEOUT` (env, default 120 s) → ingress→enforcer
   **30 s hardcoded** → enforcer→worker `tool_def["timeout"]` (per-resource). Effective ceiling = 30 s.

3. **No live audit stream/API and no `.jsonl` file.** Audit is `logger.info("SECURE_LOG::<b64
   ciphertext>")` to stdout only — no file path, no rotation, no tail endpoint. Skepsis's blue
   plane must scrape the ingress container's stdout, regex `SECURE_LOG::(\S+)`, base64-decode,
   and AES-256-GCM-decrypt with `LOG_ENC_KEY_HEX`. A real event bus / tail API would need to be
   added to Kybernos.

4. **Audit entries lack metadata.** No timestamp, request-id, or correlation id in the entry
   body (only `phase` + `data`); `EGRESS`/`EGRESS_DENIED` do **not** carry the principal or
   resource (only `INGRESS` does), so correlating an ingress to its egress requires ordering/
   timing, not an id. If the ledger needs joins, add a request id upstream.

5. **`FMT_OVERFLOW` / `max_output_size` are global, not per-resource** (§6). There is no
   per-resource output-size policy. Supporting large Kali output cleanly is a Kybernos feature
   gap, not just config.

6. **Single-use token is consumed *before* the worker runs** (`getdel` at step 2, worker at
   step 6). A worker crash/timeout still spends the token; retries need a fresh authorize
   (automatic via the gateway loop, but not idempotent — a partially-run Kali tool is not
   rolled back).

7. **The DB resource's schema regex is stricter than `node_db`'s own guard.** The enforcer
   schema (`resource_catalog.yaml`) is the binding gate on input; don't assume the worker's
   internal guard is what limits callers. For `node-kali`, the **`resource_catalog` schema is
   authoritative on input** — put your real arg constraints there, and re-validate in the worker.

8. **`node_fs` write path has one unwrapped `os.makedirs`** (could surface as `500`) — not
   relevant to `node-kali` unless you copy the FS write pattern; mentioned for completeness.
