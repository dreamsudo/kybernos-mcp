# Kybernos — User Manual

> Installation, choosing your model, authentication, API usage, provider setup, and operations for users and operators.
> **Version:** v6.0 · **Model-agnostic** (Anthropic-optimized) zero-trust LLM tool-call gateway

## Table of Contents

1. [Introduction](#introduction)
2. [Installation and First Run](#installation-and-first-run)
3. [Choosing and Configuring Your Model](#choosing-and-configuring-your-model)
4. [Authentication and API Keys](#authentication-and-api-keys)
5. [Using the API](#using-the-api)
6. [Principals and Permissions](#principals-and-permissions)
7. [Tools and What They Accept](#tools-and-what-they-accept)
8. [Admin and Operations](#admin-and-operations)
9. [Understanding Responses and Errors](#understanding-responses-and-errors)
10. [Provider Setup Guides](#provider-setup-guides)
11. [Running on Kubernetes](#running-on-kubernetes)
12. [Security, Privacy, and FAQ](#security-privacy-and-faq)

---

## Introduction

Kybernos is a **model-agnostic, zero-trust gateway that brokers the tool calls an LLM wants to make**. It sits directly between a model and the real tools that model can reach — the filesystem, a database, the network — and forces every single tool call through a fixed security pipeline before anything actually runs:

```
authenticate → authorize → mint scoped capability token → validate (JSON-Schema)
→ enforce (firewall) → sandboxed execute → egress-DLP → audit
```

Two ideas define the product:

1. **One API, any model.** Clients always speak the OpenAI Chat Completions protocol (`POST /v1/chat/completions`). Behind that edge you can run **Anthropic** (native, optimized), **OpenAI**, or a **local/self-hosted** model (Ollama, vLLM, LM Studio, LiteLLM, Together, Groq, …). Switching providers changes nothing on the client and nothing about the security controls.
2. **Zero trust on every tool call.** Identity comes from an **API key, never the request body**. Even a fully "jailbroken" model cannot escalate: the pipeline authorizes against a fixed policy, mints a short-lived scoped token, validates the payload against an authoritative schema, runs a semantic firewall, executes inside a sandbox, and scrubs the response — recording an encrypted audit trail the whole way.

### Who it is for

| Audience | What they get |
|---|---|
| **Application / agent developers** | A single stable OpenAI-compatible endpoint. Point your existing OpenAI SDK at the gateway and get tool-calling with guardrails, no per-provider code. |
| **Platform / security operators** | A ZTA control plane (RBAC, capability tokens, JSON-Schema validation, semantic firewall, egress DLP, encrypted audit) that is **provider-independent** — provider swaps never weaken the NIST-style controls. |
| **AI red-teamers / auditors** | A deterministic, replayable pipeline with a verified probe corpus and an LLM-driven forensic auditor. |

### Where it sits

```mermaid
flowchart LR
    Client["Client / Agent (OpenAI SDK)"] -->|"POST /v1/chat/completions"| GW["service-gateway :8000 (edge, only public)"]
    GW -->|"native request via adapter"| LLM["LLM provider (Anthropic / OpenAI / local)"]
    LLM -->|"tool_calls"| GW
    GW -->|"{principal, resource, payload}"| CTRL["Control plane (ingress / registry / enforcer)"]
    CTRL -->|"POST /run"| WORK["Sandboxed workers (node-fs / node-db / node-net)"]
    WORK -->|"result"| CTRL
    CTRL -->|"tool result"| GW
    GW -->|"chat.completion"| Client
    CTRL -.->|"encrypted audit"| STATE["redis-store :6379"]
```

The gateway is the **only** externally reachable service. The model is treated as untrusted: it can *request* a tool call, but the gateway — not the model — decides who the caller is and whether the call is allowed.

### Core concepts

| Concept | Plain-language meaning |
|---|---|
| **Gateway** | The edge service (`service-gateway :8000`). Authenticates the caller, talks to the LLM, and pushes every tool call into the security pipeline. The only public endpoint. |
| **Principal** | *Who* is calling, derived **only** from the API key (`Authorization: Bearer <key>` or `X-API-Key: <key>`) — never from the request body. Example principals: `principal_analyst`, `principal_auditor`, `principal_netbot`, `principal_admin`. |
| **Provider** | *Which model backend* serves a principal — an Anthropic, OpenAI, or local endpoint. Selected server-side from `model_inventory.yaml`; clients never choose it. |
| **Resource / tool** | A real capability the model can invoke: `resource_filesystem` (node-fs), `resource_database` (node-db), `resource_network` (node-net). Each has a strict JSON Schema. |
| **Capability** | A short-lived **ES256 JWT capability token** minted per authorized call (`sub`, `scope`, `jti`, `iat`, `nbf`, `exp`), tracked in Redis for replay/revocation. `scope` must equal the target resource. |
| **Sandbox** | Where tool execution actually happens. `node-fs` runs under a locked sandbox root (`/app/data/sandbox`, or `SANDBOX_DIR`) with realpath escape checks; `node-db` is a read-only SQL connector (single-SELECT guard, driver-enforced read-only) and `node-net` is an SSRF-safe HTTPS egress fetcher (public-IP-only, no redirect-following). |
| **Audit** | Encrypted, tamper-evident log (AES-256-GCM) written at ingress and egress for every brokered call. |

### Model-agnostic by design

The **edge is always OpenAI-compatible**. Internally, a provider **adapter layer** (`src/common/providers.py`, `get_adapter(provider_type)`) translates only the model wire format:

```mermaid
flowchart TB
    subgraph edge["Uniform edge — OpenAI chat format"]
      req["/v1/chat/completions request"]
      resp["chat.completion response"]
    end
    req --> A{"get_adapter(provider_type)"}
    A -->|"type == anthropic"| AN["AnthropicAdapter → POST /v1/messages (x-api-key + anthropic-version)"]
    A -->|"everything else"| OA["OpenAIAdapter → POST /v1/chat/completions (Bearer)"]
    AN -->|"normalize tool_use → tool_calls"| resp
    OA -->|"near passthrough"| resp
```

| `type` value | Adapter | Wire behavior |
|---|---|---|
| `anthropic` | `AnthropicAdapter` | Native Anthropic Messages API: `POST /v1/messages`, headers `x-api-key` + `anthropic-version`, required `max_tokens`, system prompt lifted to a top-level `system` field, tools mapped to `name`/`description`/`input_schema`, tool calls returned as `tool_use` blocks and sent back as `tool_result` blocks. Optional optimizations: `thinking` (adaptive thinking) and `effort` (→ `output_config.effort`). Responses are **normalized back** to an OpenAI `chat.completion`. |
| `openai`, `local`, `ollama`, `vllm`, `lmstudio`, `litellm`, `together`, `groq`, … (any other) | `OpenAIAdapter` | Near-passthrough OpenAI `/v1/chat/completions`, `Bearer` auth from `api_key_env`. `NULL_KEY` means send no `Authorization` header. |

**Critical:** adapters translate *only* the wire format. RBAC, capability tokens, JSON-Schema validation, firewall, egress DLP, and audit all run **downstream** on `{principal, resource, payload}` and are fully provider-independent. Changing your model never changes your zero-trust controls. The gateway also runs a **bounded agentic tool loop** — `MAX_TOOL_ROUNDS` (default `4`); after the budget it forces a final answer with tools removed.

### Provider configuration samples

Providers live in `config/model_inventory.yaml`. Each entry under `providers` has a `type`, `endpoint`, and `api_key_env`; Anthropic providers may add `anthropic_version`, `max_tokens`, `thinking`, `effort`. The `models` block maps each **principal → provider + `upstream_model_id`**. Use current Claude IDs: `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5`.

**1) Anthropic (optimized)** — native Messages API with adaptive thinking:

```yaml
# config/model_inventory.yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true          # optional -> adaptive thinking
    # effort: ...           # optional -> output_config.effort

models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
```

**2) OpenAI** — passthrough Chat Completions:

```yaml
providers:
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY

models:
  principal_analyst:
    provider: provider_openai
    upstream_model_id: gpt-4o        # your chosen OpenAI model
```

**3) Local — Ollama** (the shipped default) — OpenAI-compatible, no auth header:

```yaml
providers:
  provider_local:
    type: openai            # any non-anthropic type uses OpenAIAdapter
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY   # NULL_KEY -> send no Authorization header

models:
  principal_analyst:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

**4) Local — vLLM** — same adapter, self-hosted OpenAI-compatible server (example host/port; keep it off the gateway's `:8000`):

```yaml
providers:
  provider_vllm:
    type: vllm              # treated as openai
    endpoint: http://vllm-host:8000/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_analyst:
    provider: provider_vllm
    upstream_model_id: mistral:7b-instruct
```

**5) LiteLLM proxy** — front many models behind one OpenAI-compatible URL (example proxy address):

```yaml
providers:
  provider_litellm:
    type: litellm           # treated as openai
    endpoint: http://litellm-proxy:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY   # or NULL_KEY if the proxy is unauthenticated

models:
  principal_netbot:
    provider: provider_litellm
    upstream_model_id: gpt-4o
```

**6) Mixed fleet** — different principals on different providers at the same time. The security pipeline is identical for all of them:

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
  provider_local:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_admin:                       # premium Anthropic path
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
  principal_analyst:                     # balanced Anthropic path
    provider: provider_anthropic
    upstream_model_id: claude-sonnet-5
  principal_auditor:                      # hosted OpenAI
    provider: provider_openai
    upstream_model_id: gpt-4o
  principal_netbot:                       # cheap local model
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

Provider secrets are supplied through the environment (`ANTHROPIC_API_KEY`, `REMOTE_API_KEY`) — carried by `deploy/docker/.env` or the `mcp-provider` Kubernetes Secret — and are referenced only by the `api_key_env` name. They are **never** written into config or the SBOM.

### Your first call

The client experience is the same no matter which provider a principal is mapped to. Identity is the API key; the gateway resolves the model for you.

Check health:

```bash
curl -sS http://localhost:8000/healthz
```

Make a tool-enabled chat request — note there is **no model or identity in the body**; the authenticated principal determines both:

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "List the files available to me."}
    ]
  }'
```

The gateway authenticates the key → resolves `principal_analyst` → picks its provider/model/adapter → runs the bounded tool loop, sending each tool call through the full ZTA pipeline → returns a standard OpenAI `chat.completion`. Swap `$ANALYST_API_KEY` for a different principal's key and the same request may run on a different model with different tool permissions — with **zero client changes**.

> Because identity is bound to the API key (`hmac.compare_digest` lookup), any `user`/identity field a model or caller tries to smuggle into the JSON body is ignored for authorization. This is what makes the "one API, any model" promise safe.

### Trust zones at a glance

A default-deny NetworkPolicy makes each service reachable **only** by its legitimate caller; only the gateway is externally reachable.

```
edge     ── service-gateway  :8000   (only public: /healthz, /v1/chat/completions, /runtime/sbom [admin])
control  ── service-ingress  :8443   (/process)
            service-registry :8500   (/authorize — RBAC + capability tokens)
            service-enforcer :8650   (/execute — validate + firewall + exec + egress DLP)
worker   ── node-fs          :8620   (sandboxed filesystem)
            node-db          :8610   (read-only SQL)
            node-net         :8630   (SSRF-safe HTTP)
state    ── redis-store      :6379   (rate limits, token registry, audit)
```

The remainder of this manual details each stage of the request lifecycle, the RBAC and capability model, resource schemas, the semantic firewall and egress DLP, deployment (Docker and Kubernetes), and the test/probe tooling. If you only remember two things from this Introduction: **clients always speak OpenAI to `:8000`**, and **the model never gets to decide who you are or what you may touch**.

---

## Installation and First Run

This section takes you from a clean checkout to a **live, verified gateway** answering `POST /v1/chat/completions` on port `8000`. The first run brings up all eight services (edge + control + workers + state) with zero-trust defaults already enabled, wires them to **one model backend of your choice** (Anthropic, OpenAI, or a local/OpenAI-compatible server), and confirms health.

Because the edge is always OpenAI-Chat-Completions-compatible, **your clients never change** when you switch backends. Only `config/model_inventory.yaml` and one key in `deploy/docker/.env` differ between an Anthropic deployment and a local Ollama deployment.

---

### 1. Prerequisites

| Requirement | Why it is needed | Notes |
|---|---|---|
| **Docker Engine + Docker Compose v2** | Runs the whole stack from `deploy/docker/docker-compose.yml` | Pods run non-root (uid 1000), read-only rootfs |
| **OpenSSL / bash** | `scripts/gen_keys.sh` mints the ES256 keypair, log-encryption key, and principal API keys | Ships with most Linux/macOS shells |
| **`curl`** (or any HTTP client) | Health check + first chat-completion smoke test | Any client works |
| **A model backend** — pick **one** to start | The gateway must have an upstream LLM to broker | See the three options below |

Choose exactly one backend for the first run (you can add more later — see the mixed-fleet sample):

| Backend | What you need | `api_key_env` used |
|---|---|---|
| **Anthropic (optimized)** | An `ANTHROPIC_API_KEY` | `ANTHROPIC_API_KEY` |
| **OpenAI** | A `REMOTE_API_KEY` (your OpenAI key) | `REMOTE_API_KEY` |
| **Local (Ollama / vLLM / LM Studio / LiteLLM …)** | A running OpenAI-compatible server, no cloud key | `NULL_KEY` (no `Authorization` header sent) |

> The default `config/model_inventory.yaml` ships with `provider_anthropic`, `provider_openai`, and `provider_local` already defined, so any of the three works out of the box once its key (if any) is present.

**Service / port map you are about to launch** (only the gateway is externally reachable):

```
edge     service-gateway   :8000   <- ONLY public port (GET /healthz, POST /v1/chat/completions)
control  service-ingress   :8443   POST /process
         service-registry  :8500   POST /authorize   (RBAC + ES256 token mint)
         service-enforcer  :8650   POST /execute     (schema + firewall + exec)
worker   node-fs           :8620   POST /run   (sandboxed filesystem)
         node-db           :8610   POST /run   (read-only SQL)
         node-net          :8630   POST /run   (SSRF-safe HTTP)
state    redis-store       :6379   rate limits, token replay/revocation
```

---

### 2. Startup sequence (what the first run does)

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Repo as "repo checkout"
    participant Keys as "scripts/gen_keys.sh"
    participant Env as "deploy/docker/.env"
    participant Compose as "docker compose"
    participant Redis as "redis-store :6379"
    participant Ctrl as "control (ingress/registry/enforcer)"
    participant Work as "workers (node-fs/db/net)"
    participant GW as "service-gateway :8000"

    Op->>Repo: git clone / cd
    Op->>Keys: run gen_keys.sh
    Keys-->>Op: print principal API keys ONCE (save them)
    Keys->>Env: write LOG_ENC_KEY_HEX
    Keys->>Repo: write keys/ + secrets/api_keys.json
    Op->>Env: set ANTHROPIC_API_KEY (or REMOTE_API_KEY)
    Op->>Compose: up --build
    Compose->>Redis: start (state)
    Compose->>Ctrl: start (mount config/secrets/keys read-only)
    Compose->>Work: start (sandbox root /app/data/sandbox)
    Compose->>GW: start (publish :8000)
    Op->>GW: GET /healthz
    GW-->>Op: "200 healthy"
```

---

### 3. Step-by-step

#### Step 3.1 — Get the code

```bash
git clone <your-repo-url> kybernos
cd kybernos
```

All commands below are run **from the repository root**.

#### Step 3.2 — Generate keys and secrets

`scripts/gen_keys.sh` provisions every cryptographic material the stack needs and **nothing is committed**:

- ES256 keypair → `keys/` (used by `securio_binding.py` for JWT sign/verify; `PRIV_KEY_PATH` / `PUB_KEY_PATH`)
- `LOG_ENC_KEY_HEX` → written into `deploy/docker/.env` (AES-256-GCM audit-log encryption)
- Principal API keys → `secrets/api_keys.json` (the `api_key → principal` map loaded by `auth.py`)

```bash
scripts/gen_keys.sh
```

> ⚠️ **SAVE THE PRINTED API KEYS NOW.** The script prints the principal API keys **exactly once** to your terminal and does not store them in plaintext anywhere else. These are the client credentials your callers use as `Authorization: Bearer <key>`. If you lose them, re-run `gen_keys.sh` (which rotates them) and redistribute.

Expected artifacts after this step:

```
keys/                     # ES256 private + public key (mounted read-only)
secrets/api_keys.json     # api_key -> principal map (mounted read-only)
deploy/docker/.env        # now contains LOG_ENC_KEY_HEX=<hex>
```

The generated `secrets/api_keys.json` maps each key to one of the shipped principals defined in `config/access_policy.yaml`:

| Principal | Allowed resources | Admin? |
|---|---|---|
| `principal_analyst` | filesystem, database | no |
| `principal_auditor` | database | no |
| `principal_netbot` | network | no |
| `principal_admin` | filesystem, database, network | **yes** (unlocks `GET /runtime/sbom`) |

#### Step 3.3 — Set your provider key in `.env`

`gen_keys.sh` already wrote `LOG_ENC_KEY_HEX`. Now add the key for the backend you chose. `deploy/docker/.env` carries exactly three provider-relevant values: `LOG_ENC_KEY_HEX`, `ANTHROPIC_API_KEY`, `REMOTE_API_KEY`.

**Anthropic (optimized path):**

```bash
# deploy/docker/.env
LOG_ENC_KEY_HEX=<generated by gen_keys.sh — do not edit>
ANTHROPIC_API_KEY=sk-ant-...your-key...
REMOTE_API_KEY=                 # leave blank for an Anthropic-only run
```

**OpenAI:**

```bash
# deploy/docker/.env
LOG_ENC_KEY_HEX=<generated by gen_keys.sh>
REMOTE_API_KEY=sk-...your-openai-key...
ANTHROPIC_API_KEY=              # leave blank for an OpenAI-only run
```

**Local (Ollama / vLLM / LM Studio):** no cloud key is required. The `provider_local` entry uses `api_key_env: NULL_KEY`, which tells the OpenAI adapter to **send no `Authorization` header**. First make sure your local server is running and the model is pulled, e.g. for Ollama:

```bash
ollama serve                       # in a separate terminal
ollama pull mistral:7b-instruct    # matches provider_local's upstream_model_id
```

Then `deploy/docker/.env` only needs the log key (both provider keys may stay blank):

```bash
# deploy/docker/.env
LOG_ENC_KEY_HEX=<generated by gen_keys.sh>
```

> The default `provider_local` endpoint is `http://host.docker.internal:11434/v1/chat/completions`, which lets the containerized gateway reach an Ollama server running on your host.

#### Step 3.4 — (Optional) confirm which principal talks to which model

Identity is resolved from the **authenticated API key**, and the gateway maps that principal to a provider + model via `config/model_inventory.yaml`. Confirm the mapping matches your chosen backend before launch. The default set:

```yaml
# config/model_inventory.yaml (shipped defaults)
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
  provider_local:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
```

Provider-selection samples for each use case are in [Step 6](#6-provider-configuration-samples) below.

#### Step 3.5 — Launch with Docker Compose

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Compose builds the `python:3.11-slim` image (non-root uid 1000), mounts `config/`, `secrets/`, and `keys/` **read-only**, injects `.env`, and starts all eight services with a read-only root filesystem. The gateway is the only service that publishes a host port (`8000`).

To run detached:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build -d
docker compose -f deploy/docker/docker-compose.yml ps
```

---

### 4. Verify the first run

#### 4.1 — Health check (the gateway)

```bash
curl -sS http://localhost:8000/healthz
```

A healthy edge returns **HTTP 200**. Because of the zero-trust network posture, the control/worker `/healthz` endpoints are **not** published to the host — inspect them via container logs / `docker compose ps` rather than curling them directly:

```bash
docker compose -f deploy/docker/docker-compose.yml logs --tail=40 service-gateway
docker compose -f deploy/docker/docker-compose.yml logs --tail=40 service-enforcer
```

#### 4.2 — First brokered tool call (smoke test)

Use one of the API keys `gen_keys.sh` printed (here, the `principal_analyst` key). Identity comes **only** from the key — never from the request body — and the gateway resolves the model from the principal via `model_inventory.yaml`, so no `model` field is required in the body.

```bash
export ANALYST_KEY="<paste-analyst-key-from-gen_keys>"

curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ${ANALYST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
        "messages": [
          {"role": "user", "content": "List the files available in the sandbox."}
        ]
      }'
```

The alternate auth header is also accepted:

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: ${ANALYST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"list the sandbox"}]}'
```

A successful call returns a normalized OpenAI `chat.completion` object (Anthropic responses are translated back to this shape so the edge stays uniform). If the model requests a tool call, the gateway drives the bounded agentic loop (`MAX_TOOL_ROUNDS`, default **4**) through authenticate → authorize → mint token → validate → firewall → sandboxed execute → egress-DLP → audit.

#### 4.3 — Interpreting the response status

| Status | Meaning during first run |
|---|---|
| **200** | Allowed / completed |
| **401** | Missing or invalid API key (check you pasted a `gen_keys.sh` key) |
| **403** | RBAC/scope violation, non-admin hitting `/runtime/sbom`, or **no model provisioned for the principal** (check `model_inventory.yaml`) |
| **400** | JSON-Schema validation or semantic-firewall block, or invalid JSON |
| **429** | Rate limited (`max_requests_per_min` = 10 by default) |
| **502** | Upstream provider/node error, or egress-DLP block — usually a **bad/missing provider key** or unreachable local server |
| **503** | Rate limiter (Redis) unavailable and failing closed |

> **Most common first-run failure is 502.** It almost always means the provider key in `.env` is blank/wrong, or (for local) your Ollama/vLLM server isn't reachable at the configured `endpoint`.

---

### 5. Optional runtime toggles

These are set in `deploy/docker/.env` (or the compose environment) and are safe to leave at their defaults for a first run:

| Env var | Purpose | Default |
|---|---|---|
| `MAX_TOOL_ROUNDS` | Agentic tool-loop budget before a forced final answer | `4` |
| `EGRESS_DLP` | Run the firewall over the tool **response** (egress DLP) | on |
| `RATE_LIMIT_FAIL_CLOSED` | Reject when the rate limiter is unavailable (→ 503) | fail-closed |
| `UPSTREAM_TIMEOUT` | Upstream LLM call timeout | — |
| `SANDBOX_DIR` | Override the node-fs sandbox root | `/app/data/sandbox` |
| `LOG_LEVEL` | Log verbosity | — |

---

### 6. Provider configuration samples

All samples below are edits to `config/model_inventory.yaml`. Keep your provider key(s) in `deploy/docker/.env`; the YAML references them **by env-var name** via `api_key_env` and never contains raw secrets.

#### 6.1 — Anthropic (optimized)

Native Messages API with the optional performance features enabled. Responses are normalized back to OpenAI shape automatically.

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true      # optional: adaptive thinking
    effort: high        # optional: maps to output_config.effort

models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8      # or claude-sonnet-5 / claude-haiku-4-5
```

`.env`: set `ANTHROPIC_API_KEY`.

#### 6.2 — OpenAI

Near-passthrough OpenAI Chat Completions with Bearer auth.

```yaml
providers:
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY

models:
  principal_analyst:
    provider: provider_openai
    upstream_model_id: gpt-4o-mini          # any model your OpenAI account serves
```

`.env`: set `REMOTE_API_KEY`.

#### 6.3 — Local (Ollama / vLLM)

Every non-`anthropic` type uses the OpenAI adapter. `NULL_KEY` means **no `Authorization` header** is sent — correct for keyless local servers.

```yaml
# Ollama
providers:
  provider_local:
    type: openai        # any non-anthropic type -> OpenAI adapter
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_analyst:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct

# vLLM (OpenAI-compatible server; replace host/model with yours)
  provider_vllm:
    type: vllm
    endpoint: http://vllm-host:8000/v1/chat/completions
    api_key_env: NULL_KEY
```

`.env`: no provider key required. Ensure the local server is running and reachable at the configured `endpoint`.

#### 6.4 — LiteLLM proxy

A LiteLLM proxy is just another OpenAI-compatible endpoint (`type: litellm` → OpenAI adapter). Point `endpoint` at **your** proxy; set `api_key_env` to a key var if your proxy enforces one, otherwise use `NULL_KEY`.

```yaml
providers:
  provider_litellm:
    type: litellm
    endpoint: http://litellm-proxy:4000/v1/chat/completions   # replace with your proxy URL
    api_key_env: REMOTE_API_KEY        # or NULL_KEY if the proxy is unauthenticated

models:
  principal_auditor:
    provider: provider_litellm
    upstream_model_id: my-router-alias  # a model/alias your LiteLLM router exposes
```

`.env`: set `REMOTE_API_KEY` only if your proxy requires it.

#### 6.5 — Mixed fleet (different principals → different providers)

Because the adapter layer only translates the model wire format, **switching providers never changes the zero-trust controls** (RBAC, capability tokens, JSON-Schema validation, firewall, egress DLP, audit all run downstream, provider-independent). You can therefore route each principal to a different backend at once:

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
  provider_local:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_admin:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-sonnet-5
  principal_auditor:
    provider: provider_openai
    upstream_model_id: gpt-4o-mini
  principal_netbot:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

For a mixed fleet, populate **every** `api_key_env` your providers reference in `deploy/docker/.env` (here, both `ANTHROPIC_API_KEY` and `REMOTE_API_KEY`; the local provider needs none).

---

### 7. First-run troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `GET /healthz` never responds | Gateway still building/starting | `docker compose ... logs -f service-gateway`; wait for startup |
| Smoke test returns **401** | Wrong/expired API key | Re-copy a key printed by `gen_keys.sh`; if lost, re-run `gen_keys.sh` |
| Smoke test returns **403** ("no model provisioned") | Principal has no `models:` entry | Add the principal → provider mapping in `model_inventory.yaml` |
| Smoke test returns **502** | Blank/invalid provider key, or local server unreachable | Fill the correct `api_key_env` in `.env`; verify the `endpoint` is reachable from the container |
| Local model 502 only | Ollama/vLLM not running or wrong `upstream_model_id` | `ollama serve` + `ollama pull mistral:7b-instruct`; confirm the model id matches |
| **503** on every call | Redis (`redis-store`) unavailable, fail-closed rate limiter | Check the `redis-store` container is up |
| **429** during testing | Hit `max_requests_per_min` (10) | Slow down, or adjust `security_policy.yaml` for your environment |

Once `GET /healthz` returns 200 and your smoke-test chat completion succeeds, the installation is complete and the full authenticate → authorize → validate → enforce → sandbox → DLP → audit pipeline is live in front of your chosen model backend.

---

## Choosing and Configuring Your Model

Kybernos is **model-agnostic**: the same client, the same edge endpoint, and the same zero-trust controls work whether a principal is served by Anthropic, OpenAI, or a model running on your laptop. You choose the backend **per principal** by editing one file — `config/model_inventory.yaml` — and supplying one secret. Nothing on the client side ever changes.

This section explains how model resolution works, walks through full `model_inventory.yaml` samples for every supported backend, and shows how to run a **mixed fleet** where different principals talk to different providers.

---

### How model selection works

Three facts drive everything in this section:

1. **The edge is always OpenAI-compatible.** Clients always `POST /v1/chat/completions` on `service-gateway:8000`, always in OpenAI Chat Completions format, regardless of which model actually answers.
2. **Identity — and therefore the model — comes from the API key, never the request body.** The gateway authenticates the API key to a **principal**, then looks that principal up in `model_inventory.yaml` to resolve its `provider`, `upstream_model_id`, and adapter. A `model` field in the request body does **not** choose the backend; the server-side mapping is authoritative.
3. **Adapters only translate the wire format.** `src/common/providers.py` exposes `get_adapter(provider_type)`. RBAC, capability tokens, JSON-Schema validation, the semantic firewall, egress DLP, and audit all run **downstream** on `{principal, resource, payload}` and are completely provider-independent. Switching a principal from Claude to a local Mistral changes *nothing* about the ZTA/NIST controls.

```mermaid
flowchart LR
    C["Client<br/>POST /v1/chat/completions"] --> G["service-gateway :8000"]
    G --> K["authN: API key to principal"]
    K --> R["resolve principal in<br/>model_inventory.yaml"]
    R --> AD{"get_adapter(type)"}
    AD -->|"anthropic"| AA["AnthropicAdapter<br/>POST /v1/messages"]
    AD -->|"anything else"| OA["OpenAIAdapter<br/>POST /v1/chat/completions"]
    AA --> U["upstream LLM"]
    OA --> U
    U --> Z["tool calls to ingress /process<br/>(RBAC, tokens, schema, firewall, DLP, audit)"]
```

---

### Anatomy of `model_inventory.yaml`

The file has two top-level maps:

- **`providers`** — keyed by provider name. Each provider declares a `type`, an `endpoint`, and an `api_key_env` (the *name* of the environment variable holding the key). Anthropic providers may add optional optimization fields.
- **`models`** — maps each **principal** to a `provider` and an `upstream_model_id`.

```yaml
providers:
  <provider_name>:
    type: <anthropic | openai | any-other>   # any other type -> OpenAIAdapter
    endpoint: <url>
    api_key_env: <ENV_VAR_NAME | NULL_KEY>
    # optional, Anthropic only:
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true
    effort: high

models:
  <principal_name>:
    provider: <provider_name>
    upstream_model_id: <model id>
```

**Adapter selection is driven purely by `type`:**

| `type` value | Adapter chosen | Auth style | Wire endpoint |
|---|---|---|---|
| `anthropic` | `AnthropicAdapter` | `x-api-key` + `anthropic-version` | `POST /v1/messages` |
| `openai` | `OpenAIAdapter` | `Bearer` (or none if `NULL_KEY`) | `POST /v1/chat/completions` |
| `local`, `ollama`, `vllm`, `lmstudio`, `litellm`, `together`, `groq`, … | `OpenAIAdapter` | `Bearer` (or none if `NULL_KEY`) | `POST /v1/chat/completions` |

Anything that is not exactly `anthropic` is treated as OpenAI-compatible. You can literally write `type: vllm` or `type: litellm` for self-documentation — it still routes through `OpenAIAdapter`.

---

### Choosing a provider

```mermaid
flowchart TD
    Start["Pick a backend for this principal"] --> Q1{"Anthropic model?"}
    Q1 -->|Yes| A["type: anthropic<br/>endpoint: /v1/messages<br/>api_key_env: ANTHROPIC_API_KEY"]
    Q1 -->|No| Q2{"Does the endpoint need a key?"}
    Q2 -->|"No (local / keyless)"| L["type: openai<br/>api_key_env: NULL_KEY"]
    Q2 -->|Yes| R["type: openai<br/>api_key_env: REMOTE_API_KEY"]
    A --> AT["upstream_model_id:<br/>claude-opus-4-8 / claude-sonnet-5 / claude-haiku-4-5"]
    L --> LT["upstream_model_id:<br/>e.g. mistral:7b-instruct"]
    R --> RT["upstream_model_id:<br/>e.g. gpt-4o or a proxy route"]
```

---

### The Claude model tiers

When a principal is pointed at `provider_anthropic`, set `upstream_model_id` to one of the current Claude IDs. Use these exact IDs — never legacy names or date suffixes.

| `upstream_model_id` | Tier | Use it for |
|---|---|---|
| `claude-opus-4-8` | Most capable, deepest reasoning | High-stakes agentic tool loops, complex multi-step filesystem/database work, the default for a demanding principal |
| `claude-sonnet-5` | Balanced capability/speed | General-purpose principals that need strong reasoning without top-tier cost |
| `claude-haiku-4-5` | Fastest, lightest | High-volume, low-complexity principals (e.g. a narrow read-only auditor) |

All three run through the identical `AnthropicAdapter` and the identical downstream controls; only the `upstream_model_id` string changes.

---

### Configure Anthropic (the optimized path)

This is the default and best-optimized backend. The adapter speaks the native Anthropic Messages API and **normalizes the response back to an OpenAI `chat.completion`** so the edge stays uniform.

```yaml
# config/model_inventory.yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096          # required by the Anthropic API
    thinking: true            # optional: adaptive thinking
    effort: high              # optional: forwarded verbatim to output_config.effort

models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
```

Supply the key (see [Supplying provider secrets](#supplying-provider-secrets)):

```bash
# deploy/docker/.env
ANTHROPIC_API_KEY=sk-ant-...
```

**What the `AnthropicAdapter` translates for you** (you never do this by hand — the canonical internal history stays OpenAI format):

| OpenAI edge concept | Anthropic wire form |
|---|---|
| `system` role message | extracted to a top-level `system` field |
| `tools: [{type:function, function:{name,description,parameters}}]` | `tools: [{name, description, input_schema}]` |
| assistant `tool_calls` | `tool_use` content blocks |
| `tool`-role results sent back | `tool_result` content blocks |
| Bearer auth | `x-api-key` + `anthropic-version` headers |
| — | `max_tokens` (required) sent from provider config |
| upstream response | normalized back to a `chat.completion` object |

**Optional optimizations** (Anthropic providers only):

- `thinking: true` → enables adaptive thinking on the upstream request.
- `effort: <value>` → forwarded verbatim to `output_config.effort`. Use whatever value your Anthropic account supports.

Omit both to get a plain, un-optimized Anthropic call.

---

### Configure OpenAI

Near-passthrough through `OpenAIAdapter` with Bearer auth. The key lives in `REMOTE_API_KEY`.

```yaml
providers:
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY

models:
  principal_admin:
    provider: provider_openai
    upstream_model_id: gpt-4o        # your OpenAI model id
```

```bash
# deploy/docker/.env
REMOTE_API_KEY=sk-...
```

---

### Configure a local model (Ollama / vLLM / LM Studio)

Local OpenAI-compatible servers usually need **no** auth. Set `api_key_env: NULL_KEY` — the sentinel that tells `OpenAIAdapter` to send **no `Authorization` header at all**.

```yaml
providers:
  provider_local:
    type: openai                                              # or type: ollama / vllm — both -> OpenAIAdapter
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_netbot:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

Notes:
- `host.docker.internal` reaches a model server running on the Docker host (e.g. Ollama on `:11434`). For vLLM/LM Studio, point `endpoint` at their OpenAI-compatible `/v1/chat/completions` path.
- Local models can be slow. If upstream calls time out, raise the `UPSTREAM_TIMEOUT` env var on the gateway.
- The bounded agentic tool loop is governed by `MAX_TOOL_ROUNDS` (default `4`); after the budget is spent the gateway forces a final answer with tools removed. This is provider-independent — a weaker local model simply gets the same round budget.

---

### Configure a LiteLLM proxy (and other keyed OpenAI-compatible backends)

A LiteLLM proxy — like Together, Groq, or an authenticated vLLM — presents an OpenAI-compatible endpoint behind a bearer key. Use `type: openai` (or the descriptive `type: litellm`), point `endpoint` at the proxy, and reuse `REMOTE_API_KEY` for the proxy's master key.

```yaml
providers:
  provider_litellm:
    type: litellm                                    # descriptive; still routes via OpenAIAdapter
    endpoint: http://litellm-proxy:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY                      # proxy master key

models:
  principal_auditor:
    provider: provider_litellm
    upstream_model_id: my-route                      # whatever route name your proxy exposes
```

```bash
# deploy/docker/.env  — REMOTE_API_KEY holds the proxy master key
REMOTE_API_KEY=sk-litellm-master-...
```

The same pattern covers Together / Groq / hosted vLLM: `type: openai`, their `endpoint`, `api_key_env: REMOTE_API_KEY`, and their model id in `upstream_model_id`.

---

### Mixed-fleet sample

Different principals, different providers, different tiers — all behind the one OpenAI-compatible edge. This is the canonical "one gateway, many backends" configuration.

```yaml
# config/model_inventory.yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true

  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY

  provider_local:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

models:
  principal_analyst:                 # heavy filesystem+database reasoning -> top tier Claude
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8

  principal_auditor:                 # narrow, high-volume, database-only -> cheap/fast Claude
    provider: provider_anthropic
    upstream_model_id: claude-haiku-4-5

  principal_netbot:                  # network principal -> keyless local model
    provider: provider_local
    upstream_model_id: mistral:7b-instruct

  principal_admin:                   # all-three admin -> OpenAI
    provider: provider_openai
    upstream_model_id: gpt-4o
```

```text
principal_analyst  ──> provider_anthropic ──> claude-opus-4-8   (x-api-key, /v1/messages)
principal_auditor  ──> provider_anthropic ──> claude-haiku-4-5  (x-api-key, /v1/messages)
principal_netbot   ──> provider_local     ──> mistral:7b-instruct (no auth header)
principal_admin    ──> provider_openai    ──> gpt-4o            (Bearer, /v1/chat/completions)
```

Each principal's RBAC allow-list (from `access_policy.yaml`: analyst `[filesystem,database]`, auditor `[database]`, netbot `[network]`, admin `all three`) is unchanged by the model choice. The backend picks *how the model thinks*; the allow-list picks *what tools it may touch*.

---

### Supplying provider secrets

`api_key_env` names an environment variable — the gateway reads the actual key from the process environment at runtime. Keys are **never** written into config and **never** appear in the SBOM.

**Docker** — put keys in `deploy/docker/.env` (already wired into `docker-compose.yml` alongside `LOG_ENC_KEY_HEX`):

```bash
# deploy/docker/.env
LOG_ENC_KEY_HEX=<64 hex chars from scripts/gen_keys.sh>
ANTHROPIC_API_KEY=sk-ant-...
REMOTE_API_KEY=sk-...
```

```bash
scripts/gen_keys.sh
docker compose -f deploy/docker/docker-compose.yml up --build
```

**Kubernetes** — provider keys live in the `mcp-provider` Secret (created by `deploy/k8s/apply.sh`), which carries `ANTHROPIC_API_KEY` and `REMOTE_API_KEY`. A keyless local provider needs no secret — `NULL_KEY` is a sentinel, not an environment variable you populate.

> `NULL_KEY` is **not** a real key and does not go in `.env`. It is the magic value that makes `OpenAIAdapter` omit the `Authorization` header entirely.

---

### Verify your configuration

**1. Confirm the resolved inventory (keys never included).** The SBOM reflects `models`/`resources` but strips env vars. It is admin-only, so use an admin principal's API key:

```bash
curl -s http://localhost:8000/runtime/sbom \
  -H "Authorization: Bearer $ADMIN_KEY"
```

**2. Make a real call.** Clients always use the OpenAI shape — no `model` field is needed, because the principal's mapping decides the backend:

```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "messages": [
          {"role": "user", "content": "List the files under reports/"}
        ]
      }'
```

Switch `$ANALYST_KEY` for `$NETBOT_KEY` and the exact same request is now answered by the local Mistral — the client body is identical.

---

### What changing the model does *not* change

| Concern | Affected by model choice? |
|---|---|
| Client request/response format (OpenAI `/v1/chat/completions`) | No — always identical |
| Which principal you are (API key → principal) | No — never from the body |
| RBAC allow-list, capability-token minting (ES256 JWT) | No — downstream, provider-independent |
| JSON-Schema validation (authoritative) | No |
| Semantic firewall (112 rules) + egress DLP | No |
| Encrypted audit trail | No |
| Tool-loop budget (`MAX_TOOL_ROUNDS`, default 4) | No — env-controlled, same for every provider |
| Only the **wire translation** to the upstream model | **Yes** — this is all the adapter touches |

---

### Worker-node connector configuration

The `node-db` and `node-net` workers are real connectors, configured entirely through environment variables (set them in `deploy/docker/.env` or the pod spec). The gateway/RBAC/schema/firewall layers are unaffected by these — they only change what the worker does *after* a call is authorized. Defaults are self-contained, so the stack runs out of the box.

**`node-db` — read-only SQL** (backend chosen by `DB_BACKEND`):

| Env var | Default | Meaning |
|---|---|---|
| `DB_BACKEND` | `sqlite` | Backend to use: `sqlite` (self-contained) or `postgres`/`postgresql` (needs `DATABASE_URL` + the `psycopg` driver). |
| `DB_SQLITE_PATH` | `:memory:` | SQLite database file path (used only when `DB_BACKEND=sqlite`). |
| `DATABASE_URL` | *(unset)* | Postgres connection string (used only when `DB_BACKEND=postgres`). **Point this at a dedicated read-only DB role** — the driver read-only session and single-`SELECT` guard are defense-in-depth, not a substitute for the grant. |
| `DB_MAX_ROWS` | `1000` | Maximum rows returned; over the limit sets `truncated:true`. |
| `DB_MAX_CELL` | `4096` | Maximum characters per cell; over the limit sets `truncated:true`. |

The guard accepts only a single `SELECT` or `WITH` statement (a trailing `;` is allowed, but stacked statements are rejected), and the session is forced read-only at the driver (SQLite `PRAGMA query_only=ON`; Postgres read-only transaction).

**`node-net` — SSRF-safe HTTPS egress:**

| Env var | Default | Meaning |
|---|---|---|
| `NET_ALLOWLIST` | *(unset)* | Comma-separated host allowlist; empty means any host that passes the public-IP checks. |
| `NET_ALLOW_HTTP` | `false` | If `true`, permit `http://` URLs; otherwise HTTPS-only. |
| `NET_MAX_BYTES` | `1048576` | Maximum response size in bytes (1 MiB); over the limit sets `truncated:true`. |
| `NET_TIMEOUT` | `5` | Request timeout in seconds. |

Every DNS-resolved IP must be public (cloud metadata `169.254.169.254`, loopback, and RFC1918/link-local ranges are blocked), and redirects are never auto-followed (a `3xx` returns `403`). To fully close DNS-rebinding, front `node-net` with an IP-pinning egress proxy (e.g. Smokescreen).

---

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `403` "no model provisioned" | Principal has no entry in the `models` map | Add a `models:<principal>` block with `provider` + `upstream_model_id` |
| `401` at the edge | API key missing/invalid | Send `Authorization: Bearer <key>` or `X-API-Key: <key>`; check `secrets/api_keys.json` |
| `502` upstream provider error | Wrong `endpoint`, bad/missing provider key, or upstream down | Verify `endpoint`; confirm the env var named by `api_key_env` is set (or `NULL_KEY` for keyless) |
| Local model call hangs / times out | Slow local server | Increase `UPSTREAM_TIMEOUT`; confirm `host.docker.internal` reachability |
| Anthropic call rejected upstream | Missing required `max_tokens`, or wrong `anthropic_version` | Set `max_tokens` and `anthropic_version` on the `provider_anthropic` block |
| Model tier ignored | Wrong or legacy Claude ID | Use exactly `claude-opus-4-8`, `claude-sonnet-5`, or `claude-haiku-4-5` |
| Sent `Authorization` header to a keyless local model | `api_key_env` not set to `NULL_KEY` | Set `api_key_env: NULL_KEY` so no header is sent |

---

## Authentication and API Keys

Kybernos is a zero-trust gateway, and zero-trust starts with identity. This section explains how a caller proves who they are, how that identity becomes a *principal* that every downstream control (RBAC, capability-token minting, schema validation, firewall, DLP, audit) keys off of, and how the **two completely separate credentials** in the system relate to one another.

> **The single most important rule:** identity is derived **only** from the inbound API key. The `model` field (or any other field) in the request body is **never** trusted for identity. This was the core flaw fixed after v1–v5, and it is enforced in exactly one place: `src/common/auth.py` (`ApiKeyAuthenticator`).

---

### 1. Two keys, two trust boundaries

There are two kinds of key in the system, and confusing them is the most common operator mistake. They live on opposite sides of the gateway and are never interchangeable.

| | **Client API key** | **Provider API key** |
|---|---|---|
| Who holds it | Your users / calling apps | The gateway process only |
| Presented to | `service-gateway` (`:8000`, the only public edge) | The upstream LLM (Anthropic / OpenAI / local) |
| Header used | `Authorization: Bearer …` **or** `X-API-Key: …` | `x-api-key` (Anthropic) **or** `Authorization: Bearer …` (OpenAI-compatible) |
| Purpose | Resolve caller → **principal** (identity for RBAC) | Authenticate the gateway to the model backend |
| Where defined | `secrets/api_keys.json` (or `AUTH_KEYS_JSON`) | Env vars named by `api_key_env` in `model_inventory.yaml` |
| Example names | `mcp_…` values mapping to `principal_analyst`, … | `ANTHROPIC_API_KEY`, `REMOTE_API_KEY`, `NULL_KEY` |
| Rotated with | `scripts/gen_keys.sh` (re-run) | Provider console + redeploy the env/Secret |

A client **never** sees a provider key, and a provider key **never** identifies a client. The gateway is the airlock between the two.

```mermaid
flowchart LR
    subgraph edge["Public edge"]
        C["Client app"]
    end
    subgraph gw["service-gateway :8000"]
        A["ApiKeyAuthenticator<br/>api_key to principal"]
        R["model_inventory<br/>principal to provider+model"]
    end
    subgraph up["Upstream LLM providers"]
        AN["Anthropic Messages API"]
        OA["OpenAI-compatible API"]
    end

    C -->|"Client key: Authorization Bearer or X-API-Key"| A
    A -->|"principal (never from body)"| R
    R -->|"Provider key: x-api-key + anthropic-version"| AN
    R -->|"Provider key: Authorization Bearer (or none if NULL_KEY)"| OA
```

**Boundary 1** (left arrow) authenticates the *caller* to the gateway. **Boundary 2** (right arrows) authenticates the *gateway* to the model. Everything between them — the entire ZTA/NIST control pipeline — runs on the resolved `{principal, resource, payload}` and is provider-independent.

---

### 2. How a client authenticates (Boundary 1)

Send the client key in **either** header. The gateway accepts both; `X-API-Key` takes precedence if both are present.

```bash
# Preferred: bearer token
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer mcp_REPLACE_WITH_ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "messages": [{"role": "user", "content": "List files in reports/"}]
      }'
```

```bash
# Equivalent: X-API-Key header
curl -sS http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: mcp_REPLACE_WITH_ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"List files in reports/"}]}'
```

Header extraction logic (from `ApiKeyAuthenticator.extract_key`):

```
if X-API-Key present            -> use it (stripped)
elif Authorization starts "bearer " (case-insensitive) -> use the token after "Bearer "
else                            -> no key -> 401
```

Notice there is **no `model` or `principal` field** you can set to change who you are. The body may carry `messages`, `tools`, etc., but identity is fixed by the key alone. The principal then determines which provider/model you get (`model_inventory.yaml`) and which resources you may touch (`access_policy.yaml`).

---

### 3. Where client keys come from

Client keys are a flat `{"<api_key>": "<principal>"}` map. They are loaded, in order of precedence, from:

1. **`AUTH_KEYS_JSON`** — a JSON string in the environment.
2. **`AUTH_KEYS_PATH`** — a path to a JSON file (default `/app/secrets/api_keys.json`, mounted read-only as a Secret).

Lookup uses `hmac.compare_digest` (constant-time-ish) against every known key, so a wrong key cannot be distinguished by timing.

#### Generate them with `gen_keys.sh`

`scripts/gen_keys.sh` mints the ES256 capability-signing keypair, the AES-256 audit-log key, and a fresh set of client keys — one per default principal. **Nothing it produces is committed** (`keys/` and `secrets/` are gitignored).

```bash
cd /path/to/kybernos
scripts/gen_keys.sh
```

It writes `secrets/api_keys.json` (chmod 600) and prints the plaintext keys **once**:

```
==================== SAVE THESE KEYS (shown once) ====================
 analyst : mcp_1f0c…            # -> principal_analyst
 auditor : mcp_9ab3…            # -> principal_auditor
 netbot  : mcp_44de…            # -> principal_netbot
 admin   : mcp_7c02…            # -> principal_admin  (admin:true, unlocks /runtime/sbom)
=====================================================================
```

The resulting file looks like:

```json
{
  "mcp_1f0c…": "principal_analyst",
  "mcp_9ab3…": "principal_auditor",
  "mcp_44de…": "principal_netbot",
  "mcp_7c02…": "principal_admin"
}
```

The principal strings on the right **must** match entries in `access_policy.yaml` and `model_inventory.yaml`; a key mapping to an unknown principal will authenticate but then fail authorization (403) or model resolution (403 "no model provisioned").

#### Or inject via environment (no file)

Handy for CI or a secrets manager that only exposes env vars:

```bash
export AUTH_KEYS_JSON='{"mcp_1f0c…":"principal_analyst","mcp_7c02…":"principal_admin"}'
```

If neither source yields keys, the authenticator logs `No API keys configured; all requests will be rejected` and every request returns **401**.

---

### 4. The provider key (Boundary 2)

Once the principal is known, the gateway resolves its provider and model from `model_inventory.yaml`, then authenticates itself to that upstream using the env var named by the provider's `api_key_env`. This is handled by the adapter layer (`src/common/providers.py`):

| Provider `type` | Adapter | Auth header the gateway sends |
|---|---|---|
| `anthropic` | `AnthropicAdapter` | `x-api-key: <key>` + `anthropic-version: 2023-06-01` |
| anything else (`openai`, `local`, `ollama`, `vllm`, `lmstudio`, `litellm`, `together`, `groq`, …) | `OpenAIAdapter` | `Authorization: Bearer <key>` |
| any, with `api_key_env: NULL_KEY` | `OpenAIAdapter` | *(no Authorization header sent)* |

Special value: **`NULL_KEY`** means "this backend needs no credential" — used for a local Ollama/vLLM server. The adapter also sends no header if the resolved env var is empty.

Provider keys live in the environment / Secrets, seeded by `gen_keys.sh` (which writes `deploy/docker/.env` with `LOG_ENC_KEY_HEX` and a `REMOTE_API_KEY=` placeholder). Fill in the real values there:

```bash
# deploy/docker/.env  — Generated by gen_keys.sh — DO NOT COMMIT
LOG_ENC_KEY_HEX=…                      # AES-256-GCM audit key (auto-filled)
ANTHROPIC_API_KEY=sk-ant-…             # for provider_anthropic
REMOTE_API_KEY=sk-…                    # for provider_openai
```

In Kubernetes the same values land in the `mcp-provider` Secret (`ANTHROPIC_API_KEY` + `REMOTE_API_KEY`) via `deploy/k8s/apply.sh`.

---

### 5. Provider configuration samples

All of the following are edits to `config/model_inventory.yaml`. The **client** keys never change when you switch providers — clients always POST `/v1/chat/completions` to `:8000`.

#### 5a. Anthropic (optimized / recommended)

```yaml
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096            # required by the Messages API
    thinking: true              # optional: adaptive thinking
    effort: "high"              # optional: low|medium|high|xhigh|max

models:
  principal_admin:
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
```

```bash
export ANTHROPIC_API_KEY='sk-ant-…'
```

#### 5b. OpenAI

```yaml
providers:
  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"

models:
  principal_analyst:
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"
```

```bash
export REMOTE_API_KEY='sk-…'
```

#### 5c. Local (Ollama / vLLM / LM Studio — OpenAI-compatible, no key)

```yaml
providers:
  provider_local:
    type: "openai"                        # OpenAI-compatible wire format
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"               # NULL_KEY = send no Authorization header

models:
  principal_analyst:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
```

No env var needed — `NULL_KEY` suppresses the `Authorization` header. (For a vLLM server started with an `--api-key`, set `api_key_env` to a real env var instead.)

#### 5d. LiteLLM proxy (one endpoint fronting many providers)

```yaml
providers:
  provider_litellm:
    type: "openai"                        # LiteLLM speaks OpenAI wire format
    endpoint: "http://litellm:4000/v1/chat/completions"
    api_key_env: "LITELLM_KEY"

models:
  principal_netbot:
    provider: "provider_litellm"
    upstream_model_id: "bedrock/claude-3-5-sonnet"   # a LiteLLM route name
```

```bash
export LITELLM_KEY='sk-litellm-…'
```

#### 5e. Mixed fleet (different principals, different providers)

Because provider selection is per-principal, you can run a heterogeneous fleet without touching a single client:

```yaml
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096
  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"
  provider_local:
    type: "openai"
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"

models:
  principal_admin:                        # premium Anthropic path
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
  principal_auditor:                      # hosted OpenAI
    provider: "provider_openai"
    upstream_model_id: "gpt-4o"
  principal_analyst:                      # offline local model
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_netbot:                       # cheaper Anthropic tier
    provider: "provider_anthropic"
    upstream_model_id: "claude-haiku-4-5"
```

> Every principal that can call the gateway **must** be provisioned a model here; an unprovisioned principal authenticates but then gets **403 (no model provisioned)**.

---

### 6. Rotation

Because client identity and provider credentials are independent, you rotate them independently.

**Client keys** — re-run the generator (it overwrites `secrets/api_keys.json` with fresh values) or hand-edit the map, then reload the gateway so the file is re-read:

```bash
scripts/gen_keys.sh                    # mint new client keys (prints once)
# ...distribute new keys to callers...
docker compose -f deploy/docker/docker-compose.yml up -d --force-recreate service-gateway
```

For zero-downtime rotation, add the new key **alongside** the old one in the JSON map (multiple keys may map to the same principal), roll out, migrate callers, then remove the old entry and roll out again.

**Provider keys** — issue a new key in the provider console, update `ANTHROPIC_API_KEY` / `REMOTE_API_KEY` (or your custom env var) in `deploy/docker/.env` or the `mcp-provider` Kubernetes Secret, redeploy, then revoke the old key upstream. No client is affected.

```bash
# Kubernetes example
kubectl -n <ns> create secret generic mcp-provider \
  --from-literal=ANTHROPIC_API_KEY='sk-ant-NEW' \
  --from-literal=REMOTE_API_KEY='sk-NEW' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n <ns> rollout restart deploy/service-gateway
```

> **Capability-signing keys** (the ES256 keypair in `keys/`) and the **audit-log key** (`LOG_ENC_KEY_HEX`) are also produced by `gen_keys.sh` but are *not* auth credentials — they belong to the token-minting and audit subsystems, covered in their own sections.

---

### 7. Failure modes and status codes

Authentication failures surface at the edge before any provider or tool is touched:

```
Client key             Result
─────────────────────  ────────────────────────────────────────
missing (no header)    401  (no API key)
present but unknown     401  (invalid API key)
valid                   -> principal resolved, pipeline continues
```

| Symptom | Likely cause | Fix |
|---|---|---|
| `401` on every request | No keys loaded (`AUTH_KEYS_JSON`/file empty or unmounted) | Check the `Loaded N API key(s)` log line; verify the Secret mount |
| `401` for one caller | Wrong/rotated client key, or stray whitespace | Re-issue the key; keys are compared exactly |
| `403` after `200`-style auth | Key maps to a principal not in `access_policy.yaml`, or RBAC denies the resource | Align the principal name; check the ACL |
| `403` "no model provisioned" | Principal missing from `model_inventory.yaml` `models:` | Add a `provider` + `upstream_model_id` entry |
| `502` upstream provider | Bad/absent **provider** key, wrong `api_key_env`, or endpoint unreachable | Fix the provider env var / endpoint |

Note the diagnostic split: a **`401`** points at **Boundary 1** (the client key), while a **`502` upstream** almost always points at **Boundary 2** (the provider key). Keeping those two boundaries straight is the fastest path to a correct fix.

---

### 8. Quick reference

```
CLIENT  ──[ Authorization: Bearer <client_key>  OR  X-API-Key: <client_key> ]──▶  GATEWAY :8000
                                                                                     │
                          api_key ──ApiKeyAuthenticator──▶ principal  (NEVER from body)
                                                                                     │
                          principal ──model_inventory──▶ provider + upstream_model_id
                                                                                     │
GATEWAY ──[ x-api-key <ANTHROPIC_API_KEY> | Bearer <REMOTE_API_KEY> | (none if NULL_KEY) ]──▶  LLM
```

- **Client keys:** `secrets/api_keys.json` or `AUTH_KEYS_JSON`; minted/rotated by `scripts/gen_keys.sh`; headers `Authorization: Bearer` / `X-API-Key`.
- **Provider keys:** env vars named by `api_key_env` (`ANTHROPIC_API_KEY`, `REMOTE_API_KEY`, custom, or `NULL_KEY`); set in `.env` / K8s Secret `mcp-provider`.
- **Identity is the key, not the body.** Swapping to OIDC/JWT later means replacing only `ApiKeyAuthenticator` — nothing downstream changes.

---

## Using the API

This is the only interface most clients ever touch. The gateway edge speaks **OpenAI Chat Completions** and nothing else: you always `POST /v1/chat/completions` to `service-gateway:8000`, regardless of whether the principal's backend is Anthropic, OpenAI, a local Ollama/vLLM box, or a LiteLLM proxy. The request body is byte-for-byte identical across all of them — switching a backend is a server-side config edit, never a client change.

### The one endpoint

| Property | Value |
|---|---|
| Method / path | `POST /v1/chat/completions` |
| Host | `service-gateway:8000` (the only externally reachable service) |
| Wire format | OpenAI Chat Completions (request **and** response) |
| Auth header | `Authorization: Bearer <key>` **or** `X-API-Key: <key>` |
| Content type | `application/json` |
| Health | `GET /healthz` (unauthenticated liveness) |
| SBOM | `GET /runtime/sbom` (admin principals only) |

Two rules that govern everything below:

- **Identity comes from the API key, never the request body.** The key resolves to a principal (`principal_analyst`, `principal_auditor`, `principal_netbot`, `principal_admin`). Any user/role/identity you put in the JSON is ignored for authorization.
- **The backend model is resolved from the principal**, via `config/model_inventory.yaml` (`models: <principal> -> provider + upstream_model_id`). The OpenAI `model` field in the body is accepted for client-library compatibility but is **advisory** — the gateway uses the principal's inventory entry as authoritative.

### Authentication

Both header styles are equivalent; pick one.

```bash
# Bearer style
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" -d '{ ... }'

# X-API-Key style
curl -sS http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: $ANALYST_KEY" \
  -H "Content-Type: application/json" -d '{ ... }'
```

Keys map to principals in `secrets/api_keys.json` (or the `AUTH_KEYS_JSON` env). A missing or invalid key returns **401** before any model call.

### Plain chat (no tools)

The simplest call. The model behind `principal_analyst` answers; the response is a standard `chat.completion`.

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-opus-4-8",
    "messages": [
      {"role": "system", "content": "You are a terse assistant."},
      {"role": "user",   "content": "Give me one sentence on zero-trust."}
    ]
  }'
```

Representative response (already normalized to OpenAI shape — true even when the backend was the Anthropic Messages API):

```json
{
  "id": "chatcmpl-8f3c...",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "finish_reason": "stop",
      "message": {
        "role": "assistant",
        "content": "Zero-trust assumes no implicit trust and authenticates and authorizes every request individually."
      }
    }
  ]
}
```

#### Same request, any backend

The demonstration of model-agnosticism: the command above is **unchanged** whether `principal_analyst` is pointed at Anthropic or at a local model. To move that principal from Anthropic to a local Ollama box you edit one YAML block — the client never learns the difference.

```yaml
# config/model_inventory.yaml  — Anthropic today...
models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
```

```yaml
# config/model_inventory.yaml  — ...local tomorrow. Same curl, same output shape.
models:
  principal_analyst:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

Only the wire translation changes (handled by `AnthropicAdapter` vs `OpenAIAdapter` in `src/common/providers.py`). RBAC, capability tokens, JSON-Schema validation, the firewall, egress DLP, and audit run downstream and are identical either way.

### Tools = registered resources

Tool-calling is where the gateway earns its keep. You declare tools in the standard OpenAI **function** format. Each tool's `function.name` must match a **registered resource id** from `config/resource_catalog.yaml`, and its arguments must satisfy that resource's schema. There are three resources:

```
tool (function.name)   ->  resource         ->  worker node
──────────────────────────────────────────────────────────────
resource_filesystem    ->  resource_filesystem  ->  node-fs  :8620
resource_database      ->  resource_database    ->  node-db  :8610
resource_network       ->  resource_network     ->  node-net :8630
```

A principal may only invoke the resources on its access list. Reach for one you lack and the pipeline returns **403** (RBAC).

| Principal | Allowed resources |
|---|---|
| `principal_analyst` | `resource_filesystem`, `resource_database` |
| `principal_auditor` | `resource_database` |
| `principal_netbot`  | `resource_network` |
| `principal_admin`   | all three (`admin: true`) |

The argument schemas you must honor (mirrors `resource_catalog.yaml`, `additionalProperties: false`):

| Resource | Field | Constraint |
|---|---|---|
| `resource_filesystem` | `action` | enum `read` \| `list` \| `write` |
| | `path` | no leading `/`, no `..`, ext in `.txt .json .log .md` |
| | `content` | optional; printable ASCII; `maxLength 10240` |
| `resource_database` | `query` | must start `SELECT`/`SHOW`/`DESCRIBE`, `... FROM ...`; `maxLength 512` |
| `resource_network` | `url` | `https` only, no internal IPs; `maxLength 256` |
| | `method` | `GET` only |

### End-to-end tool-calling flow

The gateway runs a **bounded internal agent loop** — you do not execute tools yourself and you do not send `tool`-role results back. You POST your prompt **plus the tool declarations**; the gateway calls the model, intercepts every tool call the model wants to make, forces each one through the full zero-trust pipeline, feeds the results back to the model, and repeats. The loop is capped by `MAX_TOOL_ROUNDS` (default **4**); once the budget is spent the gateway forces a final answer with the tools removed. You get back a single, finished `chat.completion`.

```mermaid
sequenceDiagram
    autonumber
    participant C as "Client"
    participant G as "service-gateway :8000"
    participant L as "Upstream LLM"
    participant I as "service-ingress :8443"
    participant R as "service-registry :8500"
    participant E as "service-enforcer :8650"
    participant W as "worker node"
    C->>G: "POST /v1/chat/completions (messages + tools)"
    G->>G: "authN API key -> principal"
    G->>L: "adapter build_request -> call model"
    L-->>G: "assistant turn with tool_calls"
    loop up to MAX_TOOL_ROUNDS (default 4)
        G->>I: "POST /process {principal, resource, payload}"
        I->>R: "POST /authorize (RBAC allow_list)"
        R-->>I: "ES256 capability token + resource"
        I->>E: "POST /execute (token + payload)"
        E->>E: "verify JWT -> JSON-Schema -> firewall"
        E->>W: "POST /run"
        W-->>E: "result"
        E->>E: "egress DLP -> size cap"
        E-->>I: "tool result"
        I-->>G: "tool result"
        G->>L: "append result -> call model"
        L-->>G: "next turn"
    end
    G-->>C: "chat.completion (final answer)"
```

Each hop maps to the request lifecycle: gateway authenticates and rate-limits, ingress writes the encrypted INGRESS audit, registry does the RBAC check and mints the scoped JWT (stored as `valid_token:<jti>` in Redis), enforcer verifies the token, validates against the precompiled Draft202012 schema, runs the 112-rule firewall, calls the worker, applies egress DLP over the response, and ingress writes the EGRESS audit.

#### Filesystem example (`principal_analyst`)

Ask the model to read a sandboxed file; the gateway executes the `read` through `node-fs`.

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-opus-4-8",
    "messages": [
      {"role": "user", "content": "Read notes/report.md and summarize it in two lines."}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "resource_filesystem",
          "description": "Sandboxed filesystem access under the worker sandbox root.",
          "parameters": {
            "type": "object",
            "properties": {
              "action":  {"type": "string", "enum": ["read", "list", "write"]},
              "path":    {"type": "string"},
              "content": {"type": "string"}
            },
            "required": ["action", "path"],
            "additionalProperties": false
          }
        }
      }
    ]
  }'
```

A `write` looks the same, but adds `content` in the arguments the model produces:

```json
{"action": "write", "path": "notes/out.txt", "content": "generated summary\n"}
```

Paths with a leading `/`, a `..`, or a disallowed extension are rejected at the schema stage (**400**) — the sandbox escape check (`realpath` + `os.sep`) is a second line of defense, not the first.

#### Database example (`principal_auditor`)

The auditor may only touch the database. Read-only SQL is enforced by schema **and** firewall.

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: $AUDITOR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "How many rows are in the events table?"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "resource_database",
          "description": "Read-only SQL against the database (SELECT/SHOW/DESCRIBE ... FROM).",
          "parameters": {
            "type": "object",
            "properties": {
              "query": {"type": "string"}
            },
            "required": ["query"],
            "additionalProperties": false
          }
        }
      }
    ]
  }'
```

The model emits e.g. `{"query": "SELECT COUNT(*) FROM events"}`. An `INSERT`, `DROP`, or `UPDATE` never reaches the worker: it fails the `SELECT/SHOW/DESCRIBE` schema pattern (**400**), and the SQLI firewall group is there as defense-in-depth. `node-db` runs the query against a real backend (SQLite by default, or Postgres via `DATABASE_URL`) under a read-only session — only a single `SELECT`/`WITH` is accepted by its own guard, and results are bounded by `DB_MAX_ROWS`/`DB_MAX_CELL`.

#### Network example (`principal_netbot`)

Only `principal_netbot` may reach `resource_network`; only `https` GETs to public hosts are permitted.

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $NETBOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "Fetch https://example.com/status and tell me if it is ok."}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "resource_network",
          "description": "Outbound HTTPS GET to public hosts only.",
          "parameters": {
            "type": "object",
            "properties": {
              "url":    {"type": "string"},
              "method": {"type": "string", "enum": ["GET"]}
            },
            "required": ["url", "method"],
            "additionalProperties": false
          }
        }
      }
    ]
  }'
```

The model emits `{"url": "https://example.com/status", "method": "GET"}`. An `http://` URL, a non-GET method, or an internal IP (e.g. `https://169.254.169.254/...`) is rejected — by schema first, and by the SSRF firewall group as backup. `node-net` then performs a real HTTPS fetch, re-checking that every resolved IP is public (blocking metadata/loopback/RFC1918), refusing to auto-follow redirects, and bounding the response by `NET_MAX_BYTES`/`NET_TIMEOUT`.

> If you send a network tool to `principal_analyst`, or a filesystem tool to `principal_netbot`, the gateway calls the model but the tool invocation is denied at registry with **403** — the model's requested resource is not on the principal's allow list.

### Provider configuration samples

Everything below lives in `config/model_inventory.yaml`. `providers` are keyed by name (`type`, `endpoint`, `api_key_env`, plus optional per-provider fields); `models` maps each principal to a provider and an `upstream_model_id`. The client API is unaffected by any of it.

**Anthropic (optimized).** Native Messages API under the hood, normalized back to OpenAI at the edge. Optional `thinking` and `effort` enable adaptive thinking and effort tuning.

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true
    effort: high
models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8   # or claude-sonnet-5, claude-haiku-4-5
```

**OpenAI.** Near-passthrough `/v1/chat/completions`, Bearer auth from `REMOTE_API_KEY`.

```yaml
providers:
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
models:
  principal_analyst:
    provider: provider_openai
    upstream_model_id: gpt-4o
```

**Local (Ollama / vLLM).** Any non-`anthropic` type uses `OpenAIAdapter`. `NULL_KEY` tells the adapter to send **no** `Authorization` header.

```yaml
providers:
  provider_ollama:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY
  provider_vllm:
    type: vllm            # free-form type, treated as OpenAI-compatible
    endpoint: http://vllm-server:8000/v1/chat/completions
    api_key_env: NULL_KEY
models:
  principal_analyst:
    provider: provider_ollama
    upstream_model_id: mistral:7b-instruct
```

**LiteLLM proxy.** Point the gateway at a LiteLLM router; it is just another OpenAI-compatible endpoint.

```yaml
providers:
  provider_litellm:
    type: litellm         # non-anthropic -> OpenAIAdapter
    endpoint: http://litellm:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY
models:
  principal_analyst:
    provider: provider_litellm
    upstream_model_id: my-router-alias
```

**Mixed fleet.** Different principals on different backends simultaneously — the whole point of the adapter layer. Clients for all four principals use the identical `POST /v1/chat/completions`.

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
  provider_local:
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY
models:
  principal_analyst: { provider: provider_anthropic, upstream_model_id: claude-opus-4-8 }
  principal_auditor: { provider: provider_openai,    upstream_model_id: gpt-4o }
  principal_netbot:  { provider: provider_local,     upstream_model_id: mistral:7b-instruct }
  principal_admin:   { provider: provider_anthropic, upstream_model_id: claude-sonnet-5 }
```

The matching `api_key_env` names must be populated in the environment (`ANTHROPIC_API_KEY`, `REMOTE_API_KEY`); `NULL_KEY` needs nothing. In Docker these ride in `deploy/docker/.env`; in Kubernetes they come from the `mcp-provider` Secret.

### Limits that shape a request

| Limit | Value | On breach |
|---|---|---|
| `max_input_size` | 524288 bytes | **413** body too large |
| `max_output_size` | 4096 bytes | truncated / **502** on oversize node output |
| `max_requests_per_min` | 10 (fixed window, per principal) | **429** |
| `token_ttl` | 30 s (capability token) | expired token -> **401** |
| `MAX_TOOL_ROUNDS` | 4 (env) | loop ends, final answer forced with tools removed |

### Response status codes

```
200  allowed
400  JSON-Schema validation failed / firewall violation / invalid JSON body
401  no or invalid API key, or invalid/expired capability token
403  RBAC violation / scope mismatch / non-admin SBOM / no model provisioned
404  resource or file not found
413  request body over max_input_size
429  rate limit (max_requests_per_min)
502  upstream provider or worker-node error, or egress-DLP block
503  rate limiter unavailable (fail-closed)
```

### Quick reference

```
Client
  │  POST /v1/chat/completions   (Authorization: Bearer <key>  |  X-API-Key: <key>)
  │  body = { messages[], tools[]? , model? (advisory) }
  ▼
service-gateway :8000
  ├─ authN key -> principal          (401 if bad)
  ├─ rate limit + body cap           (429 / 413)
  ├─ resolve provider+model+adapter  (model_inventory.yaml)
  ├─ call upstream LLM (adapter)
  └─ bounded tool loop (MAX_TOOL_ROUNDS) ── each tool_call ──▶ ingress ▶ registry ▶ enforcer ▶ node
  ▼
chat.completion  (always OpenAI-shaped, every backend)
```

Tips:
- Send the same body to every backend; change behavior by editing the principal's entry in `model_inventory.yaml`, not the client.
- Name each tool exactly after the resource it targets (`resource_filesystem` / `resource_database` / `resource_network`) and match that resource's schema.
- Do not put identity in the body — the key is the identity.
- Expect a single finished answer; the gateway executes tools internally and never asks you to return `tool`-role messages.

---

## Principals and Permissions

Every request that reaches Kybernos is executed **as a principal** — a named identity with a fixed set of resource permissions. The principal is the anchor of the entire zero-trust pipeline: it is what RBAC checks, what the capability token's `sub`/`scope` are minted from, and what the encrypted audit log records. There are exactly **four** principals shipped in the default policy.

Critically, **identity comes from the API key, never from the request body.** A client cannot select or spoof a principal by putting a name in the JSON payload — the gateway derives it from the presented key and carries that authenticated principal through ingress → registry → enforcer. Anything a caller puts in the body is *data*, not identity.

### The four principals at a glance

| Principal | `allow_list` | Admin | Can reach | Cannot reach | Typical use |
|---|---|---|---|---|---|
| `principal_analyst` | `[filesystem, database]` | no | files + SQL | network, SBOM | General data work: read/write sandboxed files and query the database |
| `principal_auditor` | `[database]` | no | SQL only | files, network, SBOM | Read-only reporting / reconciliation against the database |
| `principal_netbot` | `[network]` | no | outbound HTTPS GET | files, database, SBOM | Fetchers/crawlers that only pull remote content |
| `principal_admin` | `[filesystem, database, network]` | **yes** | all three resources | — | Operators / break-glass; `admin:true` also unlocks `GET /runtime/sbom` |

The `allow_list` entries name the three resources defined in `resource_catalog.yaml`:

```
principal (resolved from the API key)
 └─ allow_list  ──▶ resource_catalog.yaml
      filesystem ─▶ resource_filesystem  → node-fs  :8620   (action read|list|write)
      database   ─▶ resource_database    → node-db  :8610   (SELECT/SHOW/DESCRIBE only)
      network    ─▶ resource_network     → node-net :8630   (https GET only)
```

### Permission matrix

```mermaid
flowchart LR
  A["principal_analyst"] --> FS["resource_filesystem (node-fs:8620)"]
  A --> DB["resource_database (node-db:8610)"]
  AU["principal_auditor"] --> DB
  N["principal_netbot"] --> NET["resource_network (node-net:8630)"]
  AD["principal_admin (admin:true)"] --> FS
  AD --> DB
  AD --> NET
  AD --> SBOM["GET /runtime/sbom (admin-only)"]
```

Read as a grid (✓ = allowed, blank = 403):

| | filesystem | database | network | `/runtime/sbom` |
|---|:---:|:---:|:---:|:---:|
| `principal_analyst` | ✓ | ✓ | | |
| `principal_auditor` | | ✓ | | |
| `principal_netbot` | | | ✓ | |
| `principal_admin` | ✓ | ✓ | ✓ | ✓ |

> Reminder: switching a principal's upstream **provider** (Anthropic, OpenAI, local, LiteLLM…) never changes this matrix. Adapters translate only the model wire format; RBAC, capability tokens, schema validation, the firewall, egress DLP, and audit run downstream on `{principal, resource, payload}` and are fully provider-independent.

### Where identity is established: `api_keys.json`

The `ApiKeyAuthenticator` in `src/common/auth.py` loads an **api-key → principal** map from the `AUTH_KEYS_JSON` env var, or from the `AUTH_KEYS_PATH` file (default `/app/secrets/api_keys.json`). Lookup uses `hmac.compare_digest`.

```json
{
  "sk-analyst-REPLACE_ME": "principal_analyst",
  "sk-auditor-REPLACE_ME": "principal_auditor",
  "sk-netbot-REPLACE_ME":  "principal_netbot",
  "sk-admin-REPLACE_ME":   "principal_admin"
}
```

Callers present the key one of two ways at the edge (`service-gateway:8000`):

```bash
# Preferred
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" -H "Content-Type: application/json" -d '{...}'

# Equivalent
curl -sS http://localhost:8000/v1/chat/completions \
  -H "X-API-Key: $ANALYST_KEY" -H "Content-Type: application/json" -d '{...}'
```

A missing or unknown key never becomes a principal — it returns **401** before any RBAC runs.

### Where permissions live: `access_policy.yaml`

The RuntimeRegistry loads `config/access_policy.yaml` at boot (from `CONFIG_PATH`) and exposes it as `.access_list`. This is the authoritative RBAC source.

```yaml
# config/access_policy.yaml
access_control_list:
  principal_analyst:
    allow_list: [filesystem, database]
  principal_auditor:
    allow_list: [database]
  principal_netbot:
    allow_list: [network]
  principal_admin:
    allow_list: [filesystem, database, network]
    admin: true          # unlocks GET /runtime/sbom
```

To create a new least-privilege identity, add a key to `api_keys.json`, then add a matching `access_control_list` entry with the narrowest `allow_list` it needs. Do **not** grant `admin: true` unless the identity must read the SBOM.

### How to choose a principal (least privilege first)

Pick the **narrowest** principal that still lets the task succeed:

| If the job needs to… | Choose | Why |
|---|---|---|
| Read/write sandboxed files **and** query the DB | `principal_analyst` | Only principal with both file + DB scope |
| Only run `SELECT`/`SHOW`/`DESCRIBE` reports | `principal_auditor` | DB-only; no filesystem or egress surface |
| Only pull remote content over HTTPS GET | `principal_netbot` | Network-only; cannot touch files or DB |
| Operate/inspect the platform, or read the SBOM | `principal_admin` | Full resource scope **and** admin |

Anti-patterns: don't use `principal_admin` for routine data pulls (it needlessly widens blast radius), and don't reach for `principal_analyst` when a reporting job only ever reads the database — `principal_auditor` removes the file-write surface entirely.

### What a 403 looks like (out-of-`allow_list`)

RBAC is enforced at `service-registry` (`POST /authorize`) **before** any capability token is minted. If the resource the model is trying to reach is not in the authenticated principal's `allow_list`, the request is denied with **403** and nothing runs downstream.

Worked example — a `principal_netbot` client whose model tries to read a file:

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $NETBOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "auto",
        "messages": [
          {"role": "user", "content": "Read reports/q2.txt and summarize it."}
        ]
      }'
# The model emits a filesystem tool_call. The gateway forwards it to ingress
# using the AUTHENTICATED principal (principal_netbot), NOT anything in the body.
# Registry rejects it: filesystem is not in principal_netbot.allow_list ([network]).
# -> 403 RBAC policy violation; the tool result carries the denial, so the model
#    never receives file contents.
```

> The `model` field in the body is not how identity or model selection works — the gateway resolves the principal's provider + upstream model from `model_inventory.yaml`. The body cannot promote a caller's permissions.

Conceptually, what the gateway forwards internally (control-zone only; `service-ingress:8443` is **not** client-reachable — a zero-trust NetworkPolicy allows only the gateway to call it):

```jsonc
// POST http://service-ingress:8443/process
{
  "principal": "principal_netbot",       // from the API key, never the payload
  "resource":  "resource_filesystem",
  "payload":   { "action": "read", "path": "reports/q2.txt" }
}
// -> 403  (principal_netbot allow_list = [network]; filesystem not permitted)
```

The four RBAC-related **403** causes you will encounter:

- **out-of-`allow_list`** — principal lacks the targeted resource (the case above)
- **scope mismatch** — capability token `scope` ≠ the resource being executed
- **non-admin SBOM** — a non-`admin` principal calls `GET /runtime/sbom`
- **no model provisioned** — the principal has no entry in `model_inventory.yaml`

Admin-gated SBOM, demonstrated:

```bash
# admin -> 200 (SBOM; env vars are NEVER included in it)
curl -sS http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY"

# analyst -> 403 (admin:true required)
curl -sS http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ANALYST_KEY"
```

### Binding principals to models and providers

Permissions decide **which resources** a principal may touch; `model_inventory.yaml` decides **which LLM** answers for that principal. Every active principal needs a `models` entry — a missing one is one of the **403** ("no model provisioned") causes above. The provider `type` selects the adapter: `type: anthropic` → `AnthropicAdapter` (native Messages API, normalized back to an OpenAI `chat.completion`); every other type → `OpenAIAdapter`.

**Anthropic (optimized).** Native `/v1/messages`, with the optional Anthropic-only optimizations:

```yaml
# config/model_inventory.yaml  (providers)
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true      # optional: adaptive thinking
    effort: high        # optional: maps to output_config.effort
```

**OpenAI.** Near-passthrough `/v1/chat/completions`, Bearer auth:

```yaml
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
```

**Local (Ollama / vLLM).** OpenAI-compatible; `NULL_KEY` means send no `Authorization` header:

```yaml
  provider_local:                 # Ollama
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

  provider_vllm:                  # vLLM (any non-anthropic type -> OpenAIAdapter)
    type: vllm
    endpoint: http://host.docker.internal:8001/v1/chat/completions
    api_key_env: NULL_KEY
```

**LiteLLM proxy.** Also OpenAI-compatible, so it uses the `OpenAIAdapter`:

```yaml
  provider_litellm:
    type: litellm                 # treated as openai
    endpoint: http://host.docker.internal:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY
```

**Mixed fleet — different principals on different providers.** Because permissions and providers are orthogonal, you can run each identity on the backend that suits it while the RBAC matrix above stays identical. Use current Claude model IDs (`claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5`):

```yaml
models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8      # optimized Anthropic path
  principal_auditor:
    provider: provider_openai
    upstream_model_id: gpt-4o               # set to whatever your account serves
  principal_netbot:
    provider: provider_local
    upstream_model_id: "mistral:7b-instruct"
  principal_admin:
    provider: provider_anthropic
    upstream_model_id: claude-sonnet-5
```

Clients never change across any of these: they always `POST /v1/chat/completions` at `service-gateway:8000` with their key. The edge stays uniform, and — regardless of provider — `principal_auditor` still cannot touch a file, and only `principal_admin` can read the SBOM.

### Quick reference

| Symptom | Meaning | Fix |
|---|---|---|
| `401` | No/invalid API key | Key missing from `api_keys.json` / `AUTH_KEYS_JSON` |
| `403` out-of-`allow_list` | Principal lacks that resource | Use a principal whose `allow_list` includes it (least privilege) |
| `403` non-admin SBOM | `/runtime/sbom` without `admin:true` | Call with `principal_admin` |
| `403` no model provisioned | Principal missing from `model_inventory.yaml` | Add a `models:` entry for the principal |

---

## Tools and What They Accept

Kybernos exposes exactly **three tools** (called *resources*) to the model. No matter which upstream model a principal is wired to, the model sees these tools as ordinary **OpenAI function tools** and the gateway intercepts every tool-call, forcing it through RBAC → capability token → JSON-Schema validation → firewall → sandboxed execute → egress-DLP → audit.

Two facts govern everything in this section:

1. **Identity is never in the payload.** The calling principal is derived from the API key on the request (`Authorization: Bearer <key>` or `X-API-Key: <key>`), never from the tool arguments. Ingress always sees `{principal, resource, payload}` where `principal` is the *authenticated* identity.
2. **The tool contract is provider-independent.** Adapters (`src/common/providers.py`) only translate the model wire format. The schemas, RBAC, firewall, and DLP described below run downstream on `{principal, resource, payload}` and are identical whether the principal is on Anthropic, OpenAI, a local Ollama, vLLM, or a LiteLLM proxy.

### The three tools at a glance

| Tool (resource) | Worker node | Port | Actions / verbs | Hard limits |
|---|---|---|---|---|
| `resource_filesystem` | node-fs (sandboxed FS) | 8620 | `read`, `list`, `write` | `content` ≤ 10240 chars, printable ASCII |
| `resource_database` | node-db (read-only SQL) | 8610 | `SELECT` / `SHOW` / `DESCRIBE` only | `query` ≤ 512 chars |
| `resource_network` | node-net (SSRF-safe HTTP) | 8630 | `GET` only, `https://` only | `url` ≤ 256 chars |

> `node-db` is a **real read-only SQL connector** (SQLite by default, or Postgres via `DATABASE_URL`) — its own guard accepts only a single `SELECT`/`WITH`, the driver session is forced read-only, and output is bounded by `DB_MAX_ROWS`/`DB_MAX_CELL`. `node-net` is a **real SSRF-safe HTTPS egress fetcher** — every resolved IP must be public, redirects are never auto-followed, and the response is bounded by `NET_MAX_BYTES`/`NET_TIMEOUT`. The validation/RBAC/firewall in front of them is fully real; the remaining hardening is operational (a dedicated read-only DB grant, and an IP-pinning egress proxy for net). See **Worker-node connector configuration** for the env vars.

### Who may call what (RBAC allow-list)

RBAC is authoritative and lives in `config/access_policy.yaml`. A principal calling a tool outside its allow-list is rejected with **403** *before* any schema check.

| Principal | `resource_filesystem` | `resource_database` | `resource_network` | admin |
|---|:--:|:--:|:--:|:--:|
| `principal_analyst` | yes | yes | — | — |
| `principal_auditor` | — | yes | — | — |
| `principal_netbot` | — | — | yes | — |
| `principal_admin` | yes | yes | yes | yes |

Examples: `principal_netbot` calling `resource_filesystem` → **403**. `principal_auditor` calling `resource_network` → **403**. Only `admin:true` (i.e. `principal_admin`) additionally unlocks `GET /runtime/sbom`.

---

### `resource_filesystem` — sandboxed read / list / write

Everything happens under the sandbox root **`/app/data/sandbox`** (override with the `SANDBOX_DIR` env var). The node performs an escape check using `realpath` + `os.sep`, so even a path that slips past the schema cannot climb out of the sandbox.

**Tool the model sees (OpenAI function tool):**

```json
{
  "type": "function",
  "function": {
    "name": "resource_filesystem",
    "description": "Sandboxed filesystem: read/list/write under the sandbox root.",
    "parameters": {
      "type": "object",
      "additionalProperties": false,
      "required": ["action", "path"],
      "properties": {
        "action":  { "type": "string", "enum": ["read", "list", "write"] },
        "path":    { "type": "string" },
        "content": { "type": "string", "maxLength": 10240 }
      }
    }
  }
}
```

**Field rules (from `config/resource_catalog.yaml`, `additionalProperties: false`):**

| Field | Rule |
|---|---|
| `action` | Must be one of `read`, `list`, `write`. |
| `path` | **Relative** (no leading `/`), **no `..`**, and file targets must end in `.txt`, `.json`, `.log`, or `.md`. |
| `content` | Only for `write`. Printable ASCII, **maxLength 10240**. |
| *(any other key)* | Rejected — `additionalProperties: false` → **400**. |

**Path shapes — accepted vs rejected:**

```
sandbox root = /app/data/sandbox        (override: SANDBOX_DIR)

path must satisfy ALL of:
  ├─ relative (no leading slash)   reports/q3.txt        OK
  │                                /etc/passwd           REJECT  (leading slash)
  ├─ no parent escape (no "..")    ../../secrets.txt     REJECT  (contains ..)
  └─ safe extension on files       notes.md              OK   (.txt .json .log .md)
     (governs read/write targets)  runme.sh              REJECT  (extension not allowed)
```

> The safe-extension constraint governs **file** targets (`read`/`write`). `list` enumerates a relative directory under the sandbox root; it never receives an absolute or `..`-bearing path.

**Valid vs rejected calls:**

| Payload | Result |
|---|---|
| `{"action":"read","path":"reports/q3.txt"}` | ✅ 200 (if file exists), else **404** |
| `{"action":"list","path":"logs"}` | ✅ 200 (directory listing) |
| `{"action":"write","path":"notes.md","content":"hello"}` | ✅ 200 |
| `{"action":"read","path":"/etc/passwd"}` | ❌ **400** schema (leading slash / not safe-ext) |
| `{"action":"read","path":"../../secret.json"}` | ❌ **400** schema (`..`), + LFI firewall defense-in-depth |
| `{"action":"write","path":"x.exe","content":"..."}` | ❌ **400** schema (extension not allowed) |
| `{"action":"delete","path":"x.txt"}` | ❌ **400** schema (`action` not in enum) |
| `{"action":"write","path":"x.txt","mode":"777"}` | ❌ **400** schema (`additionalProperties:false`) |

---

### `resource_database` — read-only SQL (`SELECT` / `SHOW` / `DESCRIBE`)

**Tool the model sees:**

```json
{
  "type": "function",
  "function": {
    "name": "resource_database",
    "description": "Read-only SQL against the managed database.",
    "parameters": {
      "type": "object",
      "additionalProperties": false,
      "required": ["query"],
      "properties": {
        "query": { "type": "string", "maxLength": 512 }
      }
    }
  }
}
```

**Rules:** the statement must begin with a read-only verb — `SELECT`, `SHOW`, or `DESCRIBE` — and be **≤ 512 characters**. Any write/DDL/DML verb is rejected by schema; injection patterns (stacked statements, comment tricks, `UNION`-based exfiltration) are additionally caught by the **SQLI firewall group (29 rules, DOTALL)** as defense-in-depth.

**Valid vs rejected queries:**

| Query | Result |
|---|---|
| `SELECT id, email FROM users LIMIT 10` | ✅ 200 (rows) |
| `SHOW TABLES` | ✅ 200 |
| `DESCRIBE orders` | ✅ 200 |
| `DROP TABLE users` | ❌ **400** schema (verb not allowed) |
| `UPDATE users SET admin=1` | ❌ **400** schema |
| `SELECT * FROM users; DELETE FROM users` | ❌ **400** SQLI firewall (stacked statement) |
| `SELECT * FROM users WHERE id = 1 OR 1=1 --` | ❌ **400** SQLI firewall |
| *(a query longer than 512 chars)* | ❌ **400** schema (maxLength) |

---

### `resource_network` — HTTPS `GET` only, no internal targets

**Tool the model sees:**

```json
{
  "type": "function",
  "function": {
    "name": "resource_network",
    "description": "Outbound HTTPS GET to an allowed external URL.",
    "parameters": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "method"],
      "properties": {
        "url":    { "type": "string", "maxLength": 256 },
        "method": { "type": "string", "enum": ["GET"] }
      }
    }
  }
}
```

**Rules:** `url` must be **`https://`** (plaintext `http://` rejected), must **not** target internal IPs / metadata endpoints, and be **≤ 256 characters**. `method` must be `GET`. Internal-target attempts are stopped by schema and by the **SSRF firewall group (7 rules)**.

**Valid vs rejected calls:**

| Payload | Result |
|---|---|
| `{"url":"https://api.example.com/v1/status","method":"GET"}` | ✅ 200 (response) |
| `{"url":"http://api.example.com/status","method":"GET"}` | ❌ **400** schema (not https) |
| `{"url":"https://api.example.com","method":"POST"}` | ❌ **400** schema (`method` not in enum) |
| `{"url":"https://169.254.169.254/latest/meta-data/","method":"GET"}` | ❌ **400** SSRF firewall (metadata IP) |
| `{"url":"https://10.0.0.5/admin","method":"GET"}` | ❌ **400** schema/SSRF (internal IP) |
| `{"url":"https://localhost:8500/authorize","method":"GET"}` | ❌ **400** SSRF firewall (internal host) |

---

### The allow / deny decision

Every tool-call runs the same ordered gauntlet. **JSON-Schema is authoritative; the firewall is defense-in-depth on top.**

```mermaid
flowchart TD
    A["model emits tool_call"] --> B{"RBAC: principal allowed<br/>for resource?"}
    B -- no --> R403["403 policy violation"]
    B -- yes --> T["registry mints ES256<br/>capability token"]
    T --> S{"scope == resource?"}
    S -- no --> R403b["403 scope mismatch"]
    S -- yes --> V{"JSON-Schema valid?<br/>(authoritative)"}
    V -- no --> R400["400 schema failed"]
    V -- yes --> F{"Firewall clean?<br/>(112 rules, DOTALL)"}
    F -- no --> R400b["400 firewall violation"]
    F -- yes --> W["worker /run<br/>(node-fs / node-db / node-net)"]
    W --> N{"node result?"}
    N -- "not found" --> R404["404 not found"]
    N -- "node error" --> R502["502 node error"]
    N -- ok --> EG{"Egress-DLP clean?<br/>(EGRESS_DLP)"}
    EG -- no --> R502b["502 egress block"]
    EG -- yes --> OK["200 result (audited)"]
```

Enforcement order at the enforcer, specific to a tool-call:

```mermaid
sequenceDiagram
    participant GW as "gateway :8000"
    participant IN as "ingress :8443"
    participant RG as "registry :8500"
    participant EN as "enforcer :8650"
    participant WK as "worker /run"
    GW->>IN: "POST /process {principal, resource, payload}"
    IN->>RG: "POST /authorize (RBAC allow-list)"
    RG-->>IN: "token + resource"
    IN->>EN: "POST /execute"
    Note over EN: "verify JWT -> jti in Redis -><br/>scope==resource -> JSON-Schema -><br/>firewall -> run -> egress-DLP -> size cap"
    EN->>WK: "POST /run (validated payload)"
    WK-->>EN: "result"
    EN-->>IN: "response (DLP-scanned)"
    IN-->>GW: "EGRESS audited"
```

---

### These tools behave identically across all providers

Because adapters only translate the model wire format, **the same tool definitions, schemas, RBAC, and firewall apply on every backend**. Switching a principal from Anthropic to a local model changes nothing about what `resource_filesystem` accepts. Configure the fleet in `config/model_inventory.yaml`.

**Anthropic (optimized) + OpenAI + local Ollama + vLLM + LiteLLM proxy:**

```yaml
# config/model_inventory.yaml
providers:
  provider_anthropic:                 # native Anthropic Messages API, normalized back to OpenAI
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true                    # optional: adaptive thinking
    effort: medium                    # optional: output_config.effort

  provider_openai:                    # near-passthrough OpenAI chat completions
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY       # Bearer auth

  provider_local:                     # Ollama speaks the OpenAI wire format
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY             # sentinel -> send NO Authorization header

  provider_vllm:                      # self-hosted vLLM, OpenAI-compatible
    type: openai
    endpoint: http://vllm:8000/v1/chat/completions
    api_key_env: NULL_KEY

  provider_litellm:                   # LiteLLM proxy in front of many models
    type: openai
    endpoint: http://litellm:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY       # or point at your own env var holding the proxy key
```

**Mixed fleet — different principals on different providers, one identical tool contract:**

```yaml
# config/model_inventory.yaml (models section)
models:
  principal_analyst:                  # Anthropic, optimized
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
  principal_auditor:                  # OpenAI
    provider: provider_openai
    upstream_model_id: "<openai-model-id>"
  principal_netbot:                   # local Ollama
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
  principal_admin:                    # Anthropic Sonnet
    provider: provider_anthropic
    upstream_model_id: claude-sonnet-5
```

> Use current Claude model IDs only: `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5`. `NULL_KEY` is the sentinel that tells the OpenAI adapter to omit the `Authorization` header entirely (for keyless local backends).

---

### Driving a tool from the edge (worked example)

Clients always POST `/v1/chat/completions` on the gateway (`:8000`, the only public service). Supply the tools; the model decides to call one; the gateway intercepts and enforces. The principal is resolved from the API key — not from the body.

```bash
# principal_analyst asks the model to write a sandbox file.
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gateway-managed",
    "messages": [
      { "role": "user", "content": "Save the note \"deploy done\" to notes.md" }
    ],
    "tools": [
      { "type": "function",
        "function": {
          "name": "resource_filesystem",
          "description": "Sandboxed filesystem read/list/write.",
          "parameters": {
            "type": "object",
            "additionalProperties": false,
            "required": ["action", "path"],
            "properties": {
              "action":  { "type": "string", "enum": ["read","list","write"] },
              "path":    { "type": "string" },
              "content": { "type": "string", "maxLength": 10240 }
            }
          }
        }
      }
    ]
  }'
```

The model emits a tool-call; the gateway forwards to ingress as the **authenticated** principal:

```json
{
  "principal": "principal_analyst",
  "resource":  "resource_filesystem",
  "payload":   { "action": "write", "path": "notes.md", "content": "deploy done" }
}
```

The client-supplied `model` field is advisory: the actual provider + upstream model are resolved from `model_inventory.yaml` for the authenticated principal. The gateway runs a **bounded agentic loop** (`MAX_TOOL_ROUNDS`, default 4); after the budget it forces a final answer with tools removed.

> To exercise the full pipeline against a live stack (valid/rejected corpus, every resource), run `scripts/probe_pipeline.py`. It replays the verified probe corpus and checks each verdict + control.

---

### HTTP status quick reference for tool-calls

| Status | When |
|---|---|
| **200** | Tool allowed and executed (response DLP-scanned, audited). |
| **400** | JSON-Schema validation failed, firewall violation, or invalid JSON. |
| **401** | Missing/invalid API key, or invalid/expired capability token. |
| **403** | RBAC policy violation, scope mismatch, or non-admin hitting `/runtime/sbom`. |
| **404** | Resource or file not found (e.g. `read` of a missing sandbox file). |
| **413** | Request body exceeds `max_input_size` (524288). |
| **429** | Fixed-window rate limit exceeded (`max_requests_per_min`, 10). |
| **502** | Upstream provider / worker-node error, or **egress-DLP block** on the response. |
| **503** | Rate limiter unavailable and `RATE_LIMIT_FAIL_CLOSED` is set (fail-closed). |

---

## Admin and Operations

This section is for operators who run and tune an Kybernos deployment: reading the runtime policy SBOM, managing rate limits, working with the encrypted audit trail, and re-pointing principals across Anthropic, OpenAI, and local backends — including turning on Anthropic's optimized `thinking`/`effort` path. Every control here is **model-agnostic**: switching a principal's backend never alters the RBAC, capability-token, JSON-Schema, firewall, egress-DLP, or audit behavior, because those run downstream on `{principal, resource, payload}`.

All administrative traffic goes to the only publicly reachable service, `service-gateway` on port **8000**. Control- and worker-tier services (ingress `:8443`, registry `:8500`, enforcer `:8650`, node-fs `:8620`, node-db `:8610`, node-net `:8630`, redis `:6379`) are reachable only by their legitimate caller under the zero-trust NetworkPolicy — do not expose them.

### Operator touch-points at a glance

```mermaid
flowchart TD
    Admin["Admin (principal_admin)"] -->|"GET /runtime/sbom"| GW["service-gateway :8000"]
    Client["Client / LLM app"] -->|"POST /v1/chat/completions"| GW
    GW --> AdmChk{"principal admin?"}
    AdmChk -->|"no"| D403["403 Forbidden"]
    AdmChk -->|"yes"| SBOM["Policy SBOM (no env, no secrets)"]
    GW --> RL{"count > max_requests_per_min?"}
    RL -->|"yes"| D429["429 Rate limit exceeded"]
    RL -->|"no"| ING["service-ingress :8443 /process"]
    ING -->|"encrypt INGRESS"| LOG[("Encrypted audit log (AES-256-GCM)")]
    ING --> PIPE["registry /authorize -> enforcer /execute"]
    PIPE -->|"encrypt EGRESS / EGRESS_DENIED"| LOG
```

---

### 1. The admin principal

Admin capability is a per-principal flag in `config/access_policy.yaml`. Only a principal with `admin: true` may call `GET /runtime/sbom`; the flag does **not** relax schema validation or the firewall — an admin's tool calls are still fully enforced.

| Principal | `admin` | Allowed resources | SBOM access |
|---|---|---|---|
| `principal_analyst` | — | `resource_filesystem`, `resource_database` | 403 |
| `principal_auditor` | — | `resource_database` | 403 |
| `principal_netbot` | — | `resource_network` | 403 |
| `principal_admin` | `true` | filesystem, database, network | allowed |

```yaml
# config/access_policy.yaml — grant admin (SBOM disclosure) to a principal
access_control_list:
  principal_admin:
    admin: true          # unlocks GET /runtime/sbom
    allowed_resources:
      - "resource_filesystem"
      - "resource_database"
      - "resource_network"
```

Identity is always resolved from the API key, never from the request body. Send the key as either header form:

```bash
# Both are accepted; pick one.
-H "Authorization: Bearer $ADMIN_KEY"
-H "X-API-Key: $ADMIN_KEY"
```

---

### 2. Runtime policy SBOM — `GET /runtime/sbom`

The SBOM is the live, boot-loaded set of policy objects: the model inventory, access policy, resource catalog, and security policy. It is the authoritative answer to "what is this gateway actually enforcing right now?" Crucially, **environment variables and secrets are never included** — the SBOM is policy-only.

```
runtime SBOM (policy objects only)
├── model_inventory     providers{type,endpoint,api_key_env,...} + principal→model map
├── access_policy       access_control_list (RBAC + admin flags)
├── resource_catalog    resources{endpoint,timeout,schema}
└── security_policy     system_limits + 112 semantic_firewall rules
    (no env vars, no API keys, no LOG_ENC_KEY_HEX, no JWT keys)
```

**Admin call (200):**

```bash
curl -s http://localhost:8000/runtime/sbom \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**Quick operational checks against the SBOM:**

```bash
# Which provider/model is each principal pointed at right now?
curl -s http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY" \
  | jq '.model_inventory.models'

# Confirm the active rate limit and size caps.
curl -s http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY" \
  | jq '.security_policy.system_limits'

# Count firewall rules (should be 112).
curl -s http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY" \
  | jq '.security_policy.semantic_firewall | length'
```

**Non-admin principal (403):**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/runtime/sbom \
  -H "Authorization: Bearer $ANALYST_KEY"
# 403   ("SBOM access requires an admin principal")
```

**No / invalid key (401):**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/runtime/sbom
# 401
```

---

### 3. Rate limiting and the `429` response

The gateway applies a **fixed-window, per-principal** limit backed by Redis before it resolves the provider or touches an upstream. The window is one calendar minute; each principal gets its own counter (`rl:<principal>:<window>`). When a principal's request count within the current minute exceeds `max_requests_per_min`, the request is rejected with **429**.

```yaml
# config/security_policy.yaml — tune the limit here
system_limits:
  max_input_size: 524288    # 512 KB request-body cap  -> 413 when exceeded
  max_output_size: 4096     # 4 KB enforcer output cap  -> 502 on egress
  token_ttl: 30             # capability-token TTL (seconds)
  max_requests_per_min: 10  # <-- the 429 threshold, per principal
```

Setting `max_requests_per_min` to `0` (or absent) disables the limiter.

**Fail-open vs. fail-closed.** If Redis itself is unreachable, behavior depends on `RATE_LIMIT_FAIL_CLOSED`:

| `RATE_LIMIT_FAIL_CLOSED` | Redis down → | Meaning |
|---|---|---|
| unset / `false` (default) | request proceeds | availability-first (fail-open) |
| `true` | `503` "Rate limiter unavailable" | security-first (fail-closed) |

```bash
# deploy/docker/.env  (or the container env)
RATE_LIMIT_FAIL_CLOSED=true
```

**Demonstrate the 429** (11 rapid calls for a principal capped at 10/min):

```bash
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "req $i -> %{http_code}\n" \
    -X POST http://localhost:8000/v1/chat/completions \
    -H "Authorization: Bearer $ANALYST_KEY" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"ping"}]}'
done
# req 1..10 -> 200/5xx (reaches pipeline);  req 11 -> 429
```

> Note: the window is a fixed clock minute, so a client can legitimately send up to `max_requests_per_min` at the tail of one minute and again at the head of the next. Size and content control the surrounding envelope: bodies over `max_input_size` return **413**; the payload still passes through the semantic firewall (**400** on a violation) regardless of rate state.

---

### 4. Encrypted audit trail (INGRESS / EGRESS)

Every tool call routed into the pipeline is journaled by `service-ingress`, encrypted with **AES-256-GCM** using `LOG_ENC_KEY_HEX`. Ingress emits an audit record at three phases:

| Phase | Emitted when | Payload logged |
|---|---|---|
| `INGRESS` | request enters `/process` | `{principal, resource, payload}` |
| `EGRESS` | pipeline returns a result | the enforcer's result |
| `EGRESS_DENIED` | enforcer returns non-200 | `{status, detail}` |

Records are written to the service log as a single line:

```
SECURE_LOG::<base64( 12-byte nonce || AES-256-GCM ciphertext )>
```

The plaintext inside each record is `{"phase": "<INGRESS|EGRESS|EGRESS_DENIED>", "data": {...}}`. Logs contain **no plaintext payloads** — only operators holding `LOG_ENC_KEY_HEX` can read them.

**Provision the key.** `LOG_ENC_KEY_HEX` is a 32-byte hex string (AES-256). `scripts/gen_keys.sh` generates it and writes it into `deploy/docker/.env`; to make one by hand:

```bash
openssl rand -hex 32     # -> set as LOG_ENC_KEY_HEX
```

```bash
# deploy/docker/.env
LOG_ENC_KEY_HEX=<64 hex chars>
```

In Kubernetes this is delivered as the `mcp-log-key` Secret by `deploy/k8s/apply.sh`. If the key is missing, `encrypt_audit_log` returns the marker `ERR_NO_KEY` instead of ciphertext — a clear signal the audit key was not injected.

**Read one record back** (operator-side; key never leaves the operator's control):

```bash
# Pull the ciphertext after the SECURE_LOG:: marker from the ingress logs.
docker compose -f deploy/docker/docker-compose.yml logs service-ingress \
  | grep 'SECURE_LOG::' | tail -n1 | sed 's/.*SECURE_LOG:://'
```

```python
# decrypt_audit.py — reverses ingress' encrypt_audit_log exactly.
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key  = bytes.fromhex(os.environ["LOG_ENC_KEY_HEX"])   # same key ingress used
blob = base64.b64decode(sys.stdin.read().strip())     # the base64 after SECURE_LOG::
nonce, ct = blob[:12], blob[12:]
print(json.dumps(json.loads(AESGCM(key).decrypt(nonce, ct, None)), indent=2))
# {"phase": "INGRESS", "data": {"principal": "...", "resource": "...", "payload": {...}}}
```

```bash
echo "$CIPHERTEXT" | LOG_ENC_KEY_HEX=$LOG_ENC_KEY_HEX python decrypt_audit.py
```

The response-side DLP is a separate, toggleable control (`EGRESS_DLP`) run by the enforcer over the worker's response; it is independent of audit encryption. A DLP block surfaces as **502** and is journaled as an `EGRESS_DENIED` record.

---

### 5. Switching a principal between Anthropic / OpenAI / local (config-only)

Because the gateway **edge is always OpenAI Chat-Completions-compatible**, clients keep POSTing `/v1/chat/completions` no matter which backend a principal uses. Re-pointing a principal is a one-line change in `config/model_inventory.yaml`'s `models:` map — no client change, no code change. The provider `type` selects the wire adapter (`anthropic` → native Messages API, normalized back to an OpenAI object; anything else → OpenAI-compatible). RBAC, tokens, schema, firewall, DLP, and audit are untouched.

> Config is loaded **at boot** from `CONFIG_PATH`. To apply an edit, redeploy/restart the gateway (below). "Runtime" here means "without touching clients or code," not hot-reload.

**Provider definitions** (define once; reuse across principals):

```yaml
# config/model_inventory.yaml
providers:

  # Anthropic — the optimized native path
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096

  # OpenAI (or any OpenAI-compatible cloud)
  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"

  # Local / self-hosted — Ollama
  provider_local:
    type: "openai"
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"        # NULL_KEY => send no Authorization header

  # Local — vLLM (OpenAI-compatible server), example
  provider_vllm:
    type: "openai"
    endpoint: "http://vllm:8000/v1/chat/completions"
    api_key_env: "NULL_KEY"

  # One LiteLLM proxy fronting many upstreams
  provider_litellm:
    type: "openai"
    endpoint: "http://litellm:4000/v1/chat/completions"
    api_key_env: "LITELLM_KEY"
```

**Point a principal at each backend** — swap `provider` + `upstream_model_id`:

```yaml
# --- Case A: analyst on LOCAL (offline, zero-config) ---
models:
  principal_analyst:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
```

```yaml
# --- Case B: same analyst promoted to Anthropic (optimized) ---
models:
  principal_analyst:
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
```

```yaml
# --- Case C: same analyst on OpenAI-compatible cloud ---
models:
  principal_analyst:
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"
```

**Mixed fleet** — different principals on different backends simultaneously:

```yaml
models:
  principal_admin:                 # Anthropic, optimized
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
  principal_analyst:               # local mistral
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_auditor:               # via LiteLLM proxy
    provider: "provider_litellm"
    upstream_model_id: "claude-sonnet-5"
  principal_netbot:                # OpenAI-compatible cloud
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"
```

Valid current Claude model IDs for the Anthropic path: `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5`.

**Provide each provider's key** (referenced by `api_key_env`, never stored in config, never in the SBOM):

```bash
# deploy/docker/.env
ANTHROPIC_API_KEY=sk-ant-...     # provider_anthropic
REMOTE_API_KEY=sk-...            # provider_openai
# NULL_KEY needs no value — the adapter sends no Authorization header
# LITELLM_KEY=...                # add for provider_litellm
```

A principal with no entry in `models:` is rejected with **403** ("no model provisioned").

**Apply the change:**

```bash
# Docker Compose — recreate the gateway to reload config/*.yaml
docker compose -f deploy/docker/docker-compose.yml up -d --force-recreate service-gateway

# Kubernetes — refresh the ConfigMap from config/, then roll the gateway
deploy/k8s/apply.sh                       # rebuilds the ConfigMap from config/
kubectl -n <namespace> rollout restart deployment/gateway
```

**Verify** the new mapping via the SBOM:

```bash
curl -s http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY" \
  | jq '.model_inventory.models.principal_analyst'
```

---

### 6. Enabling Anthropic `thinking` and `effort`

These optimizations apply only to providers of `type: "anthropic"`. Adding them to the provider block makes the Anthropic adapter inject the corresponding native fields; the response is still normalized back into a standard OpenAI `chat.completion` object, so clients see no difference in shape.

| Config key | Effect on the native Anthropic request | Notes |
|---|---|---|
| `thinking: true` | adds `thinking: {"type": "adaptive"}` | adaptive/extended thinking |
| `effort: "<level>"` | adds `output_config.effort: "<level>"` | `low` \| `medium` \| `high` \| `xhigh` \| `max` |
| `max_tokens: <n>` | sets `max_tokens` (required by Messages API) | defaults to `4096` if omitted |
| `anthropic_version` | sets the `anthropic-version` header | default `2023-06-01` |

```yaml
# config/model_inventory.yaml — optimized Anthropic provider
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true          # adaptive thinking
    effort: "high"          # low|medium|high|xhigh|max
```

Restart/roll the gateway as in Section 5, then the client call is unchanged — the same OpenAI-shaped request benefits from thinking/effort transparently:

```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "messages": [
          {"role":"user","content":"List the .md files under reports/ and summarize them."}
        ]
      }' | jq .
# Response is a normal OpenAI chat.completion object.
```

These settings are provider-level and inert for any non-`anthropic` provider (OpenAI, local, LiteLLM) — they are simply not emitted. The agentic tool loop is bounded independently by `MAX_TOOL_ROUNDS` (default `4`); after the budget is spent the gateway forces a final answer with tools removed, regardless of provider or thinking/effort.

---

### Operational status-code reference

| Code | When you'll see it (operations) |
|---|---|
| `200` | request allowed and completed |
| `400` | invalid JSON body, JSON-Schema validation failure, or firewall violation |
| `401` | missing/invalid API key, or invalid/expired capability token |
| `403` | RBAC denial, scope mismatch, non-admin hitting `/runtime/sbom`, or no model provisioned |
| `413` | body exceeds `max_input_size` |
| `429` | per-principal `max_requests_per_min` exceeded |
| `404` | resource or file not found |
| `502` | upstream provider/node error, or egress-DLP block |
| `503` | rate limiter unavailable with `RATE_LIMIT_FAIL_CLOSED=true` |

**Relevant environment variables:** `CONFIG_PATH`, `REDIS_URL`, `LOG_LEVEL`, `LOG_ENC_KEY_HEX`, `EGRESS_DLP`, `RATE_LIMIT_FAIL_CLOSED`, `MAX_TOOL_ROUNDS`, `UPSTREAM_TIMEOUT`, `ANTHROPIC_API_KEY`, `REMOTE_API_KEY`. None of these appear in the SBOM — policy and secrets are kept strictly separate.

---

## Understanding Responses and Errors

Every client talks to exactly one public surface — `POST /v1/chat/completions` on **service-gateway:8000** — and gets back either a normalized OpenAI `chat.completion` object (**200**) or an HTTP status code that names precisely which zero-trust control stopped the request. Because the edge is always OpenAI-Chat-Completions-compatible (the Anthropic path is normalized back to a `chat.completion` before it reaches you), the *shape* of a success never changes across providers, and the *meaning* of every error code is uniform.

> **A block is the system working.** The pipeline exists to refuse: `authenticate -> authorize -> mint scoped token -> validate (JSON-Schema) -> enforce (firewall) -> sandboxed execute -> egress-DLP -> audit`. A **400** from the semantic firewall or a **403** from RBAC is a *successful defense*, recorded in the encrypted audit log — not a bug and not something to retry with the same payload.

### Status codes at a glance

| Status | Name | Raised by | Meaning |
|---|---|---|---|
| **200** | OK | gateway edge / enforcer | Allowed. Normalized `chat.completion` (or tool result) returned. |
| **400** | Bad Request | gateway / enforcer | Invalid JSON body, **JSON-Schema validation failed**, or **semantic firewall violation**. |
| **401** | Unauthorized | gateway / enforcer | No or invalid **API key**, or invalid/expired **capability token**. |
| **403** | Forbidden | gateway / registry / enforcer | **RBAC** policy violation, **scope mismatch**, non-admin hitting `/runtime/sbom`, or **no model provisioned**. |
| **404** | Not Found | enforcer / worker | Resource or file not found. |
| **413** | Payload Too Large | gateway | Body exceeds `max_input_size` (524288 bytes). |
| **429** | Too Many Requests | gateway | Fixed-window rate limit exceeded (`max_requests_per_min` = 10). |
| **502** | Bad Gateway | gateway / enforcer | **Upstream provider / model error**, worker node error, or **egress-DLP block**. |
| **503** | Service Unavailable | gateway | Rate limiter (Redis) unavailable and `RATE_LIMIT_FAIL_CLOSED` is set — fail-closed. |

### Where each status is emitted

The gateway is the only externally reachable service; the control and worker tiers sit behind a default-deny NetworkPolicy. Knowing which tier emits a code tells you where to look.

```
CLIENT ──> service-gateway :8000
             │  401  (bad/missing API key)
             │  413  (body > max_input_size)
             │  429  (rate limit)  /  503  (limiter down, fail-closed)
             │  403  (no model provisioned  |  non-admin /runtime/sbom)
             │  502  (upstream LLM / provider error, UPSTREAM_TIMEOUT)
             └──> service-ingress :8443   (POST /process  {principal,resource,payload})
                    ├──> service-registry :8500   (POST /authorize)
                    │       403  (RBAC allow_list violation)
                    │       [mints ES256 token, valid_token:<jti> TTL=token_ttl=30s]
                    └──> service-enforcer :8650   (POST /execute)
                            401  (token invalid/expired: bad JWT or jti not in Redis)
                            403  (scope != resource)
                            400  (JSON-Schema fail  |  firewall BLOCK)
                            404  (file/resource not found)
                            502  (node /run error  |  egress-DLP block)
                            └──> node-fs :8620 / node-db :8610 / node-net :8630
```

### Status decision flow

```mermaid
flowchart TD
    A["POST /v1/chat/completions"] --> B{"Valid API key?"}
    B -- no --> E401["401 Unauthorized"]
    B -- yes --> C{"Body <= max_input_size?"}
    C -- no --> E413["413 Payload Too Large"]
    C -- yes --> D{"Under rate limit?"}
    D -- "limiter down (fail-closed)" --> E503["503 Service Unavailable"]
    D -- over --> E429["429 Too Many Requests"]
    D -- ok --> F{"Model provisioned for principal?"}
    F -- no --> E403a["403 no model"]
    F -- yes --> G{"Upstream LLM ok?"}
    G -- "error / timeout" --> E502a["502 provider error"]
    G -- "tool_call" --> H["ingress /process"]
    H --> I{"RBAC allow_list ok?"}
    I -- no --> E403b["403 RBAC"]
    I -- yes --> J{"Token valid + scope == resource?"}
    J -- "bad/expired token" --> E401b["401 invalid token"]
    J -- "scope mismatch" --> E403c["403 scope"]
    J -- ok --> K{"Schema + firewall pass?"}
    K -- no --> E400["400 blocked"]
    K -- yes --> L{"Worker run ok?"}
    L -- "file/resource missing" --> E404["404 Not Found"]
    L -- "node error / egress-DLP" --> E502b["502 node or DLP"]
    L -- ok --> M["200 OK"]
```

---

### 200 — Allowed

A success is always a normalized OpenAI `chat.completion`, regardless of whether the backend was Anthropic (`/v1/messages`), OpenAI, or a local model.

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-opus-4-8",
    "messages": [{"role":"user","content":"List the files in reports/"}]
  }'
```

Representative body:

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "choices": [
    { "index": 0,
      "message": { "role": "assistant", "content": "..." },
      "finish_reason": "stop" }
  ]
}
```

Identity is taken from the API key, **never** the request body — so the `model` you send is advisory; the real provider/model/adapter is resolved from `model_inventory.yaml` for the authenticated principal.

**Note on the bounded tool loop.** The gateway runs an agentic loop capped at `MAX_TOOL_ROUNDS` (default 4). When a tool call the model wanted is *blocked* by the pipeline (400/403/404), that failure is reported back to the model as a failed tool result and the loop continues; after the budget it forces a final answer with tools removed. The client can therefore still receive a **200** whose content explains that a tool could not be used — while no forbidden side effect ever ran. To observe the raw per-tool-call status codes directly, replay against a live stack with `scripts/probe_pipeline.py`.

---

### 401 — Unauthorized (identity failed)

Two distinct causes, at two tiers:

1. **Gateway / API key** — no `Authorization: Bearer <key>` and no `X-API-Key: <key>` header, or a key that is not in the `api_keys.json` map. Lookup uses `hmac.compare_digest`.
2. **Enforcer / capability token** — the minted ES256 JWT fails verification (bad signature, missing `exp`/`jti`/`scope`/`sub`), or its `valid_token:<jti>` entry is gone from Redis (expired past `token_ttl`=30s, or revoked). This is the replay/revocation gate.

```bash
# Missing key -> 401
curl -i http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}'
# HTTP/1.1 401 Unauthorized
```

**How to react:** confirm the key is provisioned in `secrets/api_keys.json` (or `AUTH_KEYS_JSON`), and that you sent exactly one auth header. For token-tier 401s, the token TTL is short by design — they are expected on replayed or long-delayed tool calls; re-issue by re-running the request.

---

### 403 — Forbidden (authenticated, but not allowed)

The principal is known but the action is not permitted. Four sub-cases:

| Sub-case | Raised by | Trigger |
|---|---|---|
| RBAC policy violation | registry `/authorize` | Resource not in the principal's `access_control_list` entry. |
| Scope mismatch | enforcer `/execute` | Token `scope` != requested `resource`. |
| Non-admin SBOM | gateway | `GET /runtime/sbom` without `admin: true`. |
| No model provisioned | gateway | Principal has no entry in the `models` map. |

RBAC entitlements (from `access_policy.yaml`):

```
principal_analyst  ->  [filesystem, database]
principal_auditor  ->  [database]
principal_netbot   ->  [network]
principal_admin    ->  [filesystem, database, network]   admin: true
```

So `principal_auditor` invoking `resource_filesystem` earns a clean **403** at the registry — RBAC is authoritative and runs *downstream of the provider adapter*, so switching models never changes this outcome.

```bash
# Non-admin principal hitting the SBOM -> 403
curl -i http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ANALYST_KEY"
# HTTP/1.1 403 Forbidden

# Admin principal -> 200 (env vars never appear in the SBOM)
curl -i http://localhost:8000/runtime/sbom -H "Authorization: Bearer $ADMIN_KEY"
# HTTP/1.1 200 OK
```

**How to react:** a 403 means "correct as configured." If a principal genuinely needs a resource, edit `access_policy.yaml`; do not loosen the firewall or schema to work around it.

---

### 400 — Blocked by schema or firewall (the defense fired)

A **400** means the tool-call payload was rejected by one of two enforcement layers, or the request body was not valid JSON:

- **JSON-Schema validation (AUTHORITATIVE)** — a precompiled `Draft202012Validator` per resource, with `additionalProperties: false`.
- **Semantic firewall (defense-in-depth)** — 112 regex rules, `re.DOTALL`, across 7 groups: `SQLI(29)`, `RCE(28)`, `LFI(20)`, `DLP(14)`, `FMT(8)`, `SSRF(7)`, `AI(6)`; each rule action is `BLOCK`.

The two layers are redundant on purpose: even if a schema were loosened, the firewall still blocks the classic attacks below. **A 400 here is the product succeeding.**

#### Example 1 — Path traversal (LFI)

```json
{ "action": "read", "path": "../../etc/passwd" }
```

Rejected twice: the `resource_filesystem` schema requires a `path` with **no leading slash, no `..`, and a safe extension** (`.txt|.json|.log|.md`), and the LFI firewall group matches the traversal. → **400**. (Even a schema-valid path that escaped the sandbox would be caught again at node-fs by the `realpath` + `os.sep` escape check.)

#### Example 2 — `DROP TABLE` (SQLI)

```json
{ "query": "DROP TABLE users; --" }
```

`resource_database` allows **only `SELECT` / `SHOW` / `DESCRIBE ... FROM`** statements (`maxLength` 512). A `DROP` never matches the allowed prefix, and the SQLI group flags it independently. → **400**.

#### Example 3 — HTTP to an internal IP (SSRF)

```json
{ "url": "http://169.254.169.254/latest/meta-data/", "method": "GET" }
```

`resource_network` requires **`https` only, no internal IPs, method `GET` only** (`maxLength` 256). The `http://` scheme and link-local metadata address are both rejected by schema, and the SSRF group blocks the internal target. → **400**.

**How to react:** do not retry the same payload — it will be blocked identically and audited again. Fix the input to satisfy the resource schema. If a legitimate input is being blocked (a false positive), that is a firewall-rule tuning conversation, not a bypass; the schema stays authoritative. An **invalid JSON body** at the edge also returns 400.

---

### 413 — Payload Too Large

The request body exceeded `max_input_size` (**524288 bytes**), enforced at the gateway before any upstream call. Trim the request (large `content` fields, oversized message history) and resend. This is a hard edge cap and is independent of provider.

---

### 429 — Too Many Requests

The Redis fixed-window rate limiter rejected the request: more than `max_requests_per_min` (**10**) in the current window for that principal. Back off and retry in the next window.

```bash
# 11th request inside one minute for the same principal -> 429
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:8000/v1/chat/completions \
    -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
    -d '{"model":"claude-opus-4-8","messages":[{"role":"user","content":"ping"}]}'
done
# ... 200 200 ... 429
```

**Related: 503.** If the limiter's Redis backend is unreachable *and* `RATE_LIMIT_FAIL_CLOSED` is set, the gateway returns **503** rather than admitting un-limited traffic — a deliberate fail-closed posture. Restore Redis (`REDIS_URL`) to clear it.

---

### 404 — Not Found

The RBAC check, token, schema, and firewall all passed, but the target does not exist: an unknown resource, or a file the sandbox could not find (e.g., `read` of `reports/missing.txt`). This is the one "empty result" error that is *not* a policy failure — the request was well-formed and permitted. Verify the path/resource name and that the file exists under the sandbox root (`/app/data/sandbox`, or `SANDBOX_DIR`).

---

### 502 — Upstream provider, worker node, or egress-DLP block

**502** covers everything that failed *after* the request was accepted and authorized, at the far side of a network hop:

- **Upstream LLM / provider error or model error** — the provider returned an error, the API key named by `api_key_env` was rejected, or the call exceeded `UPSTREAM_TIMEOUT`.
- **Worker node error** — node-fs/db/net `/run` failed.
- **Egress-DLP block** — the firewall, run over the *response* (toggle `EGRESS_DLP`), matched a DLP rule and refused to return the data. This is a *successful* data-loss-prevention action, not an outage.

Diagnosis matrix:

| Symptom | Likely cause | Action |
|---|---|---|
| 502 on **every** call for one principal | Wrong/missing secret named by `api_key_env`; unreachable `endpoint` | Verify the env var the provider references is populated; check `endpoint` reachability. |
| 502 after a consistent delay | Upstream slow; `UPSTREAM_TIMEOUT` hit | Raise `UPSTREAM_TIMEOUT` or investigate the provider. |
| 502 only on responses carrying sensitive data | Egress-DLP blocked the response | Expected. Inspect the encrypted EGRESS audit; only relax via `EGRESS_DLP` if it is a confirmed false positive. |
| **403** (not 502) before any upstream call | Principal missing from the `models` map | Add a `principal -> provider + upstream_model_id` mapping (below). |

#### Provider/model configuration — the source of most 403/502s

Provider and model errors trace back to `model_inventory.yaml`. Adapters only translate the *wire format* (`AnthropicAdapter` for `type: anthropic`, `OpenAIAdapter` for every other type); RBAC, tokens, schema, firewall, DLP, and audit are provider-independent, so **a 502 is never a policy problem — it is a connectivity/credential/config problem.**

**Anthropic (optimized)** — native Messages API, normalized back to `chat.completion`, with the optional `thinking`/`effort` accelerators:

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true      # -> adaptive thinking
    effort: high        # -> output_config.effort
```

**OpenAI** — near-passthrough, Bearer auth:

```yaml
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
```

**Local (Ollama / vLLM)** — OpenAI-compatible; `NULL_KEY` sends no `Authorization` header:

```yaml
  provider_local:               # Ollama
    type: openai
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY

  provider_vllm:                # vLLM (same OpenAI-compatible shape)
    type: openai
    endpoint: http://<vllm-host>:<port>/v1/chat/completions
    api_key_env: NULL_KEY
```

**LiteLLM proxy** — any non-`anthropic` type uses the OpenAI adapter; point `endpoint` at the proxy:

```yaml
  provider_litellm:
    type: openai   # any non-anthropic type -> OpenAIAdapter
    endpoint: http://<litellm-host>:<port>/v1/chat/completions
    api_key_env: REMOTE_API_KEY
```

**Mixed fleet** — different principals on different providers. A principal **absent from this map returns 403 (no model provisioned)**, not 502:

```yaml
models:
  principal_admin:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
  principal_analyst:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
  principal_auditor:
    provider: provider_openai
    upstream_model_id: <your-openai-model>
  principal_netbot:
    provider: provider_litellm
    upstream_model_id: <model-served-by-proxy>
```

---

### Reading the record behind any status

Every decision — allow or block — is captured in the **encrypted audit log** (INGRESS on the way in, EGRESS on the way out; AES-256-GCM under `LOG_ENC_KEY_HEX`). When a status surprises you:

1. Hit the unauthenticated liveness probes to separate "service down" from "request refused": `GET /healthz` on `:8000` (edge) and, from inside the mesh, on `:8443` / `:8500` / `:8650` / the worker nodes.
2. Reproduce the exact verdict against a live stack with `scripts/probe_pipeline.py` (replays the verified corpus with ground-truth verdict + control), or run `scripts/forensic_auditor.py` for an auth-aware end-to-end trace.
3. Decrypt the audit entries to see which control fired and on which `{principal, resource, payload}`.

**Bottom line:** 200 is success; 404 is an honest empty result; 401/413/429/503 are front-door hygiene; **400 and 403 are the zero-trust controls doing exactly what they exist to do**; and 502 points at a provider, node, or DLP event — fix the connection or credential, never the policy.

---

## Provider Setup Guides

Kybernos is **model-agnostic**. The gateway edge is *always* OpenAI-Chat-Completions-compatible — your clients always `POST http://<gateway>:8000/v1/chat/completions` no matter which model sits behind it. The backend is chosen by configuration, not by the client, and switching it **never** changes the zero-trust controls (RBAC, capability tokens, JSON-Schema validation, the 112-rule firewall, egress DLP, and encrypted audit all run downstream on `{principal, resource, payload}`).

Two things you edit for every provider guide below live in `config/`:

| File | What you set |
| --- | --- |
| `config/model_inventory.yaml` | `providers:` (type, endpoint, `api_key_env`, optional per-provider fields) and `models:` (which principal uses which provider + `upstream_model_id`) |
| `config/access_policy.yaml` | `access_control_list` (already ships with 4 principals) |

Identity is resolved from the **API key**, never the request body. The key → principal map lives in `secrets/api_keys.json`; the principal → provider map lives in `model_inventory.yaml`. So "which provider answers a request" is decided by *which API key you send*.

### How a request is routed to a provider

```mermaid
flowchart TD
  C["Client POST /v1/chat/completions"] --> G["Gateway :8000 authN (Bearer / X-API-Key)"]
  G --> P["principal (from api_keys.json)"]
  P --> M["model_inventory.yaml: principal to provider + upstream_model_id"]
  M --> T{"provider type"}
  T -->|anthropic| A["AnthropicAdapter -> POST /v1/messages (x-api-key)"]
  T -->|"openai / local / ollama / vllm / litellm / ..."| O["OpenAIAdapter -> POST /v1/chat/completions (Bearer or none)"]
  A --> N["normalize back to chat.completion"]
  O --> N
  N --> Z["ZTA pipeline: RBAC to token to schema to firewall to sandbox to DLP to audit"]
  Z --> R["client-facing OpenAI response"]
```

**Provider `type` → adapter** (only the wire format changes):

```
type: "anthropic"   -> AnthropicAdapter  (native Messages API, first-class/optimized)
type: anything-else -> OpenAIAdapter     (openai, local, ollama, vllm, lmstudio,
                                          llama.cpp, litellm, together, groq, ...)
```

### Prerequisites (do this once)

```bash
# From the repo root. Generates ES256 keys, secrets/api_keys.json,
# and deploy/docker/.env (with LOG_ENC_KEY_HEX + REMOTE_API_KEY placeholder).
scripts/gen_keys.sh
# -> prints the four API keys ONCE. Save them:
#      analyst / auditor / netbot / admin
```

Capture the keys into shell variables so the verifying `curl`s below work:

```bash
export ADMIN_KEY="mcp_...admin..."      # -> principal_admin
export ANALYST_KEY="mcp_...analyst..."  # -> principal_analyst
export GW="http://localhost:8000"
curl -s "$GW/healthz"                    # sanity check the edge is up
```

Bring the stack up after any config edit:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

---

### (A) Use Claude / Anthropic — the optimized path

The default config already maps `principal_admin` to Anthropic + `claude-opus-4-8`. You only need to supply the key and (optionally) turn on thinking.

**1. Get a key.** Create an Anthropic API key in the Anthropic Console (format looks like `sk-ant-api03-...`). Do **not** paste it into any config file — it is injected by environment variable only.

**2. Set `ANTHROPIC_API_KEY`.** `deploy/docker/docker-compose.yml` already forwards `ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}` into the gateway. `gen_keys.sh` does not write this line, so add it to `deploy/docker/.env`:

```bash
# deploy/docker/.env  (gitignored — never commit)
LOG_ENC_KEY_HEX=<generated by gen_keys.sh>
REMOTE_API_KEY=
ANTHROPIC_API_KEY=sk-ant-api03-REPLACE_ME
```

**3. Map admin to `claude-opus-4-8` and enable thinking.** In `config/model_inventory.yaml`:

```yaml
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096          # Anthropic Messages API requires this
    thinking: true            # adaptive thinking  -> body thinking:{type:"adaptive"}
    effort: "high"            # low|medium|high|xhigh|max -> output_config.effort

models:
  principal_admin:
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"   # or claude-sonnet-5 / claude-haiku-4-5
```

The `AnthropicAdapter` extracts the system prompt to a top-level `system` field, converts OpenAI function tools to `name`/`description`/`input_schema`, returns `tool_use` blocks, and **normalizes the reply back to an OpenAI `chat.completion`** so the edge stays uniform.

**4. Restart and verify.** `principal_admin` may use all three resources and unlocks `/runtime/sbom`.

```bash
docker compose -f deploy/docker/docker-compose.yml up --build -d

curl -s "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "claude-opus-4-8",
        "messages": [
          {"role": "user", "content": "List the files under reports/ and read report.md"}
        ]
      }'
# 200 -> OpenAI-shaped chat.completion. The upstream model is resolved from the
# admin principal, so the body "model" field is informational only.
```

> Note: the request body follows OpenAI chat format regardless of backend. The gateway runs a bounded agentic tool loop (`MAX_TOOL_ROUNDS`, default 4) and forces a final answer once the budget is spent.

---

### (B) Use OpenAI

**1. Get a key** from the OpenAI dashboard (`sk-...`). The default `provider_openai` reads it from `REMOTE_API_KEY` (already forwarded by compose and present as a placeholder in `.env`).

**2. Set the key** in `deploy/docker/.env`:

```bash
REMOTE_API_KEY=sk-REPLACE_ME
```

**3. Point a principal at OpenAI** in `config/model_inventory.yaml`. `provider_openai` already exists; just map a principal to it:

```yaml
providers:
  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"

models:
  principal_analyst:
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"   # any model your OpenAI account can serve
```

The `OpenAIAdapter` is near-passthrough and sends `Authorization: Bearer <REMOTE_API_KEY>`.

**4. Restart and verify** with the *analyst* key (analyst may use filesystem + database, not network):

```bash
curl -s "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Query the users table with a SELECT."}]
      }'
```

Any OpenAI-compatible **cloud** (Together, Groq, etc.) uses the same recipe: `type: "openai"`, that vendor's `endpoint`, and an `api_key_env` you add to `.env`.

---

### (C) Use a fully local / offline model with Ollama (no keys leave the box)

For an air-gapped or key-free deployment, point at a local OpenAI-compatible server. The special sentinel `NULL_KEY` tells the adapter to send **no `Authorization` header** — nothing to leak.

**1. Run Ollama on the host** and pull a model:

```bash
ollama serve
ollama pull mistral:7b-instruct
```

**2. Config is already the default.** `provider_local` targets Ollama via `host.docker.internal` (compose sets `extra_hosts: ["host.docker.internal:host-gateway"]`). All three non-admin principals already use it:

```yaml
providers:
  provider_local:
    type: "openai"                                                   # OpenAI-compatible wire
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"                                          # send no Authorization header

models:
  principal_analyst:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_auditor:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_netbot:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
```

**vLLM / LM Studio / llama.cpp** are identical — only the `endpoint` and `upstream_model_id` change, `type` stays `"openai"`:

```yaml
  provider_vllm:
    type: "openai"
    endpoint: "http://host.docker.internal:8000/v1/chat/completions"  # your vLLM server
    api_key_env: "NULL_KEY"
```

**3. Restart and verify** — no cloud key required anywhere:

```bash
curl -s "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"mistral:7b-instruct","messages":[{"role":"user","content":"list files in the sandbox"}]}'
```

Because `NULL_KEY` suppresses the auth header and the endpoint is on-host, **no secret ever leaves the machine**. The full ZTA pipeline still runs.

---

### (D) Use many providers via LiteLLM

Run one [LiteLLM](https://github.com/BerriAI/litellm) proxy to front many upstreams behind a single OpenAI-compatible endpoint. To the gateway it is just another `type: "openai"` provider.

**1. Run the LiteLLM proxy** (its own config lists your upstream models) so it serves `http://litellm:4000/v1/chat/completions`, and give it a master key.

**2. Add the provider** in `config/model_inventory.yaml` and a matching env var:

```yaml
providers:
  provider_litellm:
    type: "openai"
    endpoint: "http://litellm:4000/v1/chat/completions"
    api_key_env: "LITELLM_KEY"        # add LITELLM_KEY to deploy/docker/.env

models:
  principal_analyst:
    provider: "provider_litellm"
    upstream_model_id: "gpt-4o-mini"        # a model name LiteLLM knows
  principal_auditor:
    provider: "provider_litellm"
    upstream_model_id: "claude-haiku-4-5"   # LiteLLM routes it upstream
```

```bash
# deploy/docker/.env
LITELLM_KEY=sk-litellm-REPLACE_ME
```

> `LITELLM_KEY` is read by `api_key_env` and sent as `Authorization: Bearer <LITELLM_KEY>`. Add it to the gateway's `environment:` block in `docker-compose.yml` (alongside `ANTHROPIC_API_KEY` / `REMOTE_API_KEY`) so it reaches the container. Under Kubernetes, add it to the `mcp-provider` Secret.

**3. Verify** with whichever principal you mapped:

```bash
curl -s "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $ANALYST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}'
```

---

### Mixed fleet — different principals on different providers

Every principal is provisioned independently, so you can run Claude, OpenAI, and a local model side by side. This one `model_inventory.yaml` snippet does exactly that:

```yaml
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true
  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"
  provider_local:
    type: "openai"
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"

models:
  principal_admin:                 # premium reasoning on Claude
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
  principal_analyst:               # cloud OpenAI
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"
  principal_auditor:               # cheap/offline local
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_netbot:                # offline local
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
```

```
principal          provider            model                type       auth
-----------------  ------------------  -------------------  ---------  --------------------
principal_admin    provider_anthropic  claude-opus-4-8      anthropic  x-api-key (ANTHROPIC_API_KEY)
principal_analyst  provider_openai     gpt-4o-mini          openai     Bearer (REMOTE_API_KEY)
principal_auditor  provider_local      mistral:7b-instruct  openai     none (NULL_KEY)
principal_netbot   provider_local      mistral:7b-instruct  openai     none (NULL_KEY)
```

RBAC is unchanged by the model choice: `principal_admin` still reaches all three resources (and `/runtime/sbom`), `principal_analyst` filesystem+database, `principal_auditor` database only, `principal_netbot` network only.

---

### Verifying and troubleshooting

| Symptom | HTTP | Likely cause / fix |
| --- | --- | --- |
| `curl $GW/healthz` fails | — | Gateway not up; check `docker compose ... up` and port `8000` |
| Request rejected at the edge | `401` | Missing/invalid API key — send `Authorization: Bearer <key>` or `X-API-Key: <key>` |
| Provider call refused | `403` | **No model provisioned** for this principal — add it under `models:`; or RBAC/scope violation |
| Provider errors / bad key | `502` | Upstream provider or worker error (or egress-DLP block). Verify `ANTHROPIC_API_KEY` / `REMOTE_API_KEY` / `LITELLM_KEY` is set and correct |
| Payload rejected | `400` | JSON-Schema validation or firewall violation (or invalid JSON) — provider-independent |
| Too many calls | `429` | Fixed-window rate limit `max_requests_per_min` (default 10) |
| Body too big | `413` | Exceeds `max_input_size` (524288 bytes) |

**Common mistakes**

- **Never** put a provider key in `config/*.yaml`. Keys come only from the env vars named by `api_key_env` (`ANTHROPIC_API_KEY`, `REMOTE_API_KEY`, `LITELLM_KEY`, …). `NULL_KEY` means *send no auth header*.
- The request-body `model` field is informational; the real upstream model is resolved from the **principal's** `model_inventory.yaml` entry.
- Anthropic requires `max_tokens` — keep it in `provider_anthropic`. `thinking`/`effort` are opt-in optimizations that apply only to `type: "anthropic"`.
- For local providers, keep the compose `extra_hosts: ["host.docker.internal:host-gateway"]` so the container can reach a host-run Ollama/vLLM.

---

## Running on Kubernetes

This section is the operator quickstart for standing up **Kybernos** on a Kubernetes cluster. The manifests in `deploy/k8s/` deploy all eight services with a default-deny NetworkPolicy, restricted Pod Security Standards, and horizontal autoscaling on the two hot-path services (gateway and enforcer). The edge stays OpenAI-Chat-Completions-compatible regardless of which upstream model you wire in, so nothing about the client contract changes when you swap providers — only `config/model_inventory.yaml` changes.

> The namespace is defined in `deploy/k8s/00-namespace.yaml`. All commands below assume it is named `mcp`; substitute your actual namespace name if it differs.

### Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Kubernetes 1.25+ | Pod Security Standards `restricted`, HPA `autoscaling/v2` | `kubectl version` |
| `kubectl` (matching cluster) | Apply manifests, port-forward, watch rollout | `kubectl cluster-info` |
| A container runtime + image builder | Build `mcp-universal:6.0` from `deploy/docker/Dockerfile` | `docker version` |
| Image reachable by nodes | Local cluster (kind/minikube) via image load, or a registry your nodes can pull | see Step 1 |
| An Ingress controller (optional) | Only if you use `60-ingress` for real external exposure | `kubectl get pods -A \| grep ingress` |
| `metrics-server` | HPA needs CPU/memory metrics or it stays `<unknown>` | `kubectl top pods -n mcp` |
| Provider API keys | `ANTHROPIC_API_KEY` and/or `REMOTE_API_KEY` (OpenAI-style backends) | you supply these |
| `openssl` | `scripts/gen_keys.sh` mints the ES256 keypair + log key | `openssl version` |

### Manifest layout

```
deploy/k8s/
├── 00-namespace.yaml       # namespace, Pod Security Standards = restricted
├── 10-redis.yaml           # redis-store  (state zone)        :6379
├── 20-workers.yaml         # node-fs :8620  node-db :8610  node-net :8630
├── 30-core.yaml            # ingress :8443  registry :8500  enforcer :8650
├── 40-gateway.yaml         # gateway :8000 + HPA (gw 3–20, enf 2–12) + PodDisruptionBudget
├── 50-networkpolicy.yaml   # default-deny ingress + per-caller allows + DNS egress
├── 60-ingress.yaml         # Ingress: external exposure of the gateway only
└── apply.sh                # namespace → ConfigMap(config/) → Secrets → kubectl apply
```

| Manifest | Objects created | Notes |
|---|---|---|
| `00-namespace` | `Namespace` | labeled for PSS `restricted` |
| `10-redis` | `redis-store` Deployment + Service `:6379` | rate-limit / replay / token store |
| `20-workers` | `node-fs :8620`, `node-db :8610`, `node-net :8630` | worker zone; fs is sandboxed, db is read-only SQL, net is SSRF-safe egress |
| `30-core` | `service-ingress :8443`, `service-registry :8500`, `service-enforcer :8650` | control zone |
| `40-gateway` | `service-gateway :8000` Deployment + Service, **HPA** (gateway 3–20, enforcer 2–12), **PodDisruptionBudget** | only public-facing service |
| `50-networkpolicy` | `NetworkPolicy` set | default-deny ingress, per-caller allows, DNS egress |
| `60-ingress` | `Ingress` | optional external route to the gateway |

All pods run `runAsNonRoot` (uid 1000), `readOnlyRootFilesystem`, drop **ALL** capabilities, use `seccompProfile: RuntimeDefault`, carry resource requests/limits, and expose `/healthz` for liveness/readiness probes. The image is `mcp-universal:6.0`.

### Cluster topology

```mermaid
flowchart TD
    client["client<br/>POST /v1/chat/completions"] -->|":8000"| gw
    gw -.->|"DNS egress"| upstream["upstream LLM<br/>(Anthropic / OpenAI / local)"]

    subgraph ns["namespace: mcp (PSS restricted)"]
        subgraph edge["edge zone"]
            gw["service-gateway :8000<br/>HPA 3–20 · public"]
        end
        subgraph control["control zone"]
            ing["service-ingress :8443"]
            reg["service-registry :8500<br/>RBAC + mint JWT"]
            enf["service-enforcer :8650<br/>schema + firewall + exec · HPA 2–12"]
        end
        subgraph worker["worker zone"]
            fs["node-fs :8620<br/>sandboxed FS"]
            db["node-db :8610<br/>read-only SQL"]
            net["node-net :8630<br/>SSRF-safe HTTP"]
        end
        subgraph state["state zone"]
            redis["redis-store :6379"]
        end

        gw -->|"/process"| ing
        ing -->|"/authorize"| reg
        ing -->|"/execute"| enf
        enf -->|"/run"| fs
        enf -->|"/run"| db
        enf -->|"/run"| net
        gw -.-> redis
        reg -.-> redis
        enf -.-> redis
    end
```

The `50-networkpolicy` default-deny means each service is reachable **only** by its legitimate caller (gateway→ingress→registry/enforcer→workers, plus Redis from the services that need it, plus DNS egress). Only `service-gateway` is externally reachable.

---

### Step 1 — Build and load the image

Build once from the repo root:

```bash
docker build -t mcp-universal:6.0 -f deploy/docker/Dockerfile .
```

Then make the image available to your nodes.

```bash
# kind
kind load docker-image mcp-universal:6.0

# minikube
minikube image load mcp-universal:6.0

# real cluster: tag + push to a registry your nodes can pull, e.g.
docker tag  mcp-universal:6.0 registry.example.com/mcp-universal:6.0
docker push registry.example.com/mcp-universal:6.0
# (then update the image reference in 20-workers/30-core/40-gateway to match)
```

### Step 2 — Generate keys and API keys

`scripts/gen_keys.sh` mints the ES256 signing keypair, the AES-256-GCM audit-log key, and the client API-key map. It prints secrets **once** and commits nothing.

```bash
./scripts/gen_keys.sh
```

It produces:

| Artifact | Consumed as | K8s Secret (created by `apply.sh`) |
|---|---|---|
| ES256 keypair → `keys/` | `PRIV_KEY_PATH` / `PUB_KEY_PATH` (capability-token JWT sign/verify) | `mcp-keys` |
| `LOG_ENC_KEY_HEX` → `deploy/docker/.env` | audit-log AES-256-GCM key | `mcp-log-key` |
| API key → principal map → `secrets/api_keys.json` | `AUTH_KEYS_PATH` (client authentication) | `mcp-api-keys` |

Keep the printed client API keys — you will need one to call the gateway in Step 6.

### Step 3 — Provider credentials and `model_inventory.yaml`

Client identity is always the **API key**, and the gateway resolves each principal's provider + upstream model + adapter from `config/model_inventory.yaml`. The upstream provider keys live in the **`mcp-provider`** Secret, which carries exactly two values: `ANTHROPIC_API_KEY` (native Anthropic Messages API) and `REMOTE_API_KEY` (any OpenAI-compatible backend). `apply.sh` creates this Secret; you supply the values via the environment:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."     # native Anthropic path
export REMOTE_API_KEY="sk-..."            # OpenAI / LiteLLM / any Bearer backend
```

If you prefer to manage the provider Secret out-of-band (rotation, external secret store), create it directly — the namespace must exist first (`apply.sh` creates it, or run `kubectl apply -f deploy/k8s/00-namespace.yaml`):

```bash
kubectl -n mcp create secret generic mcp-provider \
  --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  --from-literal=REMOTE_API_KEY="$REMOTE_API_KEY"
```

> `NULL_KEY` is a **sentinel**, not a secret: when a provider's `api_key_env` is `NULL_KEY`, the OpenAI adapter sends **no** `Authorization` header (for keyless local inference). It never goes in `mcp-provider`.

Every example below only ever references `ANTHROPIC_API_KEY`, `REMOTE_API_KEY`, or `NULL_KEY` — the three provider key names the system knows about. Adapters translate the wire format only; RBAC, capability tokens, JSON-Schema validation, firewall, egress DLP, and audit are provider-independent and unchanged by any of these choices.

**Anthropic (optimized) — native Messages API, normalized back to OpenAI:**

```yaml
# config/model_inventory.yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true          # optional -> adaptive thinking
    effort: high            # optional -> output_config.effort
models:
  principal_analyst:
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
```

**OpenAI — near-passthrough, Bearer auth:**

```yaml
providers:
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
models:
  principal_auditor:
    provider: provider_openai
    upstream_model_id: gpt-4o
```

**Local (Ollama / vLLM) — keyless via `NULL_KEY`:**

```yaml
providers:
  # Ollama (default distribution value)
  provider_local:
    type: ollama
    endpoint: http://host.docker.internal:11434/v1/chat/completions
    api_key_env: NULL_KEY
  # vLLM in-cluster OpenAI-compatible server (set endpoint to your Service DNS)
  provider_vllm:
    type: vllm
    endpoint: http://vllm.mcp.svc.cluster.local:8000/v1/chat/completions
    api_key_env: NULL_KEY
models:
  principal_netbot:
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
```

> On Kubernetes, `host.docker.internal` is a Docker-desktop convenience and generally does **not** resolve in-cluster. Point a local provider's `endpoint` at a reachable target — an in-cluster Service DNS name (as in `provider_vllm`) or an external inference host. `type` can be `ollama`, `vllm`, `local`, etc.; every non-`anthropic` type uses the OpenAI adapter.

**LiteLLM proxy — OpenAI-compatible front for many backends:**

```yaml
providers:
  provider_litellm:
    type: litellm     # any non-anthropic type -> OpenAIAdapter
    endpoint: http://litellm.mcp.svc.cluster.local:4000/v1/chat/completions
    api_key_env: REMOTE_API_KEY
models:
  principal_analyst:
    provider: provider_litellm
    upstream_model_id: bedrock/claude-opus-4-8
```

**Mixed fleet — different principals on different providers, one edge:**

```yaml
providers:
  provider_anthropic:
    type: anthropic
    endpoint: https://api.anthropic.com/v1/messages
    api_key_env: ANTHROPIC_API_KEY
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    thinking: true
  provider_openai:
    type: openai
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: REMOTE_API_KEY
  provider_local:
    type: ollama
    endpoint: http://vllm.mcp.svc.cluster.local:8000/v1/chat/completions
    api_key_env: NULL_KEY
models:
  principal_analyst:                  # premium native Anthropic
    provider: provider_anthropic
    upstream_model_id: claude-opus-4-8
  principal_auditor:                  # frontier OpenAI
    provider: provider_openai
    upstream_model_id: gpt-4o
  principal_netbot:                   # cheap keyless local
    provider: provider_local
    upstream_model_id: mistral:7b-instruct
  principal_admin:                    # fast Anthropic
    provider: provider_anthropic
    upstream_model_id: claude-haiku-4-5
```

The principal names above (`principal_analyst`, `principal_auditor`, `principal_netbot`, `principal_admin`) are the same identities carried in `config/access_policy.yaml`, so a principal's model and its RBAC allow-list stay in lock-step. A model listed here for a principal not present in the access policy will authenticate but be denied at `/authorize` (403).

`config/` (including `model_inventory.yaml`) is published to the cluster as a **ConfigMap by `apply.sh`** and mounted at `CONFIG_PATH`; env values never land in the SBOM.

### Step 4 — Apply the stack

`apply.sh` creates the namespace, builds the ConfigMap from `config/`, creates the four Secrets (`mcp-keys`, `mcp-log-key`, `mcp-api-keys`, `mcp-provider`), and applies every manifest in order.

```bash
# with ANTHROPIC_API_KEY / REMOTE_API_KEY still exported from Step 3:
./deploy/k8s/apply.sh
```

| Secret | Contents | Backs env |
|---|---|---|
| `mcp-keys` | ES256 private + public key (from `keys/`) | `PRIV_KEY_PATH`, `PUB_KEY_PATH` |
| `mcp-log-key` | `LOG_ENC_KEY_HEX` | audit-log AES-256-GCM |
| `mcp-api-keys` | `api_keys.json` (key → principal) | `AUTH_KEYS_PATH` |
| `mcp-provider` | `ANTHROPIC_API_KEY`, `REMOTE_API_KEY` | upstream provider auth |

### Step 5 — Watch the rollout

```bash
# Wait for each Deployment to become available
kubectl -n mcp rollout status deploy/redis-store
kubectl -n mcp rollout status deploy/service-registry
kubectl -n mcp rollout status deploy/service-enforcer
kubectl -n mcp rollout status deploy/service-ingress
kubectl -n mcp rollout status deploy/service-gateway

# Live view of everything
kubectl -n mcp get pods,svc,hpa -o wide
kubectl -n mcp get pods -w
```

Confirm health once pods are `Running`/`Ready`:

```bash
# healthz through a pod (no external exposure needed)
kubectl -n mcp exec deploy/service-gateway -- \
  wget -qO- http://localhost:8000/healthz
```

Expected `Ready` counts reflect the HPA minimums: **gateway ≥ 3**, **enforcer ≥ 2**; single replicas for ingress, registry, workers, and Redis.

### Step 6 — Port-forward and smoke-test

`kubectl port-forward` tunnels through the API server to the pod, so it works even with the default-deny NetworkPolicy in place — no Ingress required for a local check.

```bash
kubectl -n mcp port-forward svc/service-gateway 8000:8000
```

In a second shell, health first, then a real tool-brokering call using a **client API key** from `secrets/api_keys.json`:

```bash
# liveness
curl -s http://localhost:8000/healthz

# a chat completion that drives a filesystem tool call through the full pipeline
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer <CLIENT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "auto",
        "messages": [
          {"role": "user", "content": "List the files in the sandbox and read notes.txt"}
        ]
      }'
```

Notes:
- Either `Authorization: Bearer <key>` or `X-API-Key: <key>` authenticates. Identity comes from the key, **never** the request body.
- The `model` field is a placeholder — the gateway resolves the real provider + upstream model + adapter from `model_inventory.yaml` by principal, so `"auto"` is fine.
- Status codes you may see: `200` allowed · `401` missing/invalid key · `403` RBAC / no model provisioned · `400` schema or firewall violation · `413` body too large · `429` rate limited · `404` file/resource not found · `502` upstream/worker or egress-DLP block · `503` rate limiter unavailable (fail-closed).

For real external exposure, use the `60-ingress` Ingress object (requires an Ingress controller) instead of port-forward. Admin-only endpoints (`GET /runtime/sbom`) require a principal with `admin: true` (`principal_admin`); non-admins get `403`.

### Step 7 — Autoscaling and disruption budget

`40-gateway` ships an `HorizontalPodAutoscaler` for the two hot-path services plus a `PodDisruptionBudget`:

| Service | Min | Max |
|---|---|---|
| `service-gateway` | 3 | 20 |
| `service-enforcer` | 2 | 12 |

```bash
# current scaling state (TARGETS shows <unknown> until metrics-server is healthy)
kubectl -n mcp get hpa
kubectl -n mcp describe hpa service-gateway
kubectl -n mcp describe hpa service-enforcer

# the PodDisruptionBudget guarding voluntary evictions (drains, upgrades)
kubectl -n mcp get pdb
```

Operational tips:
- If `TARGETS` reads `<unknown>`, install/repair `metrics-server` — the HPA cannot scale without CPU/memory metrics.
- Do not `kubectl scale` these Deployments manually; the HPA will revert replica counts. To change the envelope, edit the `minReplicas`/`maxReplicas` in `40-gateway.yaml` and re-apply.
- Generate load through the gateway and watch it scale:

  ```bash
  watch -n2 'kubectl -n mcp get hpa,pods -l app=service-gateway'
  ```

### Cleanup

```bash
kubectl delete namespace mcp
```

Deleting the namespace removes all Deployments, Services, HPAs, the PodDisruptionBudget, NetworkPolicies, ConfigMap, and the `mcp-keys` / `mcp-log-key` / `mcp-api-keys` / `mcp-provider` Secrets in one step.

---

## Security, Privacy, and FAQ

This section explains, in plain terms, what Kybernos enforces on every tool call, what it records and how those records are protected, how secrets are handled, and what "local-only" actually guarantees. It ends with honest caveats and an FAQ. Everything here is provider-independent: swapping Claude for GPT, a local Llama, or a LiteLLM proxy changes only the model wire format — **never** the security controls.

---

### 1. What it enforces (plain terms)

The gateway sits between the LLM and your real tools (filesystem, database, network). The model never touches a tool directly. Every tool call the model wants to make is intercepted and forced through a fixed, ordered pipeline before anything runs:

```
authenticate → authorize (RBAC) → mint scoped capability token → validate (JSON-Schema)
→ enforce (semantic firewall) → sandboxed execute → egress-DLP → audit
```

Two ideas do the heavy lifting:

1. **Identity comes from the API key, never the request body.** The gateway authenticates the caller with an API key (`Authorization: Bearer <key>` or `X-API-Key: <key>`) and maps it to a *principal*. The model cannot claim to be someone else — the principal used for authorization is the authenticated one, not anything the model or payload says.
2. **Least privilege is enforced twice — authoritatively by RBAC + JSON-Schema, and defensively by a denylist firewall.** A capability token is minted per call, scoped to exactly one resource, and expires in seconds.

| Control | Where it runs | What it does | Failure status |
|---|---|---|---|
| Authentication | gateway `:8000` | API key → principal via `hmac.compare_digest`. No key = no identity. | `401` |
| Rate limit | gateway | Redis fixed-window, `max_requests_per_min` (default 10). Fail-closed if Redis is down. | `429` / `503` |
| Body-size cap | gateway | Rejects bodies over `max_input_size` (512 KB). | `413` |
| RBAC (authoritative) | registry `:8500` | `allow_list` check: is this principal allowed this resource? | `403` |
| Capability token | registry | Mints ES256 JWT (`sub`, `scope`, `jti`, `iat`, `nbf`, `exp`), stores `valid_token:<jti>` in Redis with `token_ttl` (30 s). | — |
| Token verify + replay | enforcer `:8650` | Verifies ES256 (pinned), required `exp/jti/scope/sub`, 5 s leeway, checks `jti` still in Redis, `scope == resource`. | `401` / `403` |
| JSON-Schema (authoritative) | enforcer | Precompiled `Draft202012Validator` per resource; `additionalProperties: false`. | `400` |
| Semantic firewall (defense-in-depth) | enforcer | 112 regex rules, `re.DOTALL`, on the request payload. | `400` |
| Sandboxed execute | node-fs/db/net | node-fs confined to `/app/data/sandbox` (`realpath` + `os.sep` escape check). | `404` / `502` |
| Egress DLP | enforcer | Runs the firewall over the **response**; toggle `EGRESS_DLP`. | `502` |
| Output-size cap | enforcer | Caps response at `max_output_size` (4 KB) to limit exfiltration. | — |

The schema is deliberately tight. For example, the filesystem resource only accepts `read|list|write`, a relative path with no leading slash and no `..`, and a `.txt|.json|.log|.md` extension; the database resource accepts only `SELECT|SHOW|DESCRIBE ... FROM ...` (≤512 chars, no unions/subqueries); the network resource accepts only `https://` GET URLs (≤256 chars, no IP literals). RBAC and JSON-Schema are the authoritative gates — the firewall is a secondary safety net (see caveats).

---

### 2. Data-flow & privacy diagram

Where your data goes, and where it is protected, on a single tool call:

```mermaid
flowchart TD
    C["Client (OpenAI /v1/chat/completions)"] -->|"API key in header"| G["service-gateway :8000 (edge)"]
    G -->|"native request via adapter"| LLM["Upstream LLM (Anthropic / OpenAI / local)"]
    LLM -->|"tool_calls"| G
    G -->|"principal, resource, payload"| I["service-ingress :8443"]
    I -->|"encrypted INGRESS audit"| R[("redis-store :6379")]
    I --> RG["service-registry :8500 (RBAC + token)"]
    RG -->|"valid_token:jti (TTL 30s)"| R
    RG --> E["service-enforcer :8650 (validate + firewall)"]
    E --> W["worker node-fs / node-db / node-net"]
    W --> E
    E -->|"egress DLP + size cap"| I
    I -->|"encrypted EGRESS audit"| R
    I --> G --> C

    subgraph edge["Zone: edge (only public)"]
        G
    end
    subgraph control["Zone: control"]
        I
        RG
        E
    end
    subgraph worker["Zone: worker (sandboxed)"]
        W
    end
    subgraph state["Zone: state"]
        R
    end
```

Trust zones: `edge = gateway`, `control = ingress/registry/enforcer`, `worker = node-fs/db/net`, `state = redis`. A default-deny NetworkPolicy makes each service reachable **only** by its legitimate caller; **only the gateway is externally reachable**.

---

### 3. What is logged, and how it is protected

Audit happens in the ingress service, twice per pipeline pass: an **INGRESS** record (the inbound `{principal, resource, payload}`) and an **EGRESS** record (the outbound result). Both are written **encrypted**.

- **Encryption at rest.** Audit logs are sealed with **AES-256-GCM** (`encrypt_audit_log` in `securio_binding.py`) using the key in `LOG_ENC_KEY_HEX`. Without that key, the audit trail is opaque.
- **No secrets in the SBOM.** The runtime SBOM served at `GET /runtime/sbom` (admin-only) is built from `config/*.yaml` via `RuntimeRegistry`. **Environment variables are never included in the SBOM** — so API keys, the log-encryption key, and provider tokens cannot leak through policy disclosure.
- **Capability tokens are short-lived and revocable.** Each token's `jti` lives in Redis for `token_ttl` (30 s). Deleting `valid_token:<jti>` instantly revokes it; expiry handles replay.
- **Least-data-on-the-wire.** Identity travels in a header, never the body; the 4 KB output cap limits how much any single response can carry back.

```bash
# SBOM is admin-only and env-free (no secrets). Non-admins get 403.
curl -s http://localhost:8000/runtime/sbom \
  -H "X-API-Key: ${ADMIN_KEY}" | jq '.'
```

> Note: `LOG_ENC_KEY_HEX` is what makes the audit trail readable. Treat it as a crown-jewel secret and rotate it deliberately — losing it means losing the ability to decrypt existing audit records.

---

### 4. Secrets are never committed

`scripts/gen_keys.sh` generates every local secret and **commits nothing**:

- `keys/ecdsa_private.pem` + `keys/ecdsa_public.pem` — ES256 capability-token signing keypair.
- `deploy/docker/.env` — `LOG_ENC_KEY_HEX` (freshly generated) and provider key placeholders.
- `secrets/api_keys.json` — the `api_key → principal` map. API keys are printed to the terminal **once**.

All of these paths are git-ignored:

```gitignore
# Secrets — never commit
keys/
secrets/
deploy/docker/.env
*.pem
*.key
```

Bootstrap flow (Docker):

```bash
# 1. Generate keys/secrets (prints API keys once — save them)
scripts/gen_keys.sh

# 2. Fill in provider keys in deploy/docker/.env, then bring the stack up
#    (.env carries LOG_ENC_KEY_HEX, ANTHROPIC_API_KEY, REMOTE_API_KEY)
docker compose -f deploy/docker/docker-compose.yml up --build
```

**Kubernetes** keeps the same separation using native Secrets — created by `deploy/k8s/apply.sh`, not baked into images:

- `mcp-keys` — ES256 keypair
- `mcp-log-key` — `LOG_ENC_KEY_HEX`
- `mcp-api-keys` — `api_keys.json`
- `mcp-provider` — `ANTHROPIC_API_KEY` + `REMOTE_API_KEY`

Config ships as a ConfigMap (from `config/`); secrets ship as Secrets and are mounted read-only. Every pod runs `runAsNonRoot` (uid 1000), `readOnlyRootFilesystem`, drops **all** Linux capabilities, uses seccomp `RuntimeDefault`, and has resource requests/limits and `/healthz` probes.

---

### 5. Local-only = no data leaves the box

If you point principals at a **local, OpenAI-compatible** backend (Ollama, vLLM, LM Studio, llama.cpp), no prompt, tool call, or result ever leaves your machine. The default `provider_local` does exactly this and uses `NULL_KEY`, which means **no `Authorization` header is sent** to the local server.

```yaml
# config/model_inventory.yaml — fully offline provider
providers:
  provider_local:
    type: "openai"                                   # OpenAI-compatible wire format
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    api_key_env: "NULL_KEY"                          # send no Authorization header

models:
  principal_analyst:
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
```

In the shipped default set, `analyst`, `auditor`, and `netbot` all run on `provider_local` — the stack works offline out of the box. The moment you switch a principal to `provider_anthropic` or `provider_openai`, that principal's prompts and tool I/O are sent to that vendor's endpoint; everything else stays local. Provider choice is **per principal**, so you can keep sensitive principals offline while others use a cloud model.

---

### 6. Honest caveats

Read these before you trust the box in production:

- **`node-db` and `node-net` are real connectors — finish the operational hardening.** `node-db` runs queries against a real backend (SQLite by default, or Postgres via `DATABASE_URL`) under a driver-enforced read-only session, accepting only a single `SELECT`/`WITH` through its own guard; point `DATABASE_URL` at a **dedicated read-only DB role** so the grant, not just the code guard, is authoritative. `node-net` makes real HTTPS requests but re-validates that every resolved IP is public and never auto-follows redirects; front it with an **IP-pinning egress proxy** (e.g. Smokescreen) to fully close DNS-rebinding. Both bound their output (`DB_MAX_ROWS`/`DB_MAX_CELL`, `NET_MAX_BYTES`/`NET_TIMEOUT`). See **Worker-node connector configuration** for the env vars.
- **The 112-rule semantic firewall is defense-in-depth ONLY.** Regex denylists are secondary. RBAC (`allow_list`) and JSON-Schema validation (`additionalProperties: false`, precompiled Draft 2020-12) are the **authoritative** controls. Do not weaken the schema and lean on the firewall — a denylist can always be evaded; an allowlist schema cannot be widened without editing config.
- **Egress DLP is a toggle.** It runs the firewall over responses only when `EGRESS_DLP` is enabled. If you disable it, response-side leakage is no longer scanned.
- **API-key auth is intentionally simple.** `ApiKeyAuthenticator` is a static `key → principal` map. It is a clean seam, not an IdP — swapping to OIDC means replacing that one class. Rotate keys by re-running `gen_keys.sh`.
- **Rate-limit fail mode matters.** With `RATE_LIMIT_FAIL_CLOSED`, a Redis outage returns `503` rather than silently allowing traffic. Keep it fail-closed unless you have a strong reason not to.
- **The agentic loop is bounded, not free.** `MAX_TOOL_ROUNDS` (default 4) caps tool rounds; after the budget the gateway forces a final answer with tools removed. This bounds runaway tool use but is not a substitute for RBAC.

---

### 7. FAQ

**Q: Can I use GPT, Claude, or Llama?**
Yes — the system is **model-agnostic**. The client edge is *always* OpenAI Chat Completions compatible (`POST /v1/chat/completions`), regardless of the backend. `src/common/providers.py` selects a wire adapter by provider `type`:

- `type: "anthropic"` → **AnthropicAdapter**, the native, optimized path (Messages API, `x-api-key` + `anthropic-version`, required `max_tokens`, system prompt hoisted to a top-level `system` field, `tool_use`/`tool_result` blocks; optional `thinking` and `effort`). Responses are normalized back to an OpenAI `chat.completion` so the edge stays uniform.
- **any other type** (`openai`, `local`, `ollama`, `vllm`, `lmstudio`, `litellm`, `together`, `groq`, …) → **OpenAIAdapter**, near-passthrough with Bearer auth (`NULL_KEY` = no auth header).

Adapters translate **only** the model wire format. RBAC, capability tokens, JSON-Schema validation, firewall, egress DLP, and audit all run downstream and are identical no matter which model you pick.

**Q: Does switching providers weaken my security controls?**
No. The controls operate on `{principal, resource, payload}` and are fully provider-independent. Switching providers never changes the ZTA/NIST controls.

**Q: Can different users use different models?**
Yes — mix freely. Provider is assigned per principal in `model_inventory.yaml`:

```yaml
# Mixed fleet: each principal on a different backend
models:
  principal_admin:                     # optimized cloud
    provider: "provider_anthropic"
    upstream_model_id: "claude-opus-4-8"
  principal_analyst:                   # offline / private
    provider: "provider_local"
    upstream_model_id: "mistral:7b-instruct"
  principal_auditor:                   # OpenAI-compatible cloud
    provider: "provider_openai"
    upstream_model_id: "gpt-4o-mini"
  principal_netbot:                    # via a LiteLLM proxy
    provider: "provider_litellm"
    upstream_model_id: "claude-sonnet-5"
```

Corresponding provider block for the LiteLLM proxy (one endpoint fronting many vendors):

```yaml
providers:
  provider_litellm:
    type: "openai"                         # LiteLLM speaks OpenAI wire format
    endpoint: "http://litellm:4000/v1/chat/completions"
    api_key_env: "LITELLM_KEY"             # export LITELLM_KEY in the env / Secret
```

Anthropic (optimized) and OpenAI blocks for reference:

```yaml
providers:
  provider_anthropic:
    type: "anthropic"
    endpoint: "https://api.anthropic.com/v1/messages"
    api_key_env: "ANTHROPIC_API_KEY"
    anthropic_version: "2023-06-01"
    max_tokens: 4096
    # thinking: true       # opt in to adaptive thinking
    # effort: "high"       # low|medium|high|xhigh|max

  provider_openai:
    type: "openai"
    endpoint: "https://api.openai.com/v1/chat/completions"
    api_key_env: "REMOTE_API_KEY"
```

> Any principal that calls the gateway must be provisioned a model here, or the gateway returns `403` (no model provisioned).

**Q: How do I call it? Clients never change, right?**
Correct — always the same OpenAI-shaped request, whatever the backend:

```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ${ANALYST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "ignored-edge-resolves-from-principal",
        "messages": [{"role": "user", "content": "List the files in reports/"}]
      }'
```

The model field is resolved from the authenticated principal's `model_inventory` entry — the edge, not the client, decides the real upstream model.

**Q: Where is my identity taken from — can the model impersonate someone?**
No. Identity is derived from the API key at the edge and carried as the authenticated `principal` into ingress. Anything in the message body claiming a different identity is ignored for authorization.

**Q: Are my prompts sent to a vendor when I run locally?**
No. On `provider_local` (or any self-hosted OpenAI-compatible endpoint) nothing leaves the box, and with `NULL_KEY` not even an auth header is sent. Data leaves only for principals explicitly pointed at a cloud provider.

**Q: What do the HTTP status codes mean?**

| Code | Meaning |
|---|---|
| `200` | Allowed |
| `400` | Schema validation failed or firewall violation / invalid JSON |
| `401` | No/invalid API key, or invalid/expired capability token |
| `403` | RBAC violation / scope mismatch / non-admin SBOM / no model provisioned |
| `404` | Resource or file not found |
| `413` | Body too large (`max_input_size`) |
| `429` | Rate limited (`max_requests_per_min`) |
| `502` | Upstream provider / worker error, or egress-DLP block |
| `503` | Rate limiter unavailable (fail-closed) |

**Q: How do I rotate secrets?**
Re-run `scripts/gen_keys.sh` (regenerates the ES256 keypair, `LOG_ENC_KEY_HEX`, and `api_keys.json`; nothing is committed). On Kubernetes, update the corresponding Secrets (`mcp-keys`, `mcp-log-key`, `mcp-api-keys`, `mcp-provider`) via `deploy/k8s/apply.sh`. Rotating `LOG_ENC_KEY_HEX` means previously written audit records can no longer be decrypted with the new key — archive first if you need them.

**Q: Is the audit trail tamper-evident / private?**
Records are encrypted with AES-256-GCM (authenticated encryption), so they are both confidential and integrity-checked at decrypt time. Only holders of `LOG_ENC_KEY_HEX` can read them, and the SBOM never exposes env-held secrets.
