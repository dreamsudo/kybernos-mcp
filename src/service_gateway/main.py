import os
import json
import time
import logging
import httpx
import redis
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from typing import Optional
from src.common.object_registry import registry
from src.common.auth import authenticator
from src.common.providers import get_adapter, serialize_body
from src.common.banner import show_banner

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("gateway")

show_banner()  # Kybernos · Psypher Labs
app = FastAPI(title="Kybernos Gateway", version="6.0")

INGRESS_URL = os.getenv("INGRESS_URL", "http://service_ingress:8443/process")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "120"))
MAX_TOOL_ROUNDS = int(os.getenv("MAX_TOOL_ROUNDS", "4"))
_redis = redis.from_url(os.getenv("REDIS_URL", "redis://redis_store:6379"), decode_responses=True)


# --------------------------------------------------------------------------
# Identity: derived ONLY from the API key, never from the request body.
# --------------------------------------------------------------------------
def authenticate(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    key = authenticator.extract_key(authorization, x_api_key)
    principal = authenticator.resolve_principal(key)
    if not principal:
        raise HTTPException(401, "Unauthorized: valid API key required")
    return principal


def _enforce_rate_limit(principal: str):
    limit = int(registry.limits.get("max_requests_per_min", 0) or 0)
    if limit <= 0:
        return
    window = int(time.time() // 60)
    bucket = f"rl:{principal}:{window}"
    try:
        count = _redis.incr(bucket)
        if count == 1:
            _redis.expire(bucket, 65)
        if count > limit:
            raise HTTPException(429, "Rate limit exceeded")
    except redis.RedisError as e:
        logger.error("rate limiter unavailable: %s", e)
        # Zero-trust default: fail CLOSED when the limiter backend is down, so a
        # Redis outage can't be leveraged into an unthrottled window. Set
        # RATE_LIMIT_FAIL_CLOSED=false explicitly to trade that for availability.
        if os.getenv("RATE_LIMIT_FAIL_CLOSED", "true").lower() != "false":
            raise HTTPException(503, "Rate limiter unavailable")


def _resolve_provider(principal: str):
    """Resolve the principal's model + provider + wire adapter. Provider type
    selects the adapter; everything not 'anthropic' is OpenAI-compatible."""
    inv = registry.models
    model_conf = inv.get("models", {}).get(principal)
    if not model_conf:
        raise HTTPException(403, f"No model provisioned for principal '{principal}'")
    provider = inv.get("providers", {}).get(model_conf["provider"])
    if not provider:
        raise HTTPException(500, "Provider configuration missing")
    return {
        "conf": provider,
        "model_id": model_conf["upstream_model_id"],
        "adapter": get_adapter(provider.get("type", "openai")),
    }


def _tool_schema(principal: str):
    """Canonical (OpenAI function) tool list for the principal's allow-list.
    Adapters translate this to each provider's native tool format."""
    allowed = registry.access_list.get(principal, {}).get("allowed_resources", [])
    schema = []
    for tool_id in allowed:
        t = registry.resources.get(tool_id)
        if t:
            schema.append({
                "type": "function",
                "function": {
                    "name": tool_id,
                    "description": t.get("description", ""),
                    "parameters": t.get("schema", {}),
                },
            })
    return schema


async def _call_upstream(url, headers, body):
    # Transmit the canonical bytes (serialize_body) rather than letting httpx
    # re-serialize via json=. Every adapter already sets its own content-type
    # header, and Bedrock's SigV4 signs exactly these bytes — see serialize_body.
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(url, headers=headers, content=serialize_body(body))
        resp.raise_for_status()
        return resp.json()


async def _route_tool_call(principal: str, resource: str, payload: dict):
    """Send one tool call into the security pipeline. principal is the
    AUTHENTICATED identity — never anything from the model or the client body.
    This path is identical for every provider (fully model-agnostic)."""
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as sec:
        res = await sec.post(INGRESS_URL, json={"principal": principal, "resource": resource, "payload": payload})
        if res.headers.get("content-type", "").startswith("application/json"):
            return res.json()
        return {"error": res.text, "status_code": res.status_code}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/runtime/sbom")
def get_sbom(principal: str = Depends(authenticate)):
    if not registry.access_list.get(principal, {}).get("admin", False):
        raise HTTPException(403, "SBOM access requires an admin principal")
    return json.loads(registry.export_runtime_sbom())


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, principal: str = Depends(authenticate)):
    max_in = int(registry.limits.get("max_input_size", 0) or 0)
    # Reject on the declared Content-Length BEFORE buffering the body, so an
    # oversized upload can't be read fully into memory just to be 413'd after.
    if max_in:
        clen = request.headers.get("content-length")
        if clen and clen.isdigit() and int(clen) > max_in:
            raise HTTPException(413, "Request body too large")
    raw = await request.body()
    if max_in and len(raw) > max_in:
        raise HTTPException(413, "Request body too large")
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(400, "Invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid JSON body: expected an object")

    _enforce_rate_limit(principal)

    prov = _resolve_provider(principal)
    adapter, conf, model_id = prov["adapter"], prov["conf"], prov["model_id"]

    messages = body.get("messages", [])          # canonical: OpenAI chat format
    tools = _tool_schema(principal)               # canonical: OpenAI function tools

    try:
        # Bounded agentic tool loop — works identically for any provider.
        for _round in range(MAX_TOOL_ROUNDS):
            url, headers, req = adapter.build_request(model_id, messages, tools, conf)
            try:
                llm_raw = await _call_upstream(url, headers, req)
            except Exception as e:
                logger.error("upstream provider error (%s): %s", adapter.name, e)
                raise HTTPException(502, "Upstream provider error")

            turn = adapter.parse_turn(llm_raw)
            if not turn["tool_calls"]:
                return adapter.to_openai_response(llm_raw)   # final answer, OpenAI-shaped

            # Append the assistant turn, then route each tool call through the pipeline.
            if turn["assistant_msg"]:
                messages.append(turn["assistant_msg"])
            for call in turn["tool_calls"]:
                result = await _route_tool_call(principal, call["name"], call["arguments"])
                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "name": call["name"],
                    "content": json.dumps(result),
                })

        # Round budget exhausted: force a final answer with tools removed.
        url, headers, req = adapter.build_request(model_id, messages, None, conf)
        final_raw = await _call_upstream(url, headers, req)
        return adapter.to_openai_response(final_raw)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("tool-call handling failed (%s): %s", adapter.name, e)
        raise HTTPException(502, "Model interaction failed")
