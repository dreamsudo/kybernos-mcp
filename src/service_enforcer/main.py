import os
import logging
import httpx
import redis
from fastapi import FastAPI, Request, Header, HTTPException
from jsonschema import Draft202012Validator, ValidationError
from src.common.object_registry import registry
from src.common.securio_binding import securio

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("enforcer")

from src.common.banner import brand_line
brand_line("service-enforcer")
app = FastAPI(title="Kybernos · Enforcer", version="6.0")
redis_conn = redis.from_url(os.getenv("REDIS_URL", "redis://redis_store:6379"))

# Precompile one validator per resource at startup. Using the validator class
# directly (not jsonschema.validate) skips the ECMA-262 metaschema self-check,
# so Python-style patterns like (?i) are honoured, and it is far faster per call.
_VALIDATORS = {}
for _rid, _rdef in registry.resources.items():
    _schema = _rdef.get("schema")
    if _schema:
        try:
            _VALIDATORS[_rid] = Draft202012Validator(_schema)
        except Exception as _e:  # malformed schema => fail closed at request time
            logger.error("resource %s has an invalid schema: %s", _rid, _e)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/execute")
async def execute_tool(request: Request, authorization: str = Header(...)):
    # 1. Verify capability token (signature + required claims).
    try:
        token = authorization.split(" ", 1)[1]
        claims = securio.verify_jwt(token)
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

    # 2. Replay / revocation check — SINGLE USE. getdel atomically reads and
    #    deletes the token id, so a captured capability token cannot be replayed
    #    within its TTL window (a second /execute with the same jti sees nothing).
    if not redis_conn.getdel(f"valid_token:{claims['jti']}"):
        raise HTTPException(401, "Token revoked, expired, or already used")

    body = await request.json()
    resource_id = body.get("resource")
    payload = body.get("payload")

    # 3. Scope must match the granted capability.
    if claims["scope"] != resource_id:
        raise HTTPException(403, "Scope mismatch")

    tool_def = registry.resources.get(resource_id)
    if not tool_def:
        raise HTTPException(404, "Resource definition missing")

    # 4. AUTHORITATIVE control: validate args against the tool's JSON Schema.
    #    (In v1-v5 the schema was only a hint to the LLM and never enforced.)
    if tool_def.get("schema"):
        validator = _VALIDATORS.get(resource_id)
        if validator is None:
            raise HTTPException(500, "Resource schema failed to compile")  # fail closed
        try:
            validator.validate(payload)
        except ValidationError as e:
            logger.info("schema rejection on %s: %s", resource_id, e.message)
            raise HTTPException(400, f"Schema validation failed: {e.message}")

    # 5. Defense-in-depth denylist on the inbound payload.
    try:
        securio.inspect_payload(str(payload))
    except ValueError as e:
        raise HTTPException(400, str(e))

    # 6. Execute against the worker node.
    try:
        async with httpx.AsyncClient(timeout=tool_def["timeout"]) as client:
            resp = await client.post(f"{tool_def['endpoint']}/run", json=payload)
            data = resp.json()
    except Exception as e:
        logger.error("execution node failed: %s", e)
        raise HTTPException(502, "Execution node failed")

    # 6b. A worker-node denial/error (4xx/5xx) must NOT be laundered into a 200
    #     success. Surface it so ingress audits it as denied and the model sees a
    #     failure — not e.g. {"detail":"Sandbox violation"} treated as file content.
    if resp.status_code != 200:
        detail = data.get("detail") if isinstance(data, dict) else str(data)
        logger.info("worker node %s returned %s: %s", resource_id, resp.status_code, detail)
        raise HTTPException(resp.status_code if resp.status_code >= 400 else 502,
                            f"Worker node error: {detail}")

    # 7. Egress DLP: scan tool OUTPUT for secret leakage (was never done before).
    if os.getenv("EGRESS_DLP", "true").lower() == "true":
        try:
            securio.inspect_payload(str(data))
        except ValueError as e:
            logger.warning("egress DLP blocked response from %s: %s", resource_id, e)
            raise HTTPException(502, f"Response blocked by egress DLP: {e}")

    # 8. Output size cap.
    limit = int(registry.limits.get("max_output_size", 4096) or 4096)
    if len(str(data)) > limit:
        return {"status": "partial", "data": str(data)[:limit]}
    return data
