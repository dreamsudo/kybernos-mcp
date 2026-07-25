import os
import time
import redis
from fastapi import FastAPI, Request, HTTPException
from src.common.object_registry import registry
from src.common.securio_binding import securio

from src.common.banner import brand_line
brand_line("service-registry")
app = FastAPI(title="Kybernos · Registry", version="6.0")
redis_conn = redis.from_url(os.getenv("REDIS_URL", "redis://redis_store:6379"))


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/authorize")
async def authorize_request(request: Request):
    body = await request.json()
    principal = body.get("principal")
    resource = body.get("resource")

    # RBAC: authoritative allow-list check. `principal` here is the identity the
    # gateway authenticated (never client-supplied).
    allowed = registry.access_list.get(principal, {}).get("allowed_resources", [])
    if resource not in allowed:
        raise HTTPException(403, "Policy violation: resource not permitted for principal")

    ttl = int(registry.limits.get("token_ttl", 30) or 30)
    jti = os.urandom(16).hex()
    now = int(time.time())
    payload = {
        "sub": principal,
        "scope": resource,
        "jti": jti,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    # Single-use-style validity window tracked in Redis for revocation/replay.
    redis_conn.setex(f"valid_token:{jti}", ttl, 1)
    return {"token": securio.sign_jwt(payload), "resource": resource}
