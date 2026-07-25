import os
import logging
import httpx
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from src.common.securio_binding import securio

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("ingress")

from src.common.banner import brand_line
brand_line("service-ingress")
app = FastAPI(title="Kybernos · Ingress", version="6.0")

REGISTRY_URL = os.getenv("REGISTRY_URL", "http://service_registry:8500/authorize")
ENFORCER_URL = os.getenv("ENFORCER_URL", "http://service_enforcer:8650/execute")


def _persist_log(phase, data):
    blob = securio.encrypt_audit_log({"phase": phase, "data": data})
    logger.info("SECURE_LOG::%s", blob)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/process")
async def process_traffic(request: Request, bg: BackgroundTasks):
    body = await request.json()
    bg.add_task(_persist_log, "INGRESS", body)

    async with httpx.AsyncClient(timeout=30.0) as client:
        auth_res = await client.post(REGISTRY_URL, json=body)
        if auth_res.status_code != 200:
            raise HTTPException(auth_res.status_code, "Authorization denied")
        token_data = auth_res.json()

    async with httpx.AsyncClient(timeout=30.0) as client:
        exec_res = await client.post(
            ENFORCER_URL,
            json={"resource": token_data["resource"], "payload": body.get("payload")},
            headers={"Authorization": f"Bearer {token_data['token']}"},
        )
        if exec_res.status_code != 200:
            bg.add_task(_persist_log, "EGRESS_DENIED",
                        {"status": exec_res.status_code, "detail": exec_res.text})
            raise HTTPException(exec_res.status_code, exec_res.text)
        result = exec_res.json()

    bg.add_task(_persist_log, "EGRESS", result)
    return result
