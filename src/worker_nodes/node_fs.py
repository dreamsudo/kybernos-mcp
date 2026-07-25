import os
import logging
from fastapi import FastAPI, Body, HTTPException

from src.common.banner import brand_line
brand_line("node-fs")
logger = logging.getLogger("node-fs")
app = FastAPI(title="Kybernos · node-fs", version="6.0")
SANDBOX_DIR = os.getenv("SANDBOX_DIR", "/app/data/sandbox")


def _init_sandbox() -> bool:
    """Ensure the sandbox root exists (restrictive perms) AND is a writable dir.

    A genuine misconfiguration — read-only/absent mount, or SANDBOX_DIR pointing
    at a file — must fail LOUDLY via /healthz, not be silently swallowed so the
    node reports healthy while list/read/write break later and opaquely.
    """
    try:
        os.makedirs(SANDBOX_DIR, exist_ok=True)
        # makedirs' mode is umask-masked (world-writable under umask 000); set an
        # explicit non-world-writable mode so co-located principals can't plant
        # files node-fs serves. Best-effort: a mounted volume may forbid chmod.
        os.chmod(SANDBOX_DIR, 0o770)
    except OSError as e:
        logger.error("node-fs: could not provision SANDBOX_DIR=%s: %s", SANDBOX_DIR, e)
    ok = os.path.isdir(SANDBOX_DIR) and os.access(SANDBOX_DIR, os.W_OK)
    if not ok:
        logger.error("node-fs: SANDBOX_DIR=%s is not a writable directory — node NOT ready", SANDBOX_DIR)
    return ok


SANDBOX_OK = _init_sandbox()


@app.get("/healthz")
def healthz():
    if not SANDBOX_OK:              # fail loud: a broken sandbox is not "healthy"
        raise HTTPException(503, "sandbox not ready")
    return {"status": "ok"}


def _resolve(path: str) -> str:
    """Resolve a caller path inside the sandbox, refusing any escape.

    Uses realpath (resolves symlinks + ..) and an os.sep-terminated prefix
    check so a sibling dir like /app/data/sandbox_evil cannot pass.
    """
    root = os.path.realpath(SANDBOX_DIR)
    target = os.path.realpath(os.path.join(root, path.lstrip("/")))
    if target != root and not target.startswith(root + os.sep):
        raise HTTPException(403, "Sandbox violation")
    return target


@app.post("/run")
def fs_op(action: str = Body(...), path: str = Body(""), content: str = Body(None)):
    if action == "list":
        target = _resolve(path or ".")
        if not os.path.isdir(target):
            raise HTTPException(400, "Not a directory")
        return {"files": os.listdir(target)}

    target = _resolve(path)

    if action == "read":
        try:
            with open(target, "r") as f:
                return {"content": f.read()}
        except FileNotFoundError:
            raise HTTPException(404, "Not found")
        except IsADirectoryError:
            raise HTTPException(400, "Is a directory")

    if action == "write":
        if content is None:
            raise HTTPException(400, "content required for write")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write(content)
        return {"status": "written", "bytes": len(content)}

    raise HTTPException(400, "Invalid action")
