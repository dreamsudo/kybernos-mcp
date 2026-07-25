"""Regression suite — one test per confirmed bug from the adversarial bug-hunt.

Each test is labelled with the finding it locks down. These are bugs that the
pre-existing 96 assertions did NOT catch; every one here must stay green.

    BH-1  Bedrock SigV4 signed the wrong byte-string  -> every native call 403'd
    BH-3  Gemini dropped a list-form system prompt     -> guardrail loss
    BH-4  Gemini crashed (AttributeError) on null cand -> 502
    BH-5  Non-object JSON body                          -> 500 (now 400)
    BH-6  Rate limiter failed OPEN on Redis outage      -> unthrottled window
    BH-8  Banner crashed startup on non-UTF-8 stdout    -> UnicodeEncodeError
    BH-11 Capability token was replayable within TTL    -> now single-use
    (BH-2 enforcer error-masking is regressed in test_security_pipeline.py:
     "read missing file" — it needs the full multi-service router.)
"""
import os, sys, json, hashlib, io, pathlib, tempfile

PROJ = str(pathlib.Path(__file__).resolve().parents[1])
os.chdir(PROJ); sys.path.insert(0, PROJ)

_SANDBOX = tempfile.mkdtemp(prefix="kyb-reg-")
os.environ.update(
    CONFIG_PATH=f"{PROJ}/config", SANDBOX_DIR=_SANDBOX,
    PRIV_KEY_PATH=f"{PROJ}/keys/ecdsa_private.pem",
    PUB_KEY_PATH=f"{PROJ}/keys/ecdsa_public.pem",
    LOG_ENC_KEY_HEX=os.urandom(32).hex(),
    AUTH_KEYS_JSON=json.dumps({"KEY_ANALYST": "principal_analyst", "KEY_ADMIN": "principal_admin"}),
    REDIS_URL="redis://fake", KYBERNOS_BANNER="off",
)

import fakeredis, redis, time
_server = fakeredis.FakeServer()
redis.from_url = lambda *a, **k: fakeredis.FakeStrictRedis(server=_server, decode_responses=k.get("decode_responses", False))

p = f = 0
def check(name, ok, detail=""):
    global p, f
    p += bool(ok); f += (not ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")


# ---- BH-1: Bedrock SigV4 signs exactly what the gateway transmits ----------
def t_sigv4():
    from src.common.providers import get_adapter, serialize_body
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIDEXAMPLE"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ad = get_adapter("bedrock")
    msgs = [{"role": "system", "content": "guard"}, {"role": "user", "content": "héllo ☺ non-ascii"}]
    _, headers, body = ad.build_request("anthropic.claude-3-sonnet", msgs, [], {"region": "us-east-1"})
    signed = headers.get("x-amz-content-sha256")
    transmitted = hashlib.sha256(serialize_body(body)).hexdigest()
    check("BH-1 SigV4 signs the transmitted bytes", signed == transmitted,
          f"signed={signed} != wire={transmitted}")
    # and the OLD (buggy) json.dumps serialization would NOT have matched
    check("BH-1 old json.dumps serialization would 403",
          hashlib.sha256(json.dumps(body).encode()).hexdigest() != signed)


# ---- BH-3 / BH-4: Gemini adapter robustness --------------------------------
def t_gemini():
    from src.common.providers import get_adapter
    g = get_adapter("gemini")
    _, _, body = g.build_request("gemini-2", [
        {"role": "system", "content": [{"type": "text", "text": "SYSTEM_GUARD"}]},
        {"role": "user", "content": "hi"}], [], {})
    sysi = json.dumps(body.get("system_instruction", {}))
    check("BH-3 list-form system prompt preserved", "SYSTEM_GUARD" in sysi, sysi)

    blocked = {"candidates": [{"finishReason": "SAFETY", "content": None}], "usageMetadata": {}}
    try:
        turn = g.parse_turn(blocked)
        resp = g.to_openai_response(blocked)
        ok = turn["content"] == "" and resp["choices"][0]["finish_reason"] == "content_filter"
        check("BH-4 null candidate content does not crash", ok, str(resp))
    except Exception as e:
        check("BH-4 null candidate content does not crash", False, f"{type(e).__name__}: {e}")


# ---- BH-5: non-object JSON body -> 400 (not 500) ---------------------------
def t_body():
    from starlette.testclient import TestClient
    from src.service_gateway import main
    main._redis = redis.from_url("redis://fake")
    c = TestClient(main.app)
    key = "KEY_ANALYST"
    for label, payload in [("array", "[1,2]"), ("string", '"x"'), ("number", "9"), ("garbage", "{bad")]:
        r = c.post("/v1/chat/completions", headers={"X-API-Key": key, "Content-Type": "application/json"}, content=payload)
        check(f"BH-5 non-object body ({label}) -> 400", r.status_code == 400, f"got {r.status_code}")


# ---- BH-6: rate limiter fails CLOSED by default on Redis error -------------
def t_rate_fail_closed():
    from fastapi import HTTPException
    from src.service_gateway import main

    class _Boom:
        def incr(self, *a): raise redis.RedisError("down")
        def expire(self, *a): pass
    main._redis = _Boom()
    os.environ.pop("RATE_LIMIT_FAIL_CLOSED", None)  # unset -> default must be closed
    main.registry.limits["max_requests_per_min"] = 10
    try:
        main._enforce_rate_limit("principal_analyst")
        check("BH-6 Redis outage fails CLOSED by default", False, "no 503 raised")
    except HTTPException as e:
        check("BH-6 Redis outage fails CLOSED by default", e.status_code == 503, f"status {e.status_code}")


# ---- BH-8: banner never crashes on a non-UTF-8 stdout ----------------------
def t_banner():
    from src.common import banner

    class AsciiOnly(io.TextIOBase):
        encoding = "ascii"
        def write(self, s):
            s.encode("ascii")  # raises on the Greek MOTTO, like a real C-locale tty
            return len(s)
    orig = sys.stdout
    sys.stdout = AsciiOnly()
    try:
        banner._safe_print("κυβερνήτης ◆ — the steersman")  # would raise via plain print()
        ok = True; why = ""
    except Exception as e:
        ok = False; why = f"{type(e).__name__}: {e}"
    finally:
        sys.stdout = orig
    check("BH-8 banner survives non-UTF-8 stdout", ok, why)


# ---- BH-11: capability token is single-use (replay rejected) ---------------
def t_single_use():
    from starlette.testclient import TestClient
    from src.service_enforcer import main as enf
    from src.common.securio_binding import securio
    enf.redis_conn = redis.from_url("redis://fake")
    jti = os.urandom(8).hex()
    now = int(time.time())
    tok = securio.sign_jwt({"sub": "principal_analyst", "scope": "resource_filesystem",
                            "jti": jti, "iat": now, "nbf": now, "exp": now + 30})
    enf.redis_conn.setex(f"valid_token:{jti}", 30, 1)
    c = TestClient(enf.app, raise_server_exceptions=False)
    hdr = {"Authorization": f"Bearer {tok}"}
    payload = {"resource": "resource_filesystem", "payload": {"action": "list", "path": "."}}
    r1 = c.post("/execute", headers=hdr, json=payload)
    r2 = c.post("/execute", headers=hdr, json=payload)
    # first use consumes the token (may then 200 or fail downstream, but never 401);
    # the replay must be rejected as an already-used token.
    check("BH-11 first use is accepted (not 401)", r1.status_code != 401, f"got {r1.status_code}")
    check("BH-11 replay of same token -> 401", r2.status_code == 401, f"got {r2.status_code}")


# ---- BH-2b: sandbox init validates + restricts perms (verify-pass follow-ups) ----
def t_sandbox():
    import stat
    from src.worker_nodes import node_fs
    check("BH-2b writable sandbox marked ready", node_fs.SANDBOX_OK is True)
    mode = stat.S_IMODE(os.stat(node_fs.SANDBOX_DIR).st_mode)
    check("BH-2b sandbox not world-writable", not (mode & stat.S_IWOTH), oct(mode))
    # a broken sandbox (path is a regular file) must fail loudly, not be masked
    bad = tempfile.mktemp(prefix="kyb-notadir-"); open(bad, "w").close()
    orig = node_fs.SANDBOX_DIR
    node_fs.SANDBOX_DIR = bad
    try:
        ready = node_fs._init_sandbox()
    finally:
        node_fs.SANDBOX_DIR = orig
    check("BH-2b broken sandbox reports NOT ready (503)", ready is False)


if __name__ == "__main__":
    print("=== REGRESSION: adversarial bug-hunt findings ===")
    for t in (t_sigv4, t_gemini, t_body, t_rate_fail_closed, t_banner, t_single_use, t_sandbox):
        t()
    print(f"\n  regression: {p} passed, {f} failed")
    sys.exit(1 if f else 0)
