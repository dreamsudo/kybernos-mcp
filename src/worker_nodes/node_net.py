"""node-net — real, SSRF-safe egress fetcher (replaces the mock).

Zero-trust posture: the schema + firewall already constrain the URL upstream,
but this node ALSO fails closed on its own. Every fetch must clear:
  - scheme is https (http only if NET_ALLOW_HTTP=true),
  - host is on NET_ALLOWLIST when that allowlist is configured,
  - EVERY DNS-resolved address is public — blocks cloud metadata
    (169.254.169.254), loopback, and RFC1918 / link-local ranges,
  - no auto-followed redirects (a 3xx can bounce to an internal target),
  - response bounded by NET_MAX_BYTES and NET_TIMEOUT.

Residual: a DNS-rebinding attacker could return a public IP to our resolver and
a private IP to httpx's. To fully close that, front this node with an egress
proxy that pins the validated IP (e.g. Smokescreen) or a transport that connects
to the address validated here. Documented, not silently ignored.
"""
import os
import socket
import ipaddress
import logging
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Body, HTTPException

from src.common.banner import brand_line
brand_line("node-net")
logger = logging.getLogger("node-net")
app = FastAPI(title="Kybernos · node-net", version="6.0")

ALLOWLIST = {h.strip().lower() for h in os.getenv("NET_ALLOWLIST", "").split(",") if h.strip()}
ALLOW_HTTP = os.getenv("NET_ALLOW_HTTP", "false").lower() == "true"
MAX_BYTES = int(os.getenv("NET_MAX_BYTES", str(1 << 20)))   # 1 MiB
TIMEOUT = float(os.getenv("NET_TIMEOUT", "5"))


def _is_public(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _resolve(host: str, port: int):
    return {info[4][0] for info in
            socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}


def validate_url(url: str):
    """Raise HTTPException unless `url` is safe to fetch. Returns resolved IPs."""
    u = urlparse(url)
    schemes = ("http", "https") if ALLOW_HTTP else ("https",)
    if u.scheme not in schemes:
        raise HTTPException(403, f"scheme not permitted: {u.scheme or '(none)'}")
    host = u.hostname
    if not host:
        raise HTTPException(403, "URL has no host")
    if ALLOWLIST and host.lower() not in ALLOWLIST:
        raise HTTPException(403, f"host not on allowlist: {host}")
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        ips = _resolve(host, port)
    except socket.gaierror as e:
        raise HTTPException(502, f"DNS resolution failed for {host}: {e}")
    if not ips:
        raise HTTPException(502, f"no addresses for {host}")
    for ip in ips:
        if not _is_public(ip):
            raise HTTPException(403, f"SSRF blocked: {host} resolves to non-public {ip}")
    return ips


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/run")
async def net_op(url: str = Body(..., embed=True)):
    validate_url(url)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"fetch failed: {e}")
    if resp.is_redirect:  # never auto-follow to a target we did not validate
        raise HTTPException(403, f"redirect not followed: {resp.headers.get('location', '')[:200]}")
    content = resp.content[:MAX_BYTES]
    return {
        "status": "fetched",
        "url": url,
        "http_status": resp.status_code,
        "truncated": len(resp.content) > MAX_BYTES,
        "data": content.decode("utf-8", "replace"),
    }
