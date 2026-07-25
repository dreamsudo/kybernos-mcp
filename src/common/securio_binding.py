import re
import os
import time
import json
import base64
import logging
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .object_registry import registry

logger = logging.getLogger("securio")


class SecurioEnforcer:
    """Crypto + semantic-firewall primitives.

    The semantic firewall is a DENYLIST and is treated as defense-in-depth
    only. The authoritative controls are per-principal RBAC (registry) and
    server-side JSON-Schema validation (enforcer). Do not rely on regexes.
    """

    def __init__(self):
        self.priv_key_path = os.getenv("PRIV_KEY_PATH", "/app/keys/ecdsa_private.pem")
        self.pub_key_path = os.getenv("PUB_KEY_PATH", "/app/keys/ecdsa_public.pem")
        self.log_key_hex = os.getenv("LOG_ENC_KEY_HEX", "")
        self._priv_key = None
        self._pub_key = None
        self._compile_firewall()

    # --- key material (read once; mounted read-only, rotation => pod restart) ---
    def _priv(self) -> str:
        if self._priv_key is None:
            with open(self.priv_key_path, "r") as f:
                self._priv_key = f.read()
        return self._priv_key

    def _pub(self) -> str:
        if self._pub_key is None:
            with open(self.pub_key_path, "r") as f:
                self._pub_key = f.read()
        return self._pub_key

    def _compile_firewall(self):
        self.rules = []
        for rule in registry.security.get("semantic_firewall", []):
            rule_id = rule.get("id") or rule.get("rule_id")
            if not rule_id or "regex" not in rule:
                logger.warning("Skipping malformed firewall rule: %s", rule)
                continue
            # DOTALL so length/anchored rules (e.g. .{8193,}) are not bypassed by newlines.
            self.rules.append({
                "id": rule_id,
                "regex": re.compile(rule["regex"], re.DOTALL),
                "action": rule.get("action", "BLOCK"),
            })

    # --- JWT capability tokens ---
    def sign_jwt(self, payload: dict) -> str:
        return jwt.encode(payload, self._priv(), algorithm="ES256")

    def verify_jwt(self, token: str) -> dict:
        return jwt.decode(
            token,
            self._pub(),
            algorithms=["ES256"],  # pinned: no alg-confusion
            options={"require": ["exp", "jti", "scope", "sub"]},
            leeway=5,
        )

    # --- encrypted audit log ---
    def encrypt_audit_log(self, data: dict) -> str:
        if not self.log_key_hex:
            return "ERR_NO_KEY"
        try:
            aesgcm = AESGCM(bytes.fromhex(self.log_key_hex))
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, json.dumps(data, default=str).encode(), None)
            return base64.b64encode(nonce + ct).decode()
        except Exception as e:  # never let audit logging crash the request path
            logger.error("audit encryption failed: %s", e)
            return f"ERR_ENCRYPTION_FAILED"

    # --- semantic firewall (defense-in-depth denylist) ---
    def inspect_payload(self, content: str):
        for rule in self.rules:
            if rule["action"] == "BLOCK" and rule["regex"].search(content):
                raise ValueError(f"Firewall Violation: {rule['id']}")


securio = SecurioEnforcer()
