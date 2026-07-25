import os
import json
import hmac
import logging
from typing import Optional

logger = logging.getLogger("auth")


class ApiKeyAuthenticator:
    """Resolves an inbound API key to a security principal.

    This is the ONLY source of caller identity. The request body's `model`
    field is never trusted for identity (that was the core flaw in v1-v5).

    Key material is loaded from, in order of precedence:
      1. AUTH_KEYS_JSON  — a JSON string {"<api_key>": "<principal>"} (env)
      2. AUTH_KEYS_PATH  — path to a JSON file with the same shape
                           (default /app/secrets/api_keys.json, a mounted Secret)

    Swapping to OIDC/JWT later means replacing only this class.
    """

    def __init__(self):
        self._keys = {}
        self._load()

    def _load(self):
        raw = os.getenv("AUTH_KEYS_JSON")
        if not raw:
            path = os.getenv("AUTH_KEYS_PATH", "/app/secrets/api_keys.json")
            if os.path.isfile(path):
                with open(path, "r") as f:
                    raw = f.read()
        if raw:
            try:
                self._keys = {str(k): str(v) for k, v in json.loads(raw).items()}
                logger.info("Loaded %d API key(s)", len(self._keys))
            except (ValueError, AttributeError) as e:
                logger.error("Failed to parse API keys: %s", e)
                self._keys = {}
        else:
            logger.warning("No API keys configured; all requests will be rejected")

    @staticmethod
    def extract_key(authorization: Optional[str], x_api_key: Optional[str]) -> Optional[str]:
        if x_api_key:
            return x_api_key.strip()
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    def resolve_principal(self, api_key: Optional[str]) -> Optional[str]:
        """Constant-time-ish lookup. Returns the principal or None."""
        if not api_key:
            return None
        for known_key, principal in self._keys.items():
            if hmac.compare_digest(known_key, api_key):
                return principal
        return None


authenticator = ApiKeyAuthenticator()
