import os
import yaml
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("registry")


class RuntimeRegistry:
    """Loads YAML policy objects from CONFIG_PATH into memory at boot.

    Unlike earlier versions, the process environment is NOT registered into the
    object graph, so /runtime/sbom can never leak env vars or secrets.
    """

    def __init__(self):
        self.config_path = os.getenv("CONFIG_PATH", "/app/config")
        self._objects: Dict[str, Any] = {}
        self._load_configs()

    def _load_configs(self):
        if not os.path.isdir(self.config_path):
            logger.warning("CONFIG_PATH %s missing; running with empty policy", self.config_path)
            return
        for f in sorted(os.listdir(self.config_path)):
            if f.endswith((".yaml", ".yml")):
                path = os.path.join(self.config_path, f)
                with open(path, "r") as file:
                    self._objects[f.rsplit(".", 1)[0]] = yaml.safe_load(file) or {}
                    logger.info("Registered config object: %s", f)

    @property
    def models(self): return self._objects.get("model_inventory", {})
    @property
    def resources(self): return self._objects.get("resource_catalog", {}).get("resources", {})
    @property
    def access_list(self): return self._objects.get("access_policy", {}).get("access_control_list", {})
    @property
    def security(self): return self._objects.get("security_policy", {})
    @property
    def limits(self): return self._objects.get("security_policy", {}).get("system_limits", {})

    def export_runtime_sbom(self) -> str:
        # Admin-gated at the transport layer. Policy objects only (no env, no secrets).
        return json.dumps(self._objects, indent=2)


registry = RuntimeRegistry()
