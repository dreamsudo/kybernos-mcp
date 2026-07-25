#!/usr/bin/env bash
# =============================================================================
#  run_local.sh — run the full Kybernos stack locally WITHOUT Docker.
#
#  Launches all 7 services as uvicorn processes on 127.0.0.1, pointed at a
#  Redis you provide (REDIS_URL) and the model backend configured in
#  config/model_inventory.yaml. Ctrl-C stops everything.
#
#  Prereqs:
#    pip install -r requirements.txt        # fastapi, uvicorn, redis, ...
#    scripts/gen_keys.sh                     # ES256 keypair + secrets/api_keys.json
#    a running Redis:  docker run -p 6379:6379 redis:7-alpine   (or a native one)
#    a model backend:  a local Ollama, or set the provider's API key in .env
#
#  Usage:  scripts/run_local.sh
#  Then in another terminal:  scripts/smoke.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

: "${REDIS_URL:=redis://127.0.0.1:6379}"
: "${CONFIG_PATH:=$ROOT/config}"
: "${AUTH_KEYS_PATH:=$ROOT/secrets/api_keys.json}"
: "${SANDBOX_DIR:=$ROOT/.local-run/sandbox}"
PY="python3"; [ -x ".venv/bin/python" ] && PY=".venv/bin/python"
[ -n "${KYBERNOS_VENV:-}" ] && [ -x "$KYBERNOS_VENV/bin/python" ] && PY="$KYBERNOS_VENV/bin/python"
UV="$($PY -c 'import uvicorn,os;print(os.path.dirname(uvicorn.__file__))' >/dev/null 2>&1 && echo "$PY -m uvicorn" || echo uvicorn)"

# --- preflight ---
[ -f keys/ecdsa_private.pem ] || { echo "✗ keys/ missing — run scripts/gen_keys.sh first"; exit 1; }
[ -f "$AUTH_KEYS_PATH" ]      || { echo "✗ $AUTH_KEYS_PATH missing — run scripts/gen_keys.sh first"; exit 1; }
if ! $PY - <<PY 2>/dev/null
import redis,sys; redis.from_url("$REDIS_URL").ping()
PY
then echo "✗ Redis not reachable at $REDIS_URL"; echo "  start one:  docker run -p 6379:6379 redis:7-alpine"; exit 1; fi

# --- temp config: workers/providers must resolve on localhost, not docker DNS ---
RUN="$ROOT/.local-run"; mkdir -p "$RUN/logs" "$SANDBOX_DIR"
echo "hello from kybernos" > "$SANDBOX_DIR/notes.txt"
cp -r "$CONFIG_PATH"/* "$RUN/config-src" 2>/dev/null; rm -rf "$RUN/config"; cp -r "$CONFIG_PATH" "$RUN/config"
sed -i 's#http://node-fs:8620#http://127.0.0.1:8620#; s#http://node-db:8610#http://127.0.0.1:8610#; s#http://node-net:8630#http://127.0.0.1:8630#' "$RUN/config/resource_catalog.yaml"
sed -i 's#http://host.docker.internal:11434#http://127.0.0.1:11434#' "$RUN/config/model_inventory.yaml"

# --- env for every service ---
[ -f deploy/docker/.env ] && set -a && . deploy/docker/.env && set +a
export PYTHONPATH="$ROOT" CONFIG_PATH="$RUN/config" REDIS_URL AUTH_KEYS_PATH SANDBOX_DIR
export PRIV_KEY_PATH="$ROOT/keys/ecdsa_private.pem" PUB_KEY_PATH="$ROOT/keys/ecdsa_public.pem"
: "${LOG_ENC_KEY_HEX:=$($PY -c 'import os;print(os.urandom(32).hex())')}"; export LOG_ENC_KEY_HEX
export INGRESS_URL="http://127.0.0.1:8443/process" REGISTRY_URL="http://127.0.0.1:8500/authorize" ENFORCER_URL="http://127.0.0.1:8650/execute"

PIDS=()
bg() { local n="$1"; shift; "$@" >>"$RUN/logs/$n.log" 2>&1 & PIDS+=($!); }
cleanup() { echo; echo "stopping ${#PIDS[@]} services..."; kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT INT TERM

echo "▶ launching Kybernos locally (Redis: $REDIS_URL)"
bg registry $UV src.service_registry.main:app --host 127.0.0.1 --port 8500
bg enforcer $UV src.service_enforcer.main:app --host 127.0.0.1 --port 8650
bg ingress  $UV src.service_ingress.main:app  --host 127.0.0.1 --port 8443
bg nodefs   $UV src.worker_nodes.node_fs:app  --host 127.0.0.1 --port 8620
bg nodedb   $UV src.worker_nodes.node_db:app  --host 127.0.0.1 --port 8610
bg nodenet  $UV src.worker_nodes.node_net:app --host 127.0.0.1 --port 8630
bg gateway  $UV src.service_gateway.main:app  --host 127.0.0.1 --port 8000

for i in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/healthz 2>/dev/null)" = "200" ] && break
  sleep 1
done
echo "✓ gateway ready at http://127.0.0.1:8000  (logs: $RUN/logs/)"
echo "  API keys: $AUTH_KEYS_PATH   ·   try:  scripts/smoke.sh"
echo "  Ctrl-C to stop."
wait
