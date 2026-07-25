#!/bin/bash
# ==============================================================================
# apply.sh — deploy the Kybernos to the current kube-context.
#
# Creates the namespace, generates ConfigMap (from ../../config) and Secrets
# (from ../../keys, ../../secrets, and LOG_ENC_KEY_HEX), then applies manifests.
#
# Prereqs:
#   - kubectl context pointing at the target cluster
#   - image `mcp-universal:6.0` available to the cluster
#       (build: docker build -f ../docker/Dockerfile -t mcp-universal:6.0 ../..)
#       (kind:  kind load docker-image mcp-universal:6.0)
#   - run ../../scripts/gen_keys.sh first to create keys/ and secrets/
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"
PROJ="$(cd ../.. && pwd)"
NS=mcp-secure

command -v kubectl >/dev/null || { echo "kubectl not found"; exit 1; }
for f in "$PROJ/keys/ecdsa_private.pem" "$PROJ/keys/ecdsa_public.pem" "$PROJ/secrets/api_keys.json"; do
  [ -f "$f" ] || { echo "Missing $f — run scripts/gen_keys.sh first"; exit 1; }
done

# Resolve LOG_ENC_KEY_HEX from env or deploy/docker/.env
LOG_ENC_KEY_HEX="${LOG_ENC_KEY_HEX:-}"
if [ -z "$LOG_ENC_KEY_HEX" ] && [ -f "$PROJ/deploy/docker/.env" ]; then
  LOG_ENC_KEY_HEX="$(grep -E '^LOG_ENC_KEY_HEX=' "$PROJ/deploy/docker/.env" | cut -d= -f2-)"
fi
[ -n "$LOG_ENC_KEY_HEX" ] || { echo "LOG_ENC_KEY_HEX not set — run scripts/gen_keys.sh"; exit 1; }

echo "[1/4] namespace"
kubectl apply -f 00-namespace.yaml

echo "[2/4] config (ConfigMap from $PROJ/config)"
kubectl -n "$NS" create configmap mcp-config \
  --from-file="$PROJ/config" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[3/4] secrets"
kubectl -n "$NS" create secret generic mcp-keys \
  --from-file=ecdsa_private.pem="$PROJ/keys/ecdsa_private.pem" \
  --from-file=ecdsa_public.pem="$PROJ/keys/ecdsa_public.pem" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic mcp-log-key \
  --from-literal=LOG_ENC_KEY_HEX="$LOG_ENC_KEY_HEX" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic mcp-api-keys \
  --from-file=api_keys.json="$PROJ/secrets/api_keys.json" \
  --dry-run=client -o yaml | kubectl apply -f -
if [ -n "${REMOTE_API_KEY:-}" ]; then
  kubectl -n "$NS" create secret generic mcp-provider \
    --from-literal=REMOTE_API_KEY="$REMOTE_API_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

echo "[4/4] workloads"
kubectl apply -f 10-redis.yaml -f 20-workers.yaml -f 30-core.yaml -f 40-gateway.yaml -f 50-networkpolicy.yaml
echo "   (skipping 60-ingress.yaml — edit the host, then: kubectl apply -f 60-ingress.yaml)"

echo
echo "Done. Watch rollout:  kubectl -n $NS get pods -w"
echo "Port-forward test:    kubectl -n $NS port-forward svc/service-gateway 8000:8000"
