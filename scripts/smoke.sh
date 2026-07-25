#!/usr/bin/env bash
# =============================================================================
#  smoke.sh — black-box smoke test against a RUNNING Kybernos gateway.
#  Works whether the gateway is from `docker compose up` or `run_local.sh`.
#
#  Usage:
#    scripts/smoke.sh                       # BASE=http://localhost:8000
#    scripts/smoke.sh http://host:8000
#  Keys: auto-read from secrets/api_keys.json, or override with
#    KYBERNOS_KEY=<analyst-key> KYBERNOS_ADMIN_KEY=<admin-key> scripts/smoke.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
BASE="${1:-http://localhost:8000}"

pick() {  # pick <principal> — find an API key mapping to that principal
  python3 - "$1" <<'PY' 2>/dev/null
import json,sys
try:
    m=json.load(open("secrets/api_keys.json"))
    print(next((k for k,v in m.items() if v==sys.argv[1]), ""))
except Exception: print("")
PY
}
KEY="${KYBERNOS_KEY:-$(pick principal_analyst)}"
ADMIN="${KYBERNOS_ADMIN_KEY:-$(pick principal_admin)}"

pass=0; fail=0
ck() { # ck <name> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  \033[32m✓\033[0m %-42s %s\n' "$1" "$3"; pass=$((pass+1))
  else printf '  \033[31m✗\033[0m %-42s got %s, want %s\n' "$1" "$3" "$2"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

echo "smoke test → $BASE"
ck "healthz -> 200"            200 "$(code "$BASE/healthz")"
ck "no api key -> 401"         401 "$(code -XPOST "$BASE/v1/chat/completions" -d '{"messages":[]}')"
ck "bad api key -> 401"        401 "$(code -H 'X-API-Key: nope' -XPOST "$BASE/v1/chat/completions" -d '{"messages":[]}')"

if [ -n "$KEY" ]; then
  ck "chat (valid key) -> 200"  200 "$(code -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -XPOST "$BASE/v1/chat/completions" -d '{"messages":[{"role":"user","content":"list the sandbox"}]}')"
  ck "sbom (non-admin) -> 403"  403 "$(code -H "X-API-Key: $KEY" "$BASE/runtime/sbom")"
else echo "  (no analyst key found — set KYBERNOS_KEY to test the chat path)"; fi
[ -n "$ADMIN" ] && ck "sbom (admin) -> 200"       200 "$(code -H "X-API-Key: $ADMIN" "$BASE/runtime/sbom")"

echo "------------------------------------------------------------"
echo " smoke: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
