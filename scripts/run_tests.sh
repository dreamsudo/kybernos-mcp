#!/usr/bin/env bash
# =============================================================================
#  run_tests.sh — Kybernos full test suite (one command).
#
#  Runs, in order:
#    0. static   — py_compile all sources + YAML validity + JSON corpus load
#    1. providers — adapter unit tests (base python)
#    2. security  — in-process ZTA pipeline (fakeredis + ASGI)
#    3. gateway   — agnostic gateway both provider paths
#    4. e2e       — full journey through the public gateway edge
#
#  Uses .venv if present, else python3. Exits non-zero on the first failure
#  (unless --keep-going). KYBERNOS_BANNER is forced off for clean output.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
export KYBERNOS_BANNER=off PYTHONDONTWRITEBYTECODE=1

PY="python3"
[ -x ".venv/bin/python" ] && PY=".venv/bin/python"
[ -n "${KYBERNOS_VENV:-}" ] && [ -x "$KYBERNOS_VENV/bin/python" ] && PY="$KYBERNOS_VENV/bin/python"

KEEP_GOING=0; [ "${1:-}" = "--keep-going" ] && KEEP_GOING=1
pass=0; fail=0; failed_names=()

run() {  # run <name> <cmd...>
  local name="$1"; shift
  printf '\n\033[1m▶ %s\033[0m\n' "$name"
  if "$@"; then printf '  \033[32m✓ %s\033[0m\n' "$name"; pass=$((pass+1))
  else printf '  \033[31m✗ %s\033[0m\n' "$name"; fail=$((fail+1)); failed_names+=("$name")
       [ "$KEEP_GOING" -eq 0 ] && { summary; exit 1; }
  fi
}

static_checks() {
  $PY -m py_compile src/common/*.py src/*/main.py src/worker_nodes/*.py tests/*.py scripts/*.py || return 1
  $PY - <<'PY' || return 1
import glob, yaml, json, sys
for f in glob.glob("config/*.yaml"):
    yaml.safe_load(open(f))
d = json.load(open("tests/corpus/probe_corpus.json"))
assert d["pipeline_probes"] and d["prompt_probes"], "corpus empty"
print(f"  config YAML ok · corpus {len(d['pipeline_probes'])} pipeline + {len(d['prompt_probes'])} prompt probes")
PY
  for s in scripts/*.sh; do bash -n "$s" || return 1; done
}

summary() {
  printf '\n============================================================\n'
  printf ' SUITE: %d passed, %d failed\n' "$pass" "$fail"
  [ "$fail" -gt 0 ] && printf ' failed: %s\n' "${failed_names[*]}"
  printf '============================================================\n'
}

echo "Kybernos test suite · interpreter: $PY"
run "0· static (compile + yaml + corpus)" static_checks
run "1· providers (adapter units)"        $PY tests/test_providers.py
run "2· security pipeline (ZTA)"          $PY tests/test_security_pipeline.py
run "3· gateway agnostic"                 $PY tests/test_gateway_agnostic.py
run "4· end-to-end (public edge)"         $PY tests/test_e2e_full.py
run "5· regressions (bug-hunt findings)"  $PY tests/test_regressions.py
run "6· connectors (SSRF + read-only DB)" $PY tests/test_connectors.py

summary
[ "$fail" -eq 0 ]
