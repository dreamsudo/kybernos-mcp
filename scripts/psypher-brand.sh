#!/usr/bin/env bash
# =============================================================================
#  psypher-brand.sh — Kybernos banner + sloth/mango loader (cosmetic only).
#
#  Prints the neon diamond logo + locked motto, then a sloth crawling toward a
#  mango, looping until the wrapped command finishes. Touches nothing.
#
#  Usage:
#    ./scripts/psypher-brand.sh                    demo: banner + sloth loop (Ctrl-C to stop)
#    ./scripts/psypher-brand.sh up                 banner, then bring the stack up (compose)
#    ./scripts/psypher-brand.sh <cmd...>           banner + sloth while <cmd> runs, then output
#
#  Kybernos — Greek κυβερνήτης, "the steersman/governor" · by Psypher Labs
# =============================================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root
cd "$DIR"

GREEN=$'\033[38;2;57;255;20m'    # neon green  #39FF14
ROSE=$'\033[1;38;2;255;45;149m'  # neon rose   #FF2D95 (bold)
DIM=$'\033[38;2;199;204;199m'    # soft gray
RESET=$'\033[0m'
MANGO="🥭"
SLOTH="🦥"
WIDTH=18

banner() {
  printf '%s' "$GREEN"
  cat <<'LOGO'

               *
              ***
             *****
            *******
           *********
          ***********
         *****Psypher*****
          *****Labs*****
           ***********
            *******
             *****
              ***
               *
LOGO
  printf '%s\n' "$RESET"
  printf '%sKybernos%s %sby Psypher Labs%s\n' "$ROSE" "$RESET" "$GREEN" "$RESET"
  printf '%sZero-Trust Gateway for AI Agents — steer what your AI may do%s\n' "$DIM" "$RESET"
  printf '%sκυβερνήτης · the steersman for your AI agents%s\n\n' "$DIM" "$RESET"
}

# deadpan sloth captions (gateway / zero-trust themed)
CAPTIONS=(
  "manning the gate..."
  "steering the tool-call..."
  "checking the allow-list..."
  "minting a capability token..."
  "validating the schema, slowly..."
  "sniffing the payload for exploits..."
  "one claw on the firewall rule..."
  "no model gets past the sloth..."
  "trust nothing, verify everything..."
  "least privilege, maximum nap..."
  "the model asked nicely, denied anyway..."
  "auditing in triplicate, encrypted..."
  "prompt injection? not on this watch..."
  "SSRF tried the metadata endpoint. blocked..."
  "DROP TABLE? more like DROP request..."
  "path traversal caught mid-crawl..."
  "the token expired before the exploit landed..."
  "revoking a jti, mid-yawn..."
  "steering around the internal IP..."
  "the gate holds. the sloth rests..."
  "reticulating the mango splines..."
  "slow and steady guards the gate..."
  "a mango a day keeps the RCE away..."
  "governing the agents, one call at a time..."
  "too slow to fail, too calm to breach..."
  "the steersman never sleeps (much)..."
)
random_caption() { echo "${CAPTIONS[RANDOM % ${#CAPTIONS[@]}]}"; }
dots() { local n=$1 s='' i; for ((i=0; i<n; i++)); do s+='·'; done; printf '%s' "$s"; }
cleanup() { printf '\033[?25h'; }
trap cleanup EXIT

one_pass() {
  local cap; cap="$(random_caption)"
  local p
  for (( p=WIDTH; p>=0; p-- )); do
    "$@" || return 0
    printf '\r %s%s%s%s   %s%-38s%s' "$MANGO" "$(dots "$p")" "$SLOTH" "$(dots "$((WIDTH-p))")" "$DIM" "$cap" "$RESET"
    sleep 0.14
  done
}

# MODE 1: demo (no args) — loop forever until Ctrl-C
if [ "$#" -eq 0 ]; then
  banner
  printf '\033[?25l'
  trap 'printf "\033[?25h\n"; exit 0' INT TERM
  while true; do one_pass true; done
fi

# Convenience: "up" → bring the compose stack up
if [ "$1" = "up" ]; then
  shift
  set -- docker compose -f deploy/docker/docker-compose.yml up --build "$@"
fi

# MODE 2: wrap the real command — loop until it exits
LOG="$(mktemp /tmp/kybernos-brand.XXXXXX.log)"
export FORCE_COLOR=1
trap 'printf "\033[?25h\n"; kill "$PID" 2>/dev/null; rm -f "$LOG"; exit 130' INT TERM
trap 'printf "\033[?25h"; rm -f "$LOG"' EXIT

banner
"$@" >"$LOG" 2>&1 &
PID=$!
printf '\033[?25l'
while kill -0 "$PID" 2>/dev/null; do
  one_pass kill -0 "$PID"
done
wait "$PID"; rc=$?
printf '\r%80s\r' ''
cat "$LOG"
printf '\n %s%s  nom nom nom — the gate holds.\n' "$SLOTH" "$MANGO"
exit "$rc"
