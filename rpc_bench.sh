#!/usr/bin/env bash
set -euo pipefail

# Uses https://github.com/hatoo/oha

LOTUS_URL="${LOTUS_URL:-http://127.0.0.1:1234/rpc/v1}"
FOREST_URL="${FOREST_URL:-http://127.0.0.1:2345/rpc/v1}"

METHOD="${1:-eth_getBlockByNumber}"
PARAMS="${2:-[\"pending\", true]}"

PAYLOAD=$(jq -nc --arg m "$METHOD" --argjson p "$PARAMS" \
  '{jsonrpc:"2.0", method:$m, params:$p, id:1}')

RESULTS_DIR="${RESULTS_DIR:-results}"
mkdir -p "$RESULTS_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASENAME="${METHOD}-${STAMP}"

OHA_REQUESTS="${OHA_REQUESTS:-2000}"
OHA_CONCURRENCY="${OHA_CONCURRENCY:-10}"
OHA_WARMUP="${OHA_WARMUP:-200}"

printf 'method:    %s\nparams:    %s\npayload:   %s\nlotus:     %s\nforest:    %s\n\n' \
  "$METHOD" "$PARAMS" "$PAYLOAD" "$LOTUS_URL" "$FOREST_URL"

probe() {
  local name="$1" url="$2"
  if ! resp=$(curl -sS --max-time 5 -H 'Content-Type: application/json' -d "$PAYLOAD" "$url"); then
    echo "error: $name ($url) unreachable" >&2
    return 1
  fi
  printf '%-8s -> %s\n' "$name" "$resp"
}

echo "=== sanity probe ==="
probe lotus  "$LOTUS_URL"
probe forest "$FOREST_URL"
echo

oha_run() {
  local name="$1"
  local url="$2"
  local out="$RESULTS_DIR/$BASENAME.$name.txt"
  echo "--- $name ($url) ---"
  if [[ "$OHA_WARMUP" -gt 0 ]]; then
    echo "warmup ($OHA_WARMUP requests)..."
    oha --no-tui \
      -n "$OHA_WARMUP" \
      -c "$OHA_CONCURRENCY" \
      -m POST \
      -H 'Content-Type: application/json' \
      -d "$PAYLOAD" \
      "$url" >/dev/null
  fi
  oha --no-tui \
    -n "$OHA_REQUESTS" \
    -c "$OHA_CONCURRENCY" \
    -m POST \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" \
    "$url" | tee "$out"
  echo
}

echo "=== oha ==="
oha_run lotus  "$LOTUS_URL"
oha_run forest "$FOREST_URL"

echo "results written to $RESULTS_DIR/$BASENAME.*"
