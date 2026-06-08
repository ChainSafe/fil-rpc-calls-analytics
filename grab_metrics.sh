#!/usr/bin/env bash
#
# Periodically grab Prometheus metrics and write each snapshot to a
# datetime-stamped file in the given output directory.
#
# Usage:
#   ./grab_metrics.sh OUTPUT_DIR [URL] [INTERVAL_SECONDS]
#
# Examples:
#   ./grab_metrics.sh ./metrics
#   ./grab_metrics.sh ./metrics http://localhost:6116/metrics
#   ./grab_metrics.sh ./metrics http://localhost:6116/metrics 3600
#
# Runs forever, fetching once per interval (default: hourly). Stop with Ctrl-C.

set -euo pipefail

OUTPUT_DIR="${1:-}"
URL="${2:-http://localhost:6116/metrics}"
INTERVAL="${3:-3600}"

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "Usage: $0 OUTPUT_DIR [URL] [INTERVAL_SECONDS]" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Grabbing metrics from $URL into $OUTPUT_DIR every ${INTERVAL}s. Ctrl-C to stop."

while true; do
    stamp="$(date +%Y-%m-%d-%H%M%S)"
    outfile="$OUTPUT_DIR/metrics-$stamp.txt"

    if curl --silent --show-error --fail --max-time 30 "$URL" >"$outfile"; then
        echo "$(date -Is) wrote $outfile"
    else
        echo "$(date -Is) FAILED to fetch $URL" >&2
        rm -f "$outfile"
    fi

    sleep "$INTERVAL"
done
