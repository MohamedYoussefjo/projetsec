#!/usr/bin/env bash
# Import IfSecurity dashboards into Kibana (overwrite if exists).
set -e
cd "$(dirname "$0")"

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

echo "[import] waiting for Kibana at $KIBANA_URL..."
until curl -sf "$KIBANA_URL/api/status" >/dev/null; do
  sleep 2
done

curl -sf -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards.ndjson

echo
echo "[import] done. Open: $KIBANA_URL/app/dashboards"
