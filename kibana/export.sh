#!/usr/bin/env bash
# Export everything you've built in Kibana into dashboards.ndjson
# Useful if you tweak the imported dashboards and want to save your changes.
set -e
cd "$(dirname "$0")"

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

curl -sf -X POST "$KIBANA_URL/api/saved_objects/_export" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "type": ["dashboard","visualization","index-pattern","search","lens","map"],
    "includeReferencesDeep": true,
    "excludeExportDetails": true
  }' \
  -o dashboards.ndjson

echo "[export] $(wc -l < dashboards.ndjson) saved objects → kibana/dashboards.ndjson"
