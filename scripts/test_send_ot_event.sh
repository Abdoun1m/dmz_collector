#!/usr/bin/env sh
set -eu

TARGET="${1:-http://localhost:9000/events}"
TOKEN="${DMZ_INGEST_TOKEN:-}"

payload='{
  "id": "ot-test-001",
  "timestamp": "2026-05-06T10:15:33Z",
  "received_at": "2026-05-06T10:15:33.123Z",
  "zone": "OT",
  "source_type": "opcua",
  "asset_name": "OPC UA Server",
  "asset_ip": "192.168.1.62",
  "severity": "info",
  "protocol": "syslog",
  "event_category": "operator_write",
  "message": "[OPCUA] [WRITE][CMD] Open valve",
  "raw": "<134>1 ...",
  "tags": {
    "opcua_operation": "WRITE",
    "collector_decision": "forward",
    "matched_rule_id": "rule-opcua-write-keep",
    "sensitive_action": "true"
  }
}'

if [ -n "$TOKEN" ]; then
  curl -sS -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$payload"
else
  curl -sS -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$payload"
fi
echo

