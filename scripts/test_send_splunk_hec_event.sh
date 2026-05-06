#!/usr/bin/env sh
set -eu

URL="${1:-http://localhost:8088/services/collector/event}"
TOKEN="${SPLUNK_HEC_TOKEN:-}"

payload='{
  "time": 1715000000.123,
  "host": "powergrid_opcua_server",
  "source": "labshock_dmz_collector",
  "sourcetype": "labshock:ot:opcua",
  "index": "ot_operations",
  "event": {
    "id": "dmz-splunk-test-001",
    "timestamp": "2026-05-06T10:15:33Z",
    "received_at": "2026-05-06T10:15:33.123Z",
    "zone": "OT",
    "source_type": "opcua",
    "asset_name": "OPC UA Server",
    "asset_ip": "192.168.1.62",
    "severity": "warning",
    "protocol": "syslog",
    "event_category": "operator_write",
    "message": "Test HEC payload",
    "raw": "<134>1 ...",
    "tags": {
      "collector_decision": "forward",
      "matched_rule_id": "rule-opcua-write-keep",
      "splunk_sourcetype": "labshock:ot:opcua",
      "siem_index_hint": "ot_operations"
    }
  }
}'

if [ -n "$TOKEN" ]; then
  curl -sS -X POST "$URL" -H "Content-Type: application/json" -H "Authorization: Splunk $TOKEN" -d "$payload"
else
  curl -sS -X POST "$URL" -H "Content-Type: application/json" -d "$payload"
fi
echo
