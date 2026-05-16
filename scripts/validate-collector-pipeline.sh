#!/usr/bin/env sh
set -eu

OT_BASE="${1:-http://192.168.1.70:8088}"
DMZ_BASE="${2:-http://192.168.10.70:9000}"

echo "Checking OT Collector health..."
curl -s "$OT_BASE/health" | jq .

echo "Checking DMZ Collector health..."
curl -s "$DMZ_BASE/health" | jq .

# Post a test event to OT collector (if available)
TEST_ID="ot-validate-$(date +%s)"
payload=$(cat <<EOF
{
  "id": "${TEST_ID}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "received_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "zone": "OT",
  "source_type": "gds-agent",
  "asset_name": "validation-agent",
  "asset_ip": "192.168.1.99",
  "severity": "info",
  "protocol": "http",
  "event_category": "test",
  "message": "validation event",
  "raw": "validation",
  "tags": {"collector_decision":"forward","matched_rule_id":"temp-allow-all-labshock"}
}
EOF
)

echo "Posting event to OT Collector: $OT_BASE/events"
curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$OT_BASE/events" | jq . || true

sleep 2

echo "Checking OT /events for test id"
curl -s "$OT_BASE/events?limit=10" | jq '.[] | select(.id=="'${TEST_ID}'")' || true

sleep 2

echo "Checking DMZ /events for forwarded test id"
curl -s "$DMZ_BASE/events?limit=50" | jq '.[] | select(.id=="'${TEST_ID}'")' || true

# Post directly to DMZ
DMZ_TEST_ID="dmz-validate-$(date +%s)"
payload2=$(cat <<EOF
{
  "id": "${DMZ_TEST_ID}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "received_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "zone": "DMZ",
  "source_type": "opnsense",
  "asset_name": "opnsense-fw",
  "asset_ip": "192.168.10.1",
  "severity": "warning",
  "protocol": "syslog",
  "event_category": "security",
  "message": "firewall_pass",
  "raw": "<134>1 firewall",
  "tags": {"collector_decision":"forward","matched_rule_id":"temp-allow-all-labshock"}
}
EOF
)

echo "Posting event directly to DMZ Collector"
curl -s -X POST -H "Content-Type: application/json" -d "$payload2" "$DMZ_BASE/events" | jq . || true

sleep 2

echo "Checking DMZ /events for direct test id"
curl -s "$DMZ_BASE/events?limit=10" | jq '.[] | select(.id=="'${DMZ_TEST_ID}'")' || true

# Stats endpoints
echo "Checking DMZ /stats"
curl -s "$DMZ_BASE/stats" | jq .

echo "Checking DMZ /stats/summary"
curl -s "$DMZ_BASE/stats/summary" | jq .

# Normalization checks
echo "Verifying source_type normalization for gds-agent -> gds_agent"
curl -s "$DMZ_BASE/events?limit=50" | jq '.[] | select(.id=="'${TEST_ID}'") | {id: .id, source_type: .source_type, tags: .tags}' || true

echo "Verifying firewall event preserved"
curl -s "$DMZ_BASE/events?limit=50" | jq '.[] | select(.id=="'${DMZ_TEST_ID}'") | {id: .id, source_type: .source_type, message: .message, tags: .tags}' || true

echo "Validation script complete."
