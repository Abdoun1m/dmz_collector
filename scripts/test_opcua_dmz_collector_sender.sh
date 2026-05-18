#!/usr/bin/env sh
set -eu

TARGET="${1:-http://localhost:9000/opcua-dmz/events}"
TOKEN="${DMZ_COLLECTOR_OPCUA_DMZ_EVENTS_TOKEN:-${DMZ_INGEST_TOKEN:-}}"
TOKEN_FILE="${DMZ_COLLECTOR_OPCUA_DMZ_EVENTS_TOKEN_FILE:-${DMZ_INGEST_TOKEN_FILE:-}}"

if [ -z "$TOKEN" ] && [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
fi

payload='[
  {
    "source_type": "opcua_dmz_gateway",
    "sourcetype": "labshock:dmz:opcua_gateway",
    "zone": "DMZ",
    "asset_name": "opcua_dmz_gateway",
    "asset_ip": "192.168.10.20",
    "protocol": "opcua",
    "source": "opcua_dmz_gateway",
    "message": "opcua_dmz_gds_trust_pull_success",
    "event_category": "pki_trust_sync",
    "severity": "info",
    "raw": {
      "event_type": "trust_pull_completed",
      "target": "dmz-gateway-client",
      "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
      "status": "completed"
    }
  },
  {
    "source_type": "opcua_dmz_gateway",
    "message": "opcua_dmz_southbound_connect_failed",
    "event_category": "opcua_session",
    "severity": "warning",
    "raw": {
      "event_type": "southbound_connect_failed",
      "endpoint": "opc.tcp://192.168.1.62:4840",
      "status_name": "BadSecurityChecksFailed"
    }
  }
]'

if command -v curl >/dev/null 2>&1; then
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
elif command -v wget >/dev/null 2>&1; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  printf '%s\n' "$payload" > "$tmp"
  if [ -n "$TOKEN" ]; then
    wget -qO- \
      --header="Content-Type: application/json" \
      --header="Authorization: Bearer $TOKEN" \
      --post-file="$tmp" \
      "$TARGET"
  else
    wget -qO- \
      --header="Content-Type: application/json" \
      --post-file="$tmp" \
      "$TARGET"
  fi
else
  echo "curl or wget is required" >&2
  exit 1
fi
echo
