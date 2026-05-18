#!/usr/bin/env sh
set -eu

TARGET="${1:-http://localhost:9000/gds/events}"
TOKEN="${DMZ_INGEST_TOKEN:-}"
TOKEN_FILE="${DMZ_INGEST_TOKEN_FILE:-}"

if [ -z "$TOKEN" ] && [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
fi

payload='[
  {
    "event_type": "certificate_issued",
    "created_at": "2026-05-18T13:00:00Z",
    "actor": "labshock_gds",
    "target": "certificate:42",
    "details_json": {
      "request_id": "req-1",
      "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
      "fingerprint_sha256": "abc123",
      "serial_number": "01:02"
    }
  },
  {
    "event_type": "agent_auth_failure",
    "created_at": "2026-05-18T13:01:00Z",
    "actor": "opcua_dmz_gateway",
    "target": "artifact_read:OT:server",
    "source_ip": "192.168.10.20",
    "error_code": "invalid_token",
    "correlation_id": "corr-1"
  },
  {
    "ts": "2026-05-18T13:02:00Z",
    "level": "INFO",
    "logger": "gds.api",
    "msg": "artifact regenerated zone=OT role=server version=3 revision=7 reason=version_changed"
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
