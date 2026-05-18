#!/usr/bin/env sh
set -eu

TARGET="${1:-http://localhost:9000/vault/audit}"
TOKEN="${DMZ_INGEST_TOKEN:-}"

payload='{
  "type": "response",
  "time": "2026-05-18T12:19:32.587246477Z",
  "error": "permission denied",
  "auth": {
    "display_name": "root",
    "policies": ["root"],
    "token_policies": ["root"]
  },
  "request": {
    "id": "c9121682-90c6-e96a-ca6b-afcd73cac59a",
    "operation": "read",
    "path": "sys/internal/ui/mounts/secret/labshock/audit-test",
    "remote_address": "192.168.10.10",
    "remote_port": 53360,
    "mount_type": "system",
    "client_token_accessor": "hmac-sha256:a2280384d7e0"
  }
}'

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
