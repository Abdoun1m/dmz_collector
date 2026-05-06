#!/usr/bin/env sh
set -eu

URL="${1:-http://localhost:9000/ids/alerts}"
TOKEN="${DMZ_INGEST_TOKEN:-}"

payload='{
  "timestamp": "2026-05-06T10:35:00Z",
  "event_type": "alert",
  "src_ip": "192.168.1.62",
  "dest_ip": "192.168.10.20",
  "alert": {
    "signature": "ET POLICY Possible ICS Unauthorized Write",
    "severity": 2,
    "category": "Attempted Administrator Privilege Gain"
  }
}'

if [ -n "$TOKEN" ]; then
  curl -sS -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$payload"
else
  curl -sS -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d "$payload"
fi
echo

