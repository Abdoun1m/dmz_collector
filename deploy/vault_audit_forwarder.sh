#!/usr/bin/env sh
set -eu

VAULT_AUDIT_FILE="${VAULT_AUDIT_FILE:-/vault/logs/vault_audit.jsonl}"
DMZ_COLLECTOR_URL="${DMZ_COLLECTOR_URL:-http://192.168.10.70:9000/vault/audit}"
DMZ_INGEST_TOKEN="${DMZ_INGEST_TOKEN:-}"
LOG_FILE="${VAULT_AUDIT_FORWARDER_LOG:-/vault/logs/vault_audit_forwarder.log}"

log() {
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '%s %s\n' "$ts" "$*" >> "$LOG_FILE"
}

post_line() {
  line="$1"
  tmp="/tmp/vault-audit-forwarder.$$.json"
  printf '%s\n' "$line" > "$tmp"
  set +e
  if [ -n "$DMZ_INGEST_TOKEN" ]; then
    wget -qO- \
      --header='Content-Type: application/json' \
      --header="Authorization: Bearer $DMZ_INGEST_TOKEN" \
      --post-file="$tmp" \
      "$DMZ_COLLECTOR_URL" >/dev/null
  else
    wget -qO- \
      --header='Content-Type: application/json' \
      --post-file="$tmp" \
      "$DMZ_COLLECTOR_URL" >/dev/null
  fi
  rc=$?
  set -e
  rm -f "$tmp"
  return "$rc"
}

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

if [ ! -f "$VAULT_AUDIT_FILE" ]; then
  log "waiting for audit file: $VAULT_AUDIT_FILE"
  while [ ! -f "$VAULT_AUDIT_FILE" ]; do
    sleep 2
  done
fi

log "starting vault audit forwarder file=$VAULT_AUDIT_FILE target=$DMZ_COLLECTOR_URL"

tail -n 0 -f "$VAULT_AUDIT_FILE" | while IFS= read -r line; do
  [ -n "$line" ] || continue
  if post_line "$line"; then
    log "send ok"
  else
    log "send failed"
  fi
done
