#!/usr/bin/env sh
set -eu

HOST="${1:-127.0.0.1}"
PORT="${2:-5514}"
MSG='<134>1 2026-05-06T10:22:11Z fw01 firewall - - - {"action":"deny","src_ip":"192.168.1.45","dst_ip":"192.168.10.5","rule":"dmz_block"}'

if command -v nc >/dev/null 2>&1; then
  printf "%s\n" "$MSG" | nc -u -w1 "$HOST" "$PORT"
else
  echo "nc not found, use a syslog sender tool to UDP ${HOST}:${PORT}"
fi

