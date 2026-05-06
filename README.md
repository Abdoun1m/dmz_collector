# DMZ Collector (LabShock/DataProtect) - V1

Native Go DMZ security telemetry collector for LabShock/DataProtect OT cyber-range environments.

## 1. Purpose

The DMZ Collector receives normalized OT events from `ot_collector`, preserves them, enriches them for SIEM usage, buffers reliably, and forwards asynchronously to Splunk HEC (primary) or syslog (fallback). It is parallel security telemetry infrastructure and does not sit inline with MES traffic.

## 2. Architecture

`PLC / SCADA / OPC UA / EWS -> OT Collector (192.168.1.70:8088) -> DMZ Collector (192.168.10.70:9000) -> Splunk HEC / Syslog / Future SIEM`

Durability path:

1. Event accepted by `POST /events`
2. Stored to `/data/events.jsonl`
3. Appended to `/data/spool/events.jsonl`
4. Queued for async forwarding worker
5. Retries with backoff on forwarding failure

## 3. Relationship To OT Collector

Compatibility is preserved with the OT Collector schema and forwarding behavior:

- `POST /events` accepts one event object or array.
- Unknown future event fields, unknown tags, unknown source types, and unknown categories are accepted.
- Event `id` is used as idempotency key (dedup by ID).
- Ingest path is fast and fail-open to avoid OT forwarding regressions.
- Optional shared token auth via `Authorization: Bearer <token>`.

OT Collector forwarding target:

- UI/API forwarding URL: `http://192.168.10.70:9000/events`
- Env alternative: `DMZ_COLLECTOR_URL=http://192.168.10.70:9000/events`

## 4. Build / Run

```bash
docker compose -f docker-compose.dmz.yml build
docker compose -f docker-compose.dmz.yml up -d
curl http://localhost:9000/health
```

UI:

- `http://localhost:9000/`

## 5. OVS Attachment

Container runs with `network_mode: none` and must be attached manually to `br-dmz`.

Snippet template:

- [deploy/attach_dmz_collector_snippet.sh](/C:/Users/User/Documents/GitHub/dmz_collector/deploy/attach_dmz_collector_snippet.sh)

After attach to `192.168.10.70/24` with gateway `192.168.10.254`:

```bash
curl http://192.168.10.70:9000/health
```

## 6. Configure OT Collector Forwarding

From OT Collector UI (`/config/forwarding`) or env:

```json
{
  "dmz_collector_url": "http://192.168.10.70:9000/events",
  "enabled": true,
  "forward_only_filtered_events": true
}
```

If token is enabled on DMZ:

- Set `DMZ_INGEST_TOKEN` in DMZ Collector
- Configure OT Collector to send `Authorization: Bearer <token>`

## 7. Splunk HEC Setup

Environment:

- `SPLUNK_HEC_ENABLED=true`
- `SPLUNK_HEC_URL=https://splunk_it:8088/services/collector/event`
- `SPLUNK_HEC_TOKEN=<token>`
- `SPLUNK_INDEX=ot_security`
- `SPLUNK_SOURCE=labshock_dmz_collector`
- `SPLUNK_VERIFY_TLS=false` (lab mode)

Sourcetype mapping:

- `plc -> labshock:ot:plc`
- `scada -> labshock:ot:scada`
- `opcua -> labshock:ot:opcua`
- `ews -> labshock:ot:ews`
- `firewall -> labshock:net:firewall`
- `ids -> labshock:ids:alert`
- `unknown -> labshock:ot:unknown`

Index hint mapping is enriched into `tags.siem_index_hint`.

## 8. Vault Future Integration

Current v1 behavior:

- Vault package exists and is disabled by default.
- Env supported:
  - `VAULT_ENABLED=false`
  - `VAULT_ADDR=http://192.168.10.10:8200`
  - `VAULT_TOKEN=`
  - `VAULT_SECRET_PATH=secret/data/dmz_collector/splunk`
- Secret renewal and dynamic token refresh are intentionally deferred.

## 9. Firewall / IDS Future Ingestion

Available now:

- Firewall syslog listener (UDP): `0.0.0.0:5514` (configurable)
- IDS alert endpoint: `POST /ids/alerts` with Suricata-like EVE alert payload
- Optional OT subscribe mode via SSE (`OT_SSE_ENABLED=true`)

Normalization:

- Firewall -> `source_type=firewall`
- IDS -> `source_type=ids`, `event_category=security`

## 10. API Endpoints

- `POST /events`
- `GET /health`
- `GET /events`
- `GET /events/{id}`
- `GET /events/stream` (SSE)
- `GET /stats/summary`
- `GET /stats/timeline`
- `GET /sources`
- `GET /forwarding/status`
- `GET /config/forwarding`
- `POST /config/forwarding`
- `POST /forwarding/test`
- `POST /forwarding/flush`
- `GET /queue/status`
- `POST /ids/alerts`

## 11. Troubleshooting

- Check health:
  - `curl http://localhost:9000/health`
- Check summary:
  - `curl http://localhost:9000/stats/summary`
- Check forwarding config:
  - `curl http://localhost:9000/config/forwarding`
- Send test OT event:
  - `./scripts/test_send_ot_event.sh`
- View events:
  - `curl http://localhost:9000/events`

Common issues:

- `non-2xx` from `/events`: validate token/header mismatch.
- Events accepted but not forwarded: check `/forwarding/status`, queue pause flag, and HEC URL/token.
- Splunk down: expected queue growth with spool persistence.
- Duplicate OT events with same `id`: deduplicated by design.

## Files And Runtime Notes

- Default storage backend: JSONL (`/data/events.jsonl`)
- SQLite mode is intentionally not implemented in v1 and exits with clear error.
- Spool checkpoint persists in `/data/spool/checkpoint.json`.
- High-value events are prioritized in forwarding worker batches.

## Acceptance Commands

```bash
docker compose -f docker-compose.dmz.yml build
docker compose -f docker-compose.dmz.yml up -d
curl http://localhost:9000/health
curl http://localhost:9000/stats/summary
curl http://localhost:9000/config/forwarding
./scripts/test_send_ot_event.sh
curl http://localhost:9000/events
```
