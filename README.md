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

Build and run the DMZ collector (container image is provided by the repo):

```bash
docker compose -f docker-compose.dmz.yml build
docker compose -f docker-compose.dmz.yml up -d
curl http://localhost:9000/health | jq .
```

UI:

- http://localhost:9000/

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
- GDS event endpoint: `POST /gds/events` for raw GDS API rows, JSON/JSONL logs, health snapshots, and text lines
- Optional OT subscribe mode via SSE (`OT_SSE_ENABLED=true`)
- DMZ Collector self-telemetry (`DMZ_SELF_TELEMETRY_ENABLED=true`) emits `source_type=dmz_collector` events for startup, heartbeat, HEC failures/recovery, and spool growth.

Normalization:

- Firewall -> `source_type=firewall`
- IDS -> `source_type=ids`, `event_category=security`

## 9.1 DMZ Collector Self-Telemetry

Self-telemetry is the first DMZ component to enable and validate. It uses the same Splunk index as the rest of the pipeline:

- `index=ot_security`
- `zone=DMZ`
- `source_type=dmz_collector`
- `sourcetype=labshock:dmz:dmz_collector`

Configuration:

- `DMZ_SELF_TELEMETRY_ENABLED=true`
- `DMZ_SELF_TELEMETRY_INTERVAL_SECONDS=60`
- `DMZ_SELF_TELEMETRY_SPOOL_WARN_EVENTS=1000`
- `DMZ_SELF_TELEMETRY_SPOOL_CRITICAL_EVENTS=10000`
- `DMZ_SELF_TELEMETRY_EVENT_FLOW=true`

Splunk validation:

```spl
index=ot_security zone="DMZ" source_type="dmz_collector"
| stats count by sourcetype source_type asset_name message event_category severity
```

Schema and tags:

```spl
index=ot_security zone="DMZ" source_type="dmz_collector"
| table _time sourcetype source_type asset_name asset_ip severity event_category message tags.normalized tags.parser_version tags.splunk_sourcetype tags.siem_index_hint tags.alert_candidate raw
| sort - _time
```

Health/staleness:

```spl
index=ot_security zone="DMZ" source_type="dmz_collector"
| stats latest(_time) as last_seen count by message event_category severity
| eval staleness_min=round((now()-last_seen)/60,1)
| eval health=case(staleness_min<=2,"FRESH",staleness_min<=10,"WARN",true(),"STALE")
| convert ctime(last_seen)
| sort staleness_min
```

## 9.2 Vault Audit Ingest

Vault keeps its native file audit device enabled and sends raw audit records to the DMZ Collector. The DMZ Collector owns Vault parsing and emits normalized `source_type=vault` events.

Flow:

- Vault audit device writes JSONL to `/vault/logs/vault_audit.jsonl`.
- A minimal Vault-side sender posts each raw audit JSON line to `POST /vault/audit`.
- DMZ Collector classifies the audit record, stores it, spools it, enriches it, and forwards it to Splunk as `sourcetype=labshock:dmz:vault`.

Endpoint:

- `POST /vault/audit`
- Accepts one Vault audit JSON object, an array, or JSONL records.
- Uses the same optional `Authorization: Bearer <DMZ_INGEST_TOKEN>` policy as `/events`.

From `labshock_vault`, a simple `wget` test:

```sh
tail -n 1 /vault/logs/vault_audit.jsonl > /tmp/vault-audit-one.json
wget -qO- \
  --header='Content-Type: application/json' \
  --post-file=/tmp/vault-audit-one.json \
  http://192.168.10.70:9000/vault/audit
```

For continuous forwarding, copy `deploy/vault_audit_forwarder.sh` into the Vault container or bake it into the Vault image, then run it with:

```sh
VAULT_AUDIT_FILE=/vault/logs/vault_audit.jsonl \
DMZ_COLLECTOR_URL=http://192.168.10.70:9000/vault/audit \
sh /usr/local/bin/vault_audit_forwarder.sh
```

Splunk validation:

```spl
index=ot_security zone="DMZ" source_type="vault"
| table _time sourcetype source_type asset_name message event_category severity tags.alert_candidate tags.risk_level raw
| sort - _time
```

## 10. API Endpoints

- `POST /gds/events` - ingest GDS JSON, JSONL, health snapshots, or text lines and normalize to `source_type=gds`.
- `POST /vault/audit` - ingest native Vault audit JSON, arrays, or JSONL and normalize to `source_type=vault`.

The DMZ collector exposes an HTTP API. These routes reflect the current code:

- `POST /events` — ingest one event or an array of events (JSON). Returns structured JSON with counts of accepted/rejected/queued items. Returns HTTP 413 if the payload exceeds the configured limit (4 MiB).
- `GET /health` — service health and basic runtime metadata (storage backend, files, queue summary).
- `GET /events` — list stored events. Supports query filtering (limit, source_type, severity, category, asset, search).
- `GET /events/{id}` — read a single stored event by id.
- `GET /events/stream` — server-sent event stream of incoming events.
- `GET /stats` — alias for `/stats/summary` (returns JSON summary).
- `GET /stats/summary` — aggregated counters and basic telemetry (by source_type, severity, category, top sources).
- `GET /stats/timeline` — timeline buckets of events.
- `GET /sources` — known source status objects.
- `GET /forwarding/status` — forwarding queue counters and last responses.
- `GET /config/forwarding` — current forwarding configuration (Splunk, syslog, paused).
- `POST /config/forwarding` — update forwarding configuration (persisted to disk).
- `POST /forwarding/test` — send a forwarding test event.
- `POST /forwarding/flush` — enqueue pending spool records for forwarding.
- `GET /queue/status` — queue-level snapshot with `queued`, `forwarded`, `failed`, `last_success`, `last_failure`, `paused`, plus `events_file` and `spool_file` paths.
- `GET /config/rules` — simple read-only list of default rules (present for compatibility).
- `GET /filter/config` — stub endpoint returning an empty `filters` array (compatibility placeholder).
- `POST /ids/alerts` — accept IDS (Suricata-like) alert payloads and normalize them into events.

Notes:
- `/events` accepts both a single event object and an array of events.
- Events are first persisted locally to `events_file`, appended to the spool (`spool_file`), and then enqueued for forwarding.

GDS endpoint auth:
- `/gds/events` can use a dedicated token with `DMZ_COLLECTOR_GDS_EVENTS_TOKEN_FILE=/run/secrets/gds-events-token`.
- If the file setting is present, the request must include `Authorization: Bearer <file contents>`.
- If no GDS-specific token is configured, the endpoint falls back to `DMZ_INGEST_TOKEN` for compatibility.
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
- `GET /stats` returns `404` on a deployed system: that binary is older than this repo state. Use `GET /stats/summary` as the canonical stats endpoint until the service is rebuilt and redeployed.
- Events accepted but not forwarded: check `/forwarding/status`, queue pause flag, and HEC URL/token.
- Splunk down: expected queue growth with spool persistence.
- Duplicate OT events with same `id`: deduplicated by design.

## Files And Runtime Notes

- Default storage backend: JSONL (`/data/events.jsonl`). Stored records are JSON objects with `event` and `original_event_json` fields.
- SQLite mode is intentionally not implemented in v1 and the process will exit if selected.
- Spool file and checkpoint: `/data/spool/events.jsonl` and `/data/spool/checkpoint.json`.
- The forward worker prioritizes high-value events (tag `high_value`) when building batches.

Important behaviors implemented in code:

- Deduplication: the collector uses `id` as an idempotency key. If `id` is not provided, a deterministic id is computed from `timestamp|source_type|asset_ip|message|raw|event_category` hashed with SHA1 and prefixed with `dmz-` (first 8 bytes hex). This reduces duplicate entries when upstream retries occur.
- Source normalization: `source_type` is normalized in `internal/normalizer/validator.go`. Known mappings include:
  - `gds-agent` or `gds_agent` -> `gds_agent`
  - `opnsense` -> `firewall`
  - `fuxa` or `fuxa-ui` -> `scada` (decision: map FUXA to `scada` for SIEM grouping; changeable)
- Enrichment: `internal/normalizer/enricher.go` adds tags such as `dmz_collector`, `dmz_received_at`, `purdue_zone`, `splunk_sourcetype`, and `siem_index_hint` based on event fields.
- Payload size limit: HTTP ingestion uses a 4 MiB (4*1024*1024) limit; larger payloads produce HTTP 413 with structured JSON.

Needs verification:
- OT Collector behavior and exact forwarding config format — this repository expects an OT collector at `http://192.168.1.70:8088`, but the OT collector code is not present in this repo. Verify OT collector rules and action fields (store_only, forward_only, sample, drop) in the OT repository if you need enforcement upstream.

## Acceptance / Quick Validation

Build and run container

```bash
docker compose -f docker-compose.dmz.yml build
docker compose -f docker-compose.dmz.yml up -d
```

Health and basic checks

```bash
curl -s http://192.168.1.70:8088/health | jq .  # OT Collector, if present (Needs verification)
curl -s http://192.168.10.70:9000/health | jq .  # DMZ Collector
curl -s http://192.168.10.70:9000/stats | jq .
curl -s 'http://192.168.10.70:9000/events?limit=10' | jq .
```

Use the included validation script to run a quick pipeline validation (posts test events and checks forwarding):

```bash
chmod +x scripts/validate-collector-pipeline.sh
./scripts/validate-collector-pipeline.sh http://192.168.1.70:8088 http://192.168.10.70:9000
```
