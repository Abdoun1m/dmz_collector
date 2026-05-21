# DMZ Collector UI/API Contract

This document describes the live backend contract used by the embedded DMZ Collector UI.

## Frontend Architecture

- Framework: static HTML, CSS, and vanilla JavaScript embedded from `web/`.
- API base: same-origin by default. Override only for split deployments with `window.DMZ_COLLECTOR_API_BASE` or `localStorage.dmz_api_base`.
- No mock operational data is rendered. Empty panels represent empty live responses or API errors.
- Background refresh updates health, stats, queue, and forwarding state without rerendering active operator forms or filters.

## Backend Architecture

- Framework: Go `net/http`.
- Static UI: served from embedded `web` filesystem.
- Static UI assets are served with no-cache headers so rebuilt containers do not leave operators on stale JavaScript or CSS.
- Storage: append-only JSONL events and spool.
- Streaming: server-sent events at `/events/stream`.

## Routes Used By UI

| Method | Path | UI use |
| --- | --- | --- |
| `GET` | `/health` | Collector health and runtime paths |
| `GET` | `/events` | Events table; supports `limit`, `source_type`, `severity`, `category`, `asset`, `asset_ip`, `search` |
| `GET` | `/events/{id}` | Available but not used by the table; row JSON already includes full event |
| `GET` | `/events/stream` | Live event stream via SSE |
| `GET` | `/stats` | Distribution data and runtime stats |
| `GET` | `/stats/summary` | KPI row and Splunk summary |
| `GET` | `/stats/timeline` | Dashboard timeline |
| `GET` | `/sources` | Source inventory; supports visibility flags |
| `GET` | `/sources/summary` | Source distribution summary |
| `GET` | `/sources/detail` | Source detail modal; requires `source_type`, `asset_ip`, optional `limit` |
| `GET` | `/config/rules` | Read-only rule matrix |
| `GET` | `/filter/config` | Read-only filter config |
| `GET` | `/queue/status` | Queue and spool state |
| `GET` | `/forwarding/status` | Forwarding counters and last response |
| `GET` | `/config/forwarding` | Forwarding config without exposing secrets |
| `POST` | `/config/forwarding` | Save forwarding config |
| `POST` | `/forwarding/test` | Send forwarding test event |
| `POST` | `/forwarding/flush` | Requeue pending spool records |

## Event Adapter Fields

The UI normalizes backend events before display:

- `id`
- `timestamp`
- `received_at`
- `source`
- `source_type`
- `source_ip`: `source_ip`, `tags.source_ip`, `raw.source_ip`, `raw.src_ip`, then `asset_ip`
- `component`: `component`, `tags.component`, `raw.component`, then `source_type`
- `zone`
- `severity`
- `event_category`
- `message`
- `collector_decision`: `collector_decision`, `tags.collector_decision`, then `tags.collector_decision_hint`
- `matched_rule_id`: `matched_rule_id`, then `tags.matched_rule_id`
- `forward_status`: `forward_status`, `forwarding_status`, `tags.forwarding_status`, then `tags.forward_status`
- `tags`
- `raw`: parsed for preview when it is JSON, preserved as text when it is not JSON

## Security Contract

- `GET /config/forwarding` returns `splunk_hec_token_set=true|false` and never returns the HEC token value.
- `POST /config/forwarding` preserves the current token when `splunk_hec_token` is blank or `********`.
- The UI renders raw logs with text escaping; it does not inject raw HTML.
- JSON copy actions report failure when the browser clipboard API is unavailable instead of implying success.

## Intentional Limitations

- Source CRUD is not implemented by the backend. UI edit controls are disabled.
- Rule CRUD is not implemented by the backend. The rule matrix is read-only.
- Event delete/archive is not implemented. Events are append-only.
- Per-item queue retry is not implemented. Use `/forwarding/flush` to requeue pending spool records.
