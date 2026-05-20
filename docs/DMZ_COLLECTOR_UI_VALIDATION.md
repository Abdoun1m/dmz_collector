# DMZ Collector UI Validation

## Build And Test

```bash
go test ./internal/ingest ./internal/api
go test ./...
go build ./cmd/dmz-collector
node --check web/app.js
npm install
npx playwright install chromium
npm run test:ui
```

## Run Locally

```bash
go run ./cmd/dmz-collector
```

Open:

```text
http://127.0.0.1:9000
```

## Docker Rebuild

```bash
docker compose -f docker-compose.dmz.yml build --no-cache dmz_collector
docker compose -f docker-compose.dmz.yml up -d --force-recreate dmz_collector
```

Reattach the container to `br-dmz` using the lab attach script after recreation.

## API Smoke Tests

```bash
curl -s http://127.0.0.1:9000/health | jq
curl -s http://127.0.0.1:9000/stats | jq
curl -s http://127.0.0.1:9000/stats/summary | jq
curl -s http://127.0.0.1:9000/stats/timeline | jq
curl -s 'http://127.0.0.1:9000/events?limit=20' | jq
curl -s http://127.0.0.1:9000/sources | jq
curl -s http://127.0.0.1:9000/queue/status | jq
curl -s http://127.0.0.1:9000/forwarding/status | jq
curl -s http://127.0.0.1:9000/config/forwarding | jq
curl -s http://127.0.0.1:9000/config/rules | jq
curl -s http://127.0.0.1:9000/filter/config | jq
```

Verify `config/forwarding` does not expose `splunk_hec_token`.

## UI Checklist

- Dashboard loads KPIs, distribution panels, and timeline without mock data.
- Events filters work for source type, severity, category, asset, search, and decision.
- Events filters keep focus and typed values during background refresh.
- Event rows open raw/tags previews and JSON modal.
- Copy JSON button copies modal content or displays a browser clipboard failure.
- SSE status shows connected/offline; pause/resume stops live table mutation.
- Sources filters and visibility toggles work.
- Source detail opens a JSON modal.
- Queue page shows queued, forwarded, failed, last success/failure, pause/resume, and flush.
- Forwarding page saves config without exposing existing HEC token.
- Forwarding test reports success or displays the backend error.
- Rules page clearly shows read-only rule/filter state.
- Settings page shows live runtime paths and limitations.
- Narrow viewport keeps the health chip, core event controls, and tab content usable.

## Jump Syslog Validation

```bash
echo '<38>1 2026-05-20T15:30:00Z kali labshock_jumphost 123 - - Accepted publickey for jumpadmin from 192.168.20.5 port 53210 ssh2: RSA-CERT ID jumpadmin-cert' \
| nc -u -w1 192.168.10.70 5514

curl -s 'http://192.168.10.70:9000/events?source_type=jumphost&limit=20' | jq
```

Splunk:

```spl
index=ot_security zone="DMZ" source_type=jumphost
| stats count by message event_category severity source tags.high_value tags.low_value
```
