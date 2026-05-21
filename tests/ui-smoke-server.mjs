import { createReadStream, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";

const port = Number(process.env.UI_SMOKE_PORT || 9010);
const root = process.cwd();
const webRoot = join(root, "web");

const events = [
  {
    id: "evt-critical-1",
    timestamp: "2026-05-20T10:00:00Z",
    received_at: "2026-05-20T10:00:02Z",
    source: "gds_events",
    source_type: "gds",
    asset_name: "labshock_gds",
    asset_ip: "192.168.10.30",
    zone: "DMZ",
    severity: "critical",
    event_category: "security",
    message: "gds_unauthorized_request",
    collector_decision: "store_forward",
    forward_status: "queued",
    tags: {
      component: "gds",
      splunk_sourcetype: "labshock:dmz:gds",
      siem_index_hint: "ot_security",
      risk_level: "CRITICAL",
    },
    raw: {
      source_ip: "192.168.10.20",
      error_code: "invalid_agent_token",
    },
  },
  {
    id: "evt-info-1",
    timestamp: "2026-05-20T10:01:00Z",
    received_at: "2026-05-20T10:01:02Z",
    source_type: "jumphost",
    asset_name: "labshock_jumphost",
    asset_ip: "192.168.10.5",
    zone: "DMZ",
    severity: "info",
    event_category: "access_control",
    message: "jump_login_success",
    tags: {
      component: "jumphost",
      splunk_sourcetype: "labshock:dmz:jumphost",
      siem_index_hint: "ot_security",
    },
    raw: { user: "jumpadmin", src_ip: "192.168.20.5" },
  },
];

function json(res, body) {
  res.writeHead(200, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function serveAsset(req, res) {
  const requested = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const fullPath = normalize(join(webRoot, requested));
  if (!fullPath.startsWith(webRoot) || !existsSync(fullPath)) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  const types = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
  };
  res.writeHead(200, { "content-type": types[extname(fullPath)] || "application/octet-stream" });
  createReadStream(fullPath).pipe(res);
}

function handleApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/events/stream") {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    res.write("event: ready\ndata: {}\n\n");
    setTimeout(() => {
      res.write(`event: event\ndata: ${JSON.stringify({ ...events[0], id: "evt-stream-1", message: "gds_opcua_method_denied" })}\n\n`);
    }, 100);
    return;
  }
  if (url.pathname === "/health") return json(res, { status: "ok", version: "ui-smoke", data_dir: "/data" });
  if (url.pathname === "/events") return json(res, events);
  if (url.pathname === "/stats" || url.pathname === "/stats/summary") {
    return json(res, {
      total_events: 2,
      total_received: 2,
      critical_count: 1,
      warning_count: 0,
      source_count: 2,
      event_rate_per_second: 0.2,
      spool_file: "/data/spool/events.jsonl",
      splunk_enabled: true,
      splunk_hec_url: "https://splunk.example:8088/services/collector",
      splunk_success_count: 7,
      splunk_failed_count: 1,
      splunk_last_success_at: "2026-05-20T10:02:00Z",
      splunk_last_failure_at: "2026-05-20T10:03:00Z",
      splunk_last_error: "splunk status 503",
      splunk_last_event_id: "evt-critical-1",
      by_severity: { critical: 1, info: 1 },
      by_category: { security: 1, access_control: 1 },
      by_source_type: { gds: 1, jumphost: 1 },
    });
  }
  if (url.pathname === "/stats/timeline") {
    return json(res, [{ hour: "10:00", count: 2 }]);
  }
  if (url.pathname === "/queue/status") {
    return json(res, { queued: 1, forwarded: 0, failed: 0, paused: false, spool_file: "/data/spool/events.jsonl" });
  }
  if (url.pathname === "/forwarding/status") {
    return json(res, { forwarded: 0, failed: 0, queued: 1, last_response: "" });
  }
  if (url.pathname === "/config/forwarding") {
    if (req.method === "POST") return json(res, { ok: true });
    return json(res, {
      splunk_enabled: true,
      splunk_hec_url: "https://splunk.example:8088/services/collector",
      splunk_index: "ot_security",
      splunk_source: "labshock_dmz_collector",
      splunk_hec_token_set: true,
      splunk_verify_tls: false,
      syslog_forward_enabled: false,
      paused: false,
    });
  }
  if (url.pathname === "/sources" || url.pathname === "/sources/summary") {
    return json(res, {
      generated_at: "2026-05-20T10:02:00Z",
      total_sources: 2,
      visible_sources: 2,
      configured_sources: 2,
      discovered_sources: 0,
      sources: [
        {
          id: "gds-192.168.10.30",
          name: "labshock_gds",
          group: "GDS / PKI",
          source_type: "gds",
          asset_ip: "192.168.10.30",
          zone: "DMZ",
          protocol: "opcua",
          enabled: true,
          configured: true,
          forward_enabled: true,
          event_count: 1,
          severity_counts: { critical: 1 },
          category_counts: { security: 1 },
          siem_index_hint: "ot_security",
        },
      ],
    });
  }
  if (url.pathname === "/sources/detail") return json(res, { source_type: url.searchParams.get("source_type"), events });
  if (url.pathname === "/config/rules") return json(res, [{ id: "store-forward-critical", action: "store_forward", enabled: true }]);
  if (url.pathname === "/filter/config") return json(res, { default_decision: "store_forward", rules_loaded: 1 });
  if (url.pathname === "/forwarding/test" || url.pathname === "/forwarding/flush") return json(res, { ok: true });
  return false;
}

createServer((req, res) => {
  if (handleApi(req, res) !== false) return;
  serveAsset(req, res);
}).listen(port, "127.0.0.1", () => {
  const index = readFileSync(join(webRoot, "index.html"), "utf8");
  if (!index.includes("DataProtect DMZ Collector")) process.exit(1);
  console.log(`UI smoke server listening on http://127.0.0.1:${port}`);
});
