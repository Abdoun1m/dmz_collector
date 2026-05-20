/* =========================================================
   DataProtect DMZ Collector — Frontend App
   All API calls preserved. No fake data.
   ========================================================= */

const API_BASE = String(window.DMZ_COLLECTOR_API_BASE || localStorage.getItem("dmz_api_base") || "").replace(/\/$/, "");
const MAX_LIVE_EVENTS = 300;

const state = {
  activeTab: "dashboard",
  events: [],
  health: {},
  stats: {},
  statsSummary: {},
  queue: {},
  forwarding: {},
  forwardingStatus: {},
  sources: {},
  sourcesSummary: {},
  timeline: [],
  rules: [],
  filterConfig: {},
  errors: {},
  notices: {},
  stream: {
    source: null,
    connected: false,
    paused: false,
    lastEventAt: "",
  },
  eventFilters: {
    source_type: "",
    severity: "",
    category: "",
    asset: "",
    decision: "",
    search: "",
  },
  eventSort: { field: "received_at", dir: "desc" },
  eventPage: 1,
  sourceVisibility: {
    includeInternal: false,
    includeDisabled: false,
    includeDirectSIEM: false,
  },
  sourceFilter: {
    group: "",
    sourceType: "",
    zone: "",
    severity: "",
    enabled: "",
    configured: "",
    search: "",
  },
};

/* ── DOM refs ──────────────────────────────────────────────── */
const tabs = document.querySelectorAll(".tabs button");
const jsonModal = document.getElementById("json-modal");
const jsonModalBody = document.getElementById("json-modal-body");

document.getElementById("json-modal-close").addEventListener("click", () => jsonModal.close());

tabs.forEach((btn) => {
  btn.addEventListener("click", () => {
    state.activeTab = btn.dataset.tab;
    tabs.forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${state.activeTab}`));
    renderActiveTab();
  });
});

/* ── API adapter (unchanged) ───────────────────────────────── */
async function api(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...opts,
    headers: { ...(opts.headers || {}) },
  });
  const text = await res.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = text; }
  }
  if (!res.ok) {
    const msg = typeof body === "string" ? body : body?.error || body?.errors?.join(", ") || res.statusText;
    throw new Error(`${path}: ${res.status} ${msg}`);
  }
  return body ?? {};
}

/* ── Core utilities (unchanged) ────────────────────────────── */
function setError(key, err) {
  if (err) state.errors[key] = err.message || String(err);
  else delete state.errors[key];
}

function safe(v, d = "-") {
  if (v === undefined || v === null || v === "") return d;
  return v;
}

function esc(v) {
  return String(safe(v, "")).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function fmtTime(v) {
  if (!v) return "-";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return esc(v);
  return d.toLocaleString();
}

function asObject(v) {
  if (!v) return {};
  if (typeof v === "object" && !Array.isArray(v)) return v;
  if (typeof v === "string") {
    try {
      const parsed = JSON.parse(v);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : { value: parsed };
    } catch { return { detail: v }; }
  }
  return { value: v };
}

function tag(e, key, fallback = "") {
  const tags = e?.tags || {};
  if (tags[key] !== undefined && tags[key] !== null && tags[key] !== "") return tags[key];
  return fallback;
}

function normalizeEvent(e) {
  const raw = asObject(e.raw);
  const tags = e.tags && typeof e.tags === "object" ? e.tags : {};
  const collectorDecision = e.collector_decision || tag(e, "collector_decision", tag(e, "collector_decision_hint", ""));
  const matchedRuleID = e.matched_rule_id || tag(e, "matched_rule_id", "");
  const forwardStatus = e.forward_status || e.forwarding_status || tag(e, "forwarding_status", tag(e, "forward_status", ""));
  return {
    ...e,
    tags,
    raw_object: raw,
    timestamp_display: fmtTime(e.timestamp),
    received_display: fmtTime(e.received_at),
    component: e.component || tag(e, "component", raw.component || e.source_type || ""),
    source_ip: e.source_ip || tag(e, "source_ip", raw.source_ip || raw.src_ip || e.asset_ip || ""),
    collector_decision: collectorDecision,
    matched_rule_id: matchedRuleID,
    forward_status: forwardStatus,
    splunk_sourcetype: tag(e, "splunk_sourcetype", e.sourcetype || ""),
    siem_index_hint: tag(e, "siem_index_hint", ""),
  };
}

/* ── Notice/error/empty blocks ─────────────────────────────── */
function errorBlock(key) {
  if (!state.errors[key]) return "";
  return `<div class="notice error">&#9888; ${esc(state.errors[key])}</div>`;
}

function noticeBlock(key) {
  if (!state.notices[key]) return "";
  return `<div class="notice ok">&#10003; ${esc(state.notices[key])}</div>`;
}

function emptyState(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

/* ── Theme toggle ──────────────────────────────────────────── */
function initTheme() {
  const saved = localStorage.getItem("dmz-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  btn.title = "Toggle light/dark mode";
  btn.innerHTML = saved === "light" ? "&#9790;" : "&#9788;";
  btn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("dmz-theme", next);
    btn.innerHTML = next === "light" ? "&#9790;" : "&#9788;";
  });
}

/* ── Render helpers ────────────────────────────────────────── */
function card(label, value, sub) {
  return `<article class="card">
    <div class="label">${esc(label)}</div>
    <div class="kpi">${esc(value)}</div>
    ${sub ? `<div class="stat-sub">${esc(sub)}</div>` : ""}
  </article>`;
}

function statCard(label, value, sub, accent) {
  const ac = accent ? ` ac-${esc(accent)}` : "";
  return `<article class="stat-card${ac}">
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value">${esc(value)}</div>
    ${sub ? `<div class="stat-sub">${esc(sub)}</div>` : ""}
  </article>`;
}

function badge(value, prefix) {
  const v = String(safe(value, "unknown")).toLowerCase();
  const p = prefix || "sev";
  return `<span class="badge ${esc(p)}-${esc(v)}">${esc(value)}</span>`;
}

function decisionBadge(decision) {
  const d = String(decision || "").toLowerCase();
  let cls = "action-unknown";
  if (d.includes("drop")) cls = "action-drop";
  else if (d.includes("forward")) cls = "action-forward";
  else if (d.includes("sample")) cls = "action-sample";
  else if (d.includes("store")) cls = "action-store";
  else if (d.includes("keep")) cls = "action-keep";
  return `<span class="badge ${cls}">${esc(decision || "–")}</span>`;
}

function statusDot(ok) {
  const cls = ok === true ? "ok" : ok === false ? "err" : "off";
  return `<span class="status-dot ${cls}"></span>`;
}

function objectEntriesBars(obj) {
  const entries = Object.entries(obj || {}).sort((a, b) => Number(b[1]) - Number(a[1]));
  if (!entries.length) return emptyState("No data yet.");
  const max = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
  return `<div class="bars">${entries.map(([k, v]) => `
    <div class="bar-row">
      <span>${esc(k)}</span>
      <div class="bar"><span style="width:${Math.max(2, (Number(v) || 0) / max * 100)}%"></span></div>
      <strong>${esc(v)}</strong>
    </div>`).join("")}</div>`;
}

function miniPipeline(nodes) {
  return `<div class="mini-pipeline">
    ${nodes.map((n, i) => `
      ${i > 0 ? `<span class="pipeline-arrow">&#8594;</span>` : ""}
      <div class="pipeline-node ${esc(n.cls || "")}">${esc(n.label)}</div>
    `).join("")}
  </div>`;
}

function renderApiHealthGrid() {
  const checks = [
    { path: "/health",            ok: !!(state.health?.status) },
    { path: "/stats",             ok: state.stats && Object.keys(state.stats).length > 0 },
    { path: "/stats/summary",     ok: state.statsSummary && Object.keys(state.statsSummary).length > 0 },
    { path: "/stats/timeline",    ok: Array.isArray(state.timeline) },
    { path: "/events",            ok: Array.isArray(state.events) },
    { path: "/sources",           ok: !!(state.sources?.sources) },
    { path: "/config/rules",      ok: !!(state.rules && (Array.isArray(state.rules) ? state.rules.length >= 0 : state.rules.rules)) },
    { path: "/filter/config",     ok: !!(state.filterConfig) },
    { path: "/config/forwarding", ok: !!(state.forwarding) },
    { path: "/forwarding/status", ok: !!(state.forwardingStatus) },
    { path: "/queue/status",      ok: !!(state.queue) },
  ];
  return `<div class="api-health-grid">
    ${checks.map((c) => `
      <div class="api-health-item">
        ${statusDot(c.ok)}
        <code>${esc(c.path)}</code>
        <span class="chip ${c.ok ? "chip-ok" : "chip-err"}">${c.ok ? "OK" : "no data"}</span>
      </div>`).join("")}
  </div>`;
}

/* ── Dashboard ─────────────────────────────────────────────── */
function renderTimeline() {
  const rows = state.timeline || [];
  if (!rows.length) return emptyState("No timeline data yet.");
  const max = Math.max(...rows.map((r) => Number(r.count) || 0), 1);
  return `<div class="timeline">${rows.slice(-24).map((r) => `
    <div class="timeline-col" title="${esc(r.timestamp)}: ${esc(r.count)}">
      <span style="height:${Math.max(3, (Number(r.count) || 0) / max * 100)}%"></span>
    </div>`).join("")}</div>`;
}

function renderHighValueFeed() {
  const events = (state.events || []).map(normalizeEvent);
  const highlights = events.filter((e) => {
    const sev = String(e.severity || "").toLowerCase();
    return sev === "critical" || sev === "error";
  }).slice(0, 6);
  const rows = highlights.length ? highlights : events.slice(0, 5);
  if (!rows.length) return emptyState("No events loaded yet. Stream events will appear here.");
  return `<table>
    <thead><tr>
      <th>Time</th><th>Severity</th><th>Source</th><th>Category</th><th>Decision</th><th>Message</th>
    </tr></thead>
    <tbody>${rows.map((e) => `
      <tr class="row-${esc(String(e.severity || "").toLowerCase())}">
        <td class="mono" style="white-space:nowrap;font-size:11px">${esc(e.received_display)}</td>
        <td>${badge(e.severity)}</td>
        <td>${esc(e.source_type)}<br><small class="muted">${esc(e.component)}</small></td>
        <td>${esc(e.event_category)}</td>
        <td>${decisionBadge(e.collector_decision)}</td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message)}</td>
      </tr>`).join("")}
    </tbody>
  </table>`;
}

function renderDashboard() {
  const ss = state.statsSummary || {};
  const st = state.stats || {};
  const q = state.queue || {};
  const fwd = state.forwarding || {};
  const fwdSt = state.forwardingStatus || {};
  const totalEvents = ss.total_events || st.total_events || st.total_received || 0;
  const eps = st.event_rate_per_second;
  const fwdEnabled = fwd.splunk_enabled || fwd.syslog_forward_enabled;

  document.getElementById("tab-dashboard").innerHTML = `
    ${errorBlock("core")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>DMZ Collector Overview</h2>
        <p>Security telemetry ingestion, normalization, and forwarding status</p>
      </div>
      <div class="page-header-right">
        <span class="chip ${fwdEnabled ? "chip-cyan" : "chip-dim"}">
          <span class="dot"></span>${fwdEnabled ? "Forwarding active" : "Forwarding off"}
        </span>
      </div>
    </div>

    <div class="section-head"><h3>Event Processing</h3></div>
    <div class="grid">
      ${statCard("Total Events", safe(totalEvents, 0), eps !== undefined ? `${eps} ev/s` : "", "red")}
      ${statCard("Forwarded", safe(q.forwarded || fwdSt.forwarded, 0), fwd.splunk_hec_url ? "to SIEM" : "–", "cyan")}
      ${statCard("Queued", safe(q.queued, 0), q.paused ? "forwarding paused" : "active", "")}
      ${statCard("Failed", safe(q.failed || fwdSt.failed, 0), q.last_failure ? fmtTime(q.last_failure) : "–", q.failed ? "warn" : "")}
      ${statCard("Critical", safe(ss.critical_count, 0), "events", "red")}
      ${statCard("Warning", safe(ss.warning_count, 0), "events", "warn")}
      ${statCard("Sources", safe(ss.source_count || st.source_count, 0), "registered", "info")}
      ${statCard("Spool File", q.spool_file || fwd.spool_file || "–", q.queued ? `${q.queued} pending` : "empty", "purple")}
    </div>

    <div class="dashboard-grid">
      <article class="card"><h3>Severity Distribution</h3>${objectEntriesBars(st.by_severity)}</article>
      <article class="card"><h3>Event Categories</h3>${objectEntriesBars(st.by_category)}</article>
      <article class="card"><h3>Source Types</h3>${objectEntriesBars(st.by_source_type)}</article>
      <article class="card"><h3>Event Timeline (24h)</h3>${renderTimeline()}</article>
    </div>

    <div class="section-head" style="margin-top:20px"><h3>DMZ Pipeline</h3></div>
    <article class="card">
      ${miniPipeline([
        { label: "OT Collector", cls: "n-ot" },
        { label: "OPC UA Gateway", cls: "n-ot" },
        { label: "GDS / PKI", cls: "n-ot" },
        { label: "Firewall / Syslog", cls: "n-ot" },
        { label: "DMZ Collector", cls: "n-dmz" },
        { label: "Local Store", cls: "n-store" },
        { label: "Splunk SIEM", cls: "n-siem" },
      ])}
      <p class="dim" style="font-size:11px;margin-top:8px">
        Forwarding must never block local collection or event storage.
      </p>
    </article>

    <div class="section-head" style="margin-top:20px"><h3>Recent High-Value Events</h3></div>
    ${renderHighValueFeed()}
  `;
}

/* ── Events ────────────────────────────────────────────────── */
function eventQueryParams() {
  const qs = new URLSearchParams({ limit: "300" });
  for (const key of ["source_type", "severity", "category", "asset", "search"]) {
    const v = state.eventFilters[key];
    if (v) qs.set(key, v);
  }
  return qs;
}

function filteredEvents() {
  let rows = (state.events || []).map(normalizeEvent);
  const decision = state.eventFilters.decision.toLowerCase();
  if (decision) {
    rows = rows.filter((e) => String(e.collector_decision || "").toLowerCase().includes(decision));
  }
  const { field, dir } = state.eventSort;
  rows.sort((a, b) => {
    const av = String(a[field] || a.tags?.[field] || "");
    const bv = String(b[field] || b.tags?.[field] || "");
    return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  return rows;
}

function sortHeader(label, field) {
  const active = state.eventSort.field === field;
  const marker = active ? (state.eventSort.dir === "asc" ? " &#8593;" : " &#8595;") : "";
  return `<button class="table-sort${active ? " active" : ""}" data-sort="${esc(field)}">${esc(label)}${marker}</button>`;
}

function renderEvents() {
  const allRows = filteredEvents();
  const pageSize = 50;
  const totalPages = Math.max(1, Math.ceil(allRows.length / pageSize));
  if (state.eventPage > totalPages) state.eventPage = totalPages;
  const start = (state.eventPage - 1) * pageSize;
  const rows = allRows.slice(start, start + pageSize);
  const f = state.eventFilters;
  const critCount = allRows.filter((e) => String(e.severity || "").toLowerCase() === "critical").length;

  document.getElementById("tab-events").innerHTML = `
    ${errorBlock("events")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>Event Console</h2>
        <p>Live SOC event feed — ${allRows.length} visible, ${critCount > 0 ? `${critCount} critical` : "no critical"}</p>
      </div>
    </div>

    <div class="toolbar">
      <label>Source Type<input id="flt-source" placeholder="e.g. firewall" value="${esc(f.source_type)}" style="width:140px" /></label>
      <label>Severity
        <select id="flt-severity" style="width:120px">
          <option value="">Any</option>
          ${["info", "warning", "error", "critical"].map((s) =>
            `<option value="${s}" ${f.severity === s ? "selected" : ""}>${s}</option>`).join("")}
        </select>
      </label>
      <label>Category<input id="flt-category" placeholder="category" value="${esc(f.category)}" style="width:130px" /></label>
      <label>Asset<input id="flt-asset" placeholder="IP or name" value="${esc(f.asset)}" style="width:130px" /></label>
      <label>Decision<input id="flt-decision" placeholder="forward / drop…" value="${esc(f.decision)}" style="width:130px" /></label>
      <label>Search<input id="flt-search" placeholder="message / raw / tags" value="${esc(f.search)}" style="width:180px" /></label>
      <button id="flt-apply" class="primary">Apply</button>
      <button id="flt-clear" class="secondary">Clear</button>
      <button id="events-refresh">&#8635; Refresh</button>
    </div>

    <div class="stream-panel">
      <span class="chip ${state.stream.connected ? "chip-ok" : "chip-warn"}">
        <span class="dot"></span>stream ${state.stream.connected ? "connected" : "offline"}
      </span>
      <span class="chip ${state.stream.paused ? "chip-warn" : "chip-dim"}">
        ${state.stream.paused ? "&#9646;&#9646; paused" : "&#9654; live"}
      </span>
      <span class="muted" style="font-size:11px">last: ${esc(state.stream.lastEventAt || "–")}</span>
      <button id="stream-toggle" class="btn-sm">${state.stream.paused ? "Resume" : "Pause"}</button>
      <button id="stream-reconnect" class="btn-sm secondary">Reconnect</button>
    </div>

    <div class="table-meta">
      <span>${allRows.length} matching &middot; page ${state.eventPage} of ${totalPages}</span>
    </div>

    ${rows.length ? `
      <table>
        <thead><tr>
          <th>${sortHeader("Time", "received_at")}</th>
          <th>${sortHeader("Source", "source_type")}</th>
          <th>${sortHeader("Severity", "severity")}</th>
          <th>${sortHeader("Category", "event_category")}</th>
          <th>Asset / IP</th>
          <th>Decision</th>
          <th>Routing</th>
          <th>Message</th>
          <th></th>
        </tr></thead>
        <tbody>
          ${rows.map((e) => {
            const sev = String(e.severity || "").toLowerCase();
            return `
            <tr class="row-${esc(sev)}">
              <td class="mono" style="font-size:11px;white-space:nowrap">${esc(e.received_display)}</td>
              <td>${esc(e.source_type)}<br><small class="muted mono">${esc(e.component)}</small></td>
              <td>${badge(e.severity)}</td>
              <td>${esc(e.event_category)}</td>
              <td class="mono" style="font-size:11px">${esc(e.asset_name || e.asset_ip || e.source_ip || "–")}</td>
              <td>${decisionBadge(e.collector_decision)}<br><small class="muted mono">${esc(e.matched_rule_id || "")}</small></td>
              <td class="mono" style="font-size:11px">${esc(e.siem_index_hint || "–")}<br>${esc(e.splunk_sourcetype || "–")}</td>
              <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message)}</td>
              <td><button data-id="${esc(e.id)}" class="show-json btn-sm">JSON</button></td>
            </tr>
            <tr class="details-row">
              <td colspan="9">
                <details>
                  <summary class="muted" style="font-size:11px;cursor:pointer">raw / tags</summary>
                  <pre>${esc(JSON.stringify({ raw: e.raw_object, tags: e.tags }, null, 2))}</pre>
                </details>
              </td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>
      <div class="pager">
        <button id="page-prev" ${state.eventPage <= 1 ? "disabled" : ""}>&#8592; Prev</button>
        <span class="muted" style="font-size:12px">${state.eventPage} / ${totalPages}</span>
        <button id="page-next" ${state.eventPage >= totalPages ? "disabled" : ""}>Next &#8594;</button>
      </div>
    ` : emptyState("No events match the current filters.")}
  `;
  bindEventsTab(allRows);
}

function bindEventsTab(allRows) {
  document.getElementById("flt-apply").addEventListener("click", () => {
    state.eventFilters = {
      source_type: document.getElementById("flt-source").value.trim(),
      severity: document.getElementById("flt-severity").value.trim(),
      category: document.getElementById("flt-category").value.trim(),
      asset: document.getElementById("flt-asset").value.trim(),
      decision: document.getElementById("flt-decision").value.trim(),
      search: document.getElementById("flt-search").value.trim(),
    };
    state.eventPage = 1;
    loadEvents();
  });
  document.getElementById("flt-clear").addEventListener("click", () => {
    state.eventFilters = { source_type: "", severity: "", category: "", asset: "", decision: "", search: "" };
    state.eventPage = 1;
    loadEvents();
  });
  document.getElementById("events-refresh").addEventListener("click", loadEvents);
  document.getElementById("stream-toggle").addEventListener("click", () => {
    state.stream.paused = !state.stream.paused;
    renderEvents();
  });
  document.getElementById("stream-reconnect").addEventListener("click", connectStream);
  document.getElementById("page-prev")?.addEventListener("click", () => {
    state.eventPage = Math.max(1, state.eventPage - 1);
    renderEvents();
  });
  document.getElementById("page-next")?.addEventListener("click", () => {
    state.eventPage += 1;
    renderEvents();
  });
  document.querySelectorAll(".table-sort").forEach((btn) => {
    btn.addEventListener("click", () => {
      const field = btn.dataset.sort;
      if (state.eventSort.field === field) state.eventSort.dir = state.eventSort.dir === "asc" ? "desc" : "asc";
      else state.eventSort = { field, dir: "desc" };
      renderEvents();
    });
  });
  document.querySelectorAll(".show-json").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = allRows.find((e) => e.id === btn.dataset.id);
      showJSON(row);
    });
  });
}

function showJSON(row) {
  jsonModalBody.textContent = JSON.stringify(row, null, 2);
  const footer = document.getElementById("json-modal-footer");
  if (footer) {
    const existing = footer.querySelector("#copy-json");
    if (existing) existing.remove();
    const copy = document.createElement("button");
    copy.id = "copy-json";
    copy.className = "primary";
    copy.textContent = "Copy JSON";
    copy.addEventListener("click", async () => {
      await navigator.clipboard?.writeText(jsonModalBody.textContent);
      copy.textContent = "✓ Copied";
      setTimeout(() => { copy.textContent = "Copy JSON"; }, 2000);
    });
    footer.appendChild(copy);
  }
  jsonModal.showModal();
}

/* ── Sources ───────────────────────────────────────────────── */
function sourceGroups() {
  return ["Firewall", "PLCs", "SCADA / FUXA", "OPC UA", "GDS / PKI", "Engineering Workstation", "DMZ Services", "IDS / Future Monitoring", "Unknown / Other"];
}

function sourceVisibilityQuery() {
  const vis = state.sourceVisibility;
  return new URLSearchParams({
    include_internal: vis.includeInternal ? "true" : "false",
    include_disabled: vis.includeDisabled ? "true" : "false",
    include_direct_siem: vis.includeDirectSIEM ? "true" : "false",
  });
}

function matchesSourceFilter(source, filter) {
  const hay = [source.source_key, source.id, source.name, source.asset_name, source.asset_ip, source.source_type, source.zone, source.group, source.impact, source.protocol].join(" ").toLowerCase();
  if (filter.group && source.group !== filter.group) return false;
  if (filter.sourceType && source.source_type !== filter.sourceType) return false;
  if (filter.zone && (source.zone || "") !== filter.zone) return false;
  if (filter.severity && !(source.severity_counts || {})[filter.severity]) return false;
  if (filter.enabled === "true" && !source.enabled) return false;
  if (filter.enabled === "false" && source.enabled) return false;
  if (filter.configured === "configured" && !source.configured) return false;
  if (filter.configured === "discovered" && !source.discovered) return false;
  if (filter.search && !hay.includes(filter.search.toLowerCase())) return false;
  return true;
}

function badgeList(counts, clsPrefix) {
  const p = clsPrefix || "sev";
  const html = Object.entries(counts || {})
    .filter(([, v]) => v)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([k, v]) => `<span class="badge ${esc(p)}-${esc(k)}">${esc(k)}: ${esc(v)}</span>`)
    .join(" ");
  return html || `<span class="muted">none</span>`;
}

function sourceCard(source) {
  const isEnabled = source.enabled;
  const isForward = source.forward_enabled;
  const isConfigured = source.configured;
  return `
    <article class="source-card">
      <div class="source-card-header">
        <div>
          <div style="display:flex;align-items:center;gap:7px">
            <span class="status-dot ${isEnabled ? "ok" : "off"}"></span>
            <span class="source-name">${esc(source.name || source.asset_name || source.id || source.source_key)}</span>
          </div>
          <div class="source-meta">${esc(source.group)} &middot; ${esc(source.zone || "–")} &middot; ${esc(source.protocol || "–")}</div>
        </div>
        <div class="source-badges">
          ${badge(isEnabled ? "enabled" : "disabled", isEnabled ? "sev" : "cat")}
          ${badge(isForward ? "forward" : "no-forward", isForward ? "sev" : "cat")}
          ${badge(isConfigured ? "configured" : "discovered", isConfigured ? "cat" : "cat")}
        </div>
      </div>
      <div class="source-body">
        <div><span class="label">IP</span> <span class="mono">${esc(source.asset_ip || "–")}</span></div>
        <div><span class="label">Type</span> <span>${esc(source.source_type)}</span></div>
        <div><span class="label">Last Seen</span> <span class="mono">${esc(source.last_seen || "–")}</span></div>
        <div><span class="label">Events</span> <strong>${safe(source.event_count, 0)}</strong></div>
        <div><span class="label">Index</span> <span class="mono">${esc(source.siem_index_hint || "–")}</span></div>
        <div><span class="label">Impact</span> <span>${esc(source.impact || "–")}</span></div>
      </div>
      <div class="source-section"><div class="label">Severity</div><div class="badge-row">${badgeList(source.severity_counts)}</div></div>
      <div class="source-section"><div class="label">Categories</div><div class="badge-row">${badgeList(source.category_counts, "cat")}</div></div>
      <div class="source-actions">
        <button class="source-detail btn-sm" data-source-type="${esc(source.source_type)}" data-asset-ip="${esc(source.asset_ip)}">Detail</button>
        <button disabled class="btn-sm" title="Source CRUD is not implemented by the backend.">Edit</button>
      </div>
    </article>
  `;
}

function renderSources() {
  const snapshot = state.sources || {};
  const rows = snapshot.sources || [];
  const filter = state.sourceFilter;
  const vis = state.sourceVisibility;
  const filtered = rows.filter((s) => matchesSourceFilter(s, filter));
  const zones = [...new Set(rows.map((s) => s.zone).filter(Boolean))].sort();
  const sourceTypes = [...new Set(rows.map((s) => s.source_type).filter(Boolean))].sort();
  const severityKeys = [...new Set(rows.flatMap((s) => Object.keys(s.severity_counts || {})))].sort();
  const groups = sourceGroups();
  const enabledCount = rows.filter((s) => s.enabled).length;

  document.getElementById("tab-sources").innerHTML = `
    ${errorBlock("sources")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>Source Registry</h2>
        <p>DMZ asset and telemetry source inventory</p>
      </div>
      <div class="page-header-right">
        <span class="chip chip-dim">&#128336; ${esc(snapshot.generated_at || "–")}</span>
        <div class="notice readonly" style="margin:0">&#128274; Read-only — source CRUD not implemented</div>
      </div>
    </div>

    <div class="source-summary-bar">
      ${statCard("Visible", safe(snapshot.visible_sources, snapshot.total_sources || 0), "sources", "")}
      ${statCard("Enabled", enabledCount, "of visible", "ok")}
      ${statCard("Configured", safe(snapshot.configured_sources_total, snapshot.configured_sources || 0), "registered", "info")}
      ${statCard("Discovered", safe(snapshot.discovered_sources_visible, snapshot.discovered_sources || 0), "auto-detected", "purple")}
      ${statCard("Hidden", safe(snapshot.hidden_sources, 0), "excluded from view", "")}
    </div>

    <div class="toolbar source-toggles">
      <label><input id="src-toggle-internal" type="checkbox" ${vis.includeInternal ? "checked" : ""}> Show internal DMZ services</label>
      <label><input id="src-toggle-disabled" type="checkbox" ${vis.includeDisabled ? "checked" : ""}> Show disabled sources</label>
      <label><input id="src-toggle-direct-siem" type="checkbox" ${vis.includeDirectSIEM ? "checked" : ""}> Show direct-to-SIEM sources</label>
      <button id="src-toggle-apply" class="primary">&#8635; Refresh inventory</button>
    </div>

    <div class="toolbar source-filters">
      <label>Group
        <select id="src-filter-group" style="width:140px">
          <option value="">All groups</option>
          ${groups.map((g) => `<option value="${esc(g)}" ${filter.group === g ? "selected" : ""}>${esc(g)}</option>`).join("")}
        </select>
      </label>
      <label>Source Type
        <select id="src-filter-type" style="width:130px">
          <option value="">All types</option>
          ${sourceTypes.map((t) => `<option value="${esc(t)}" ${filter.sourceType === t ? "selected" : ""}>${esc(t)}</option>`).join("")}
        </select>
      </label>
      <label>Zone
        <select id="src-filter-zone" style="width:100px">
          <option value="">All zones</option>
          ${zones.map((z) => `<option value="${esc(z)}" ${filter.zone === z ? "selected" : ""}>${esc(z)}</option>`).join("")}
        </select>
      </label>
      <label>Severity
        <select id="src-filter-severity" style="width:100px">
          <option value="">Any</option>
          ${severityKeys.map((s) => `<option value="${esc(s)}" ${filter.severity === s ? "selected" : ""}>${esc(s)}</option>`).join("")}
        </select>
      </label>
      <label>Status
        <select id="src-filter-enabled" style="width:120px">
          <option value="">Enabled or disabled</option>
          <option value="true" ${filter.enabled === "true" ? "selected" : ""}>Enabled only</option>
          <option value="false" ${filter.enabled === "false" ? "selected" : ""}>Disabled only</option>
        </select>
      </label>
      <label>Search<input id="src-filter-search" placeholder="IP, name, ID" value="${esc(filter.search)}" style="width:150px" /></label>
      <button id="src-filter-apply" class="primary">Apply</button>
      <button id="src-filter-clear" class="secondary">Clear</button>
    </div>

    ${filtered.length ? `<div class="source-groups">
      ${groups.map((group) => {
        const items = filtered.filter((s) => s.group === group);
        if (!items.length) return "";
        return `<section class="source-group">
          <div class="source-group-head">
            <h3>${esc(group)}</h3>
            <span class="chip chip-info">${items.length} sources</span>
          </div>
          <div class="source-grid">${items.map(sourceCard).join("")}</div>
        </section>`;
      }).join("")}
    </div>` : emptyState("No sources match the current view.")}
  `;
  bindSourcesTab();
}

function bindSourcesTab() {
  document.getElementById("src-toggle-apply").addEventListener("click", async () => {
    state.sourceVisibility = {
      includeInternal: document.getElementById("src-toggle-internal").checked,
      includeDisabled: document.getElementById("src-toggle-disabled").checked,
      includeDirectSIEM: document.getElementById("src-toggle-direct-siem").checked,
    };
    await loadSources();
    renderSources();
  });
  document.getElementById("src-filter-apply").addEventListener("click", () => {
    state.sourceFilter = {
      group: document.getElementById("src-filter-group").value,
      sourceType: document.getElementById("src-filter-type").value,
      zone: document.getElementById("src-filter-zone").value,
      severity: document.getElementById("src-filter-severity").value,
      enabled: document.getElementById("src-filter-enabled").value,
      configured: "",
      search: document.getElementById("src-filter-search").value.trim(),
    };
    renderSources();
  });
  document.getElementById("src-filter-clear").addEventListener("click", () => {
    state.sourceFilter = { group: "", sourceType: "", zone: "", severity: "", enabled: "", configured: "", search: "" };
    renderSources();
  });
  document.querySelectorAll(".source-detail").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const detail = await api(`/sources/detail?source_type=${encodeURIComponent(btn.dataset.sourceType)}&asset_ip=${encodeURIComponent(btn.dataset.assetIp)}&limit=10`);
        showJSON(detail);
      } catch (err) {
        showJSON({ error: err.message });
      }
    });
  });
}

/* ── Queue ─────────────────────────────────────────────────── */
function renderQueue() {
  const q = state.queue || {};
  document.getElementById("tab-queue").innerHTML = `
    ${errorBlock("queue")}${noticeBlock("queue")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>Forwarding Queue</h2>
        <p>Spool management and forwarding worker control</p>
      </div>
      <div class="page-header-right">
        <span class="chip ${q.paused ? "chip-warn" : "chip-ok"}">
          <span class="dot"></span>${q.paused ? "worker paused" : "worker active"}
        </span>
      </div>
    </div>

    <div class="grid">
      ${statCard("Queued", safe(q.queued, 0), q.paused ? "forwarding paused" : "pending dispatch", "")}
      ${statCard("Forwarded", safe(q.forwarded, 0), "total", "cyan")}
      ${statCard("Failed", safe(q.failed, 0), q.last_failure ? fmtTime(q.last_failure) : "–", q.failed ? "warn" : "")}
      ${statCard("Last Success", "–", fmtTime(q.last_success), "ok")}
    </div>

    <div class="section-head" style="margin-top:16px"><h3>Spool</h3></div>
    <article class="card">
      <div class="info-row">
        <span class="info-key">Spool file</span>
        <span class="info-val mono">${esc(q.spool_file || "–")}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Last failure</span>
        <span class="info-val">${esc(fmtTime(q.last_failure) || "–")}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Last success</span>
        <span class="info-val">${esc(fmtTime(q.last_success) || "–")}</span>
      </div>
    </article>

    <div class="toolbar actionbar" style="margin-top:14px">
      <button id="btn-flush" class="primary">&#8679; Flush spool</button>
      <button id="btn-pause">${q.paused ? "Already paused" : "Pause forwarding"}</button>
      <button id="btn-resume">${q.paused ? "Resume forwarding" : "Already active"}</button>
      <button disabled title="Per-item retry is not implemented; use Flush spool to requeue pending records.">Retry failed</button>
    </div>
  `;
  document.getElementById("btn-flush").addEventListener("click", async () => {
    await action("queue", () => api("/forwarding/flush", { method: "POST" }), "Flush requested.");
    await loadCore();
    renderQueue();
  });
  document.getElementById("btn-pause").addEventListener("click", () => setPaused(true));
  document.getElementById("btn-resume").addEventListener("click", () => setPaused(false));
}

async function setPaused(paused) {
  const cfg = await api("/config/forwarding");
  cfg.paused = paused;
  await action("queue", () => api("/config/forwarding", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cfg) }), paused ? "Forwarding paused." : "Forwarding resumed.");
  await loadCore();
  renderQueue();
}

/* ── Forwarding ────────────────────────────────────────────── */
function renderForwarding() {
  const cfg = state.forwarding || {};
  const st = state.forwardingStatus || {};
  const tokenPlaceholder = cfg.splunk_hec_token_set ? "••••••••" : "";
  const splunkOk = cfg.splunk_enabled && cfg.splunk_hec_url;
  const syslogOk = cfg.syslog_forward_enabled && cfg.syslog_forward_host;

  document.getElementById("tab-forwarding").innerHTML = `
    ${errorBlock("forwarding")}${noticeBlock("forwarding")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>SIEM Forwarding</h2>
        <p>Splunk HEC and syslog uplink configuration</p>
      </div>
      <div class="page-header-right">
        <span class="chip ${splunkOk ? "chip-cyan" : "chip-dim"}"><span class="dot"></span>Splunk ${splunkOk ? "on" : "off"}</span>
        <span class="chip ${syslogOk ? "chip-ok" : "chip-dim"}"><span class="dot"></span>Syslog ${syslogOk ? "on" : "off"}</span>
      </div>
    </div>

    <div class="conn-card">
      <div class="conn-card-header">
        ${statusDot(splunkOk)}
        <span class="conn-status-text">${splunkOk ? "Splunk HEC Connected" : "Splunk HEC Not Configured"}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;font-size:13px">
        <div class="info-row"><span class="info-key">URL</span><span class="info-val mono">${esc(cfg.splunk_hec_url || "–")}</span></div>
        <div class="info-row"><span class="info-key">Index</span><span class="info-val mono">${esc(cfg.splunk_index || "–")}</span></div>
        <div class="info-row"><span class="info-key">Source</span><span class="info-val mono">${esc(cfg.splunk_source || "–")}</span></div>
        <div class="info-row"><span class="info-key">Token</span><span class="info-val">${cfg.splunk_hec_token_set ? "&#11044; set" : "not set"}</span></div>
        <div class="info-row"><span class="info-key">TLS Verify</span><span class="info-val">${cfg.splunk_verify_tls ? "yes" : "no"}</span></div>
        <div class="info-row"><span class="info-key">Last response</span><span class="info-val mono">${esc(st.last_response || "–")}</span></div>
      </div>
    </div>

    <div class="section-head"><h3>Splunk HEC Settings</h3></div>
    <article class="card">
      <div class="toolbar">
        <label>Splunk Enabled<input id="splunk-enabled" type="checkbox" ${cfg.splunk_enabled ? "checked" : ""}></label>
        <label>HEC URL<input id="splunk-url" value="${esc(cfg.splunk_hec_url || "")}" style="width:260px"></label>
        <label>HEC Token (leave blank to keep current)<input id="splunk-token" type="password" value="" placeholder="${tokenPlaceholder || "not set"}" style="width:180px"></label>
        <label>Index<input id="splunk-index" value="${esc(cfg.splunk_index || "ot_security")}" style="width:130px"></label>
        <label>Source<input id="splunk-source" value="${esc(cfg.splunk_source || "labshock_dmz_collector")}" style="width:160px"></label>
        <label>Verify TLS<input id="splunk-verify-tls" type="checkbox" ${cfg.splunk_verify_tls ? "checked" : ""}></label>
      </div>
    </article>

    <div class="section-head"><h3>Syslog Forward Settings</h3></div>
    <article class="card">
      <div class="toolbar">
        <label>Syslog Enabled<input id="syslog-enabled" type="checkbox" ${cfg.syslog_forward_enabled ? "checked" : ""}></label>
        <label>Host<input id="syslog-host" value="${esc(cfg.syslog_forward_host || "")}" style="width:180px"></label>
        <label>Port<input id="syslog-port" type="number" min="1" max="65535" value="${esc(cfg.syslog_forward_port || 514)}" style="width:80px"></label>
        <label>Protocol
          <select id="syslog-proto" style="width:80px">
            <option value="udp" ${cfg.syslog_forward_protocol === "udp" ? "selected" : ""}>udp</option>
            <option value="tcp" ${cfg.syslog_forward_protocol === "tcp" ? "selected" : ""}>tcp</option>
          </select>
        </label>
      </div>
    </article>

    <div class="toolbar actionbar" style="margin-top:12px">
      <button id="save-forwarding" class="primary">&#10003; Save configuration</button>
      <button id="test-forwarding">&#9654; Test forwarding</button>
    </div>

    <div class="section-head"><h3>Forwarding Metrics</h3></div>
    <div class="metric-grid">
      ${statCard("Forwarded", safe(st.forwarded, 0), "total", "cyan")}
      ${statCard("Failed", safe(st.failed, 0), "–", st.failed ? "warn" : "")}
      ${statCard("Queued", safe(st.queued, 0), "pending", "")}
      ${statCard("Last Response", safe(st.last_response || "–", "–"), "HTTP status", "")}
    </div>

    <div class="notice info" style="margin-top:16px">
      &#9432; Forwarding must never block local collection or event storage. If the SIEM is unreachable, events queue locally.
    </div>
  `;
  document.getElementById("save-forwarding").addEventListener("click", saveForwarding);
  document.getElementById("test-forwarding").addEventListener("click", async () => {
    await action("forwarding", () => api("/forwarding/test", { method: "POST" }), "Forwarding test succeeded.");
    await loadCore();
    renderForwarding();
  });
}

async function saveForwarding() {
  const next = {
    splunk_enabled: document.getElementById("splunk-enabled").checked,
    splunk_hec_url: document.getElementById("splunk-url").value.trim(),
    splunk_hec_token: document.getElementById("splunk-token").value.trim(),
    splunk_index: document.getElementById("splunk-index").value.trim() || "ot_security",
    splunk_source: document.getElementById("splunk-source").value.trim() || "labshock_dmz_collector",
    splunk_verify_tls: document.getElementById("splunk-verify-tls").checked,
    syslog_forward_enabled: document.getElementById("syslog-enabled").checked,
    syslog_forward_host: document.getElementById("syslog-host").value.trim(),
    syslog_forward_port: Number(document.getElementById("syslog-port").value || 514),
    syslog_forward_protocol: document.getElementById("syslog-proto").value,
    paused: Boolean(state.queue?.paused),
  };
  await action("forwarding", () => api("/config/forwarding", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(next) }), "Forwarding configuration saved.");
  await loadCore();
  renderForwarding();
}

/* ── Rules ─────────────────────────────────────────────────── */
function renderRules() {
  const rules = Array.isArray(state.rules) ? state.rules : (state.rules?.rules || []);
  const filters = state.filterConfig?.filters || [];
  const enabledRules = rules.filter((r) => r.enabled !== false).length;
  const byAction = {};
  rules.forEach((r) => {
    const a = String(r.action || "unknown").toLowerCase();
    byAction[a] = (byAction[a] || 0) + 1;
  });

  const ruleKeys = rules.length ? Object.keys(rules[0]) : [];

  function renderRuleCell(r, k) {
    const v = r[k];
    if (k === "action") return `<td>${decisionBadge(v)}</td>`;
    if (k === "enabled") return `<td>${badge(v !== false ? "enabled" : "disabled", v !== false ? "sev" : "cat")}</td>`;
    if (k === "priority") return `<td><strong>${esc(v)}</strong></td>`;
    if (typeof v === "object" && v !== null) return `<td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(JSON.stringify(v))}</td>`;
    if (v === true || v === false) return `<td class="muted">${v ? "yes" : "no"}</td>`;
    return `<td>${esc(v)}</td>`;
  }

  document.getElementById("tab-rules").innerHTML = `
    ${errorBlock("rules")}
    <div class="page-header">
      <div class="page-header-left">
        <h2>Rule Matrix</h2>
        <p>Collector filter and decision policy</p>
      </div>
      <div class="page-header-right">
        <div class="notice readonly" style="margin:0">&#128274; Read-only — rule CRUD not implemented</div>
      </div>
    </div>

    <div class="grid" style="margin-bottom:16px">
      ${statCard("Total Rules", rules.length, "", "")}
      ${statCard("Enabled", enabledRules, `of ${rules.length}`, "ok")}
      ${statCard("DROP", byAction.drop || 0, "rules", "red")}
      ${statCard("FORWARD", byAction.forward || 0, "rules", "cyan")}
      ${statCard("SAMPLE", byAction.sample || 0, "rules", "warn")}
      ${statCard("STORE", byAction.store || 0, "rules", "purple")}
    </div>

    <div class="toolbar actionbar">
      <button disabled title="No rule-create endpoint is implemented.">+ Add rule</button>
      <button disabled title="No rule update endpoint is implemented.">Edit</button>
      <button disabled title="No rule delete endpoint is implemented.">Delete</button>
    </div>

    <div class="section-head"><h3>Configured Rules</h3></div>
    <article class="card">
      ${rules.length ? `<table>
        <thead><tr>${ruleKeys.map((k) => `<th>${esc(k)}</th>`).join("")}</tr></thead>
        <tbody>${rules.map((r) => `<tr>${ruleKeys.map((k) => renderRuleCell(r, k)).join("")}</tr>`).join("")}</tbody>
      </table>` : emptyState("No configured rules returned by /config/rules.")}
    </article>

    <div class="section-head"><h3>Filter Config</h3></div>
    <article class="card">
      ${filters.length ? `<pre>${esc(JSON.stringify(filters, null, 2))}</pre>` : emptyState("No filter config returned by /filter/config.")}
    </article>
  `;
}

/* ── SIEM / Routing ────────────────────────────────────────── */
function renderSplunk() {
  const st = state.forwardingStatus || {};
  const cfg = state.forwarding || {};
  const q = state.queue || {};

  document.getElementById("tab-splunk").innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <h2>SIEM / Routing Reference</h2>
        <p>Splunk HEC uplink status and query reference</p>
      </div>
    </div>

    <div class="section-head"><h3>HEC Runtime Status</h3></div>
    <div class="grid">
      ${statCard("Forwarded", safe(st.forwarded, 0), "total events sent", "cyan")}
      ${statCard("Failed", safe(st.failed, 0), "forwarding errors", st.failed ? "warn" : "")}
      ${statCard("Queued", safe(q.queued, 0), "pending in spool", "")}
      ${statCard("Last Response", safe(st.last_response || "–", "–"), "HTTP status from SIEM", "")}
    </div>

    <div class="section-head"><h3>Routing Configuration</h3></div>
    <article class="card">
      <div class="info-row"><span class="info-key">HEC URL</span><span class="info-val mono">${esc(cfg.splunk_hec_url || "–")}</span></div>
      <div class="info-row"><span class="info-key">Index</span><span class="info-val mono">${esc(cfg.splunk_index || "–")}</span></div>
      <div class="info-row"><span class="info-key">Source tag</span><span class="info-val mono">${esc(cfg.splunk_source || "–")}</span></div>
      <div class="info-row"><span class="info-key">HEC Token</span><span class="info-val">${cfg.splunk_hec_token_set ? "&#11044; configured (masked)" : "&#9675; not set"}</span></div>
      <div class="info-row"><span class="info-key">TLS Verify</span><span class="info-val">${cfg.splunk_verify_tls ? "yes" : "no"}</span></div>
      <div class="info-row"><span class="info-key">Forwarding enabled</span><span class="info-val">${cfg.splunk_enabled ? "yes" : "no"}</span></div>
      <div class="info-row"><span class="info-key">Syslog forward</span><span class="info-val">${cfg.syslog_forward_enabled ? `${esc(cfg.syslog_forward_host)}:${esc(cfg.syslog_forward_port)} (${esc(cfg.syslog_forward_protocol)})` : "disabled"}</span></div>
    </article>

    <div class="section-head"><h3>Reference SPL Queries</h3></div>
    <article class="card">
      <p class="muted" style="font-size:12px;margin-bottom:10px">Reference queries for the DMZ Collector's default index and sourcetype scheme.</p>
      <pre>index=ot_security zone="DMZ" source_type=*
| stats count by source_type sourcetype severity event_category

index=ot_security severity=critical OR severity=error
| table _time source_type event_category message asset_ip

index=ot_security collector_decision=forward
| timechart span=1h count by source_type</pre>
    </article>

    <div class="section-head"><h3>DMZ → SIEM Pipeline</h3></div>
    <article class="card">
      ${miniPipeline([
        { label: "OT Collector", cls: "n-ot" },
        { label: "DMZ Collector", cls: "n-dmz" },
        { label: "Spool / Queue", cls: "n-store" },
        { label: "Splunk SIEM", cls: "n-siem" },
      ])}
    </article>
  `;
}

/* ── Settings / Diagnostics ────────────────────────────────── */
function renderSettings() {
  const h = state.health || {};
  const st = state.stats || {};
  const ss = state.statsSummary || {};

  document.getElementById("tab-settings").innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <h2>Diagnostics</h2>
        <p>System information, storage, and API health</p>
      </div>
    </div>

    <div class="section-head"><h3>System Information</h3></div>
    <article class="card">
      <div class="info-row"><span class="info-key">Service</span><span class="info-val">${esc(h.service || "dmz_collector")}</span></div>
      <div class="info-row"><span class="info-key">Status</span><span class="info-val">${badge(h.status || "unknown")}</span></div>
      <div class="info-row"><span class="info-key">Zone</span><span class="info-val"><span class="badge zone-dmz">DMZ</span></span></div>
      <div class="info-row"><span class="info-key">API address</span><span class="info-val mono">${esc(h.api_addr || "same-origin")}</span></div>
      <div class="info-row"><span class="info-key">API base override</span><span class="info-val mono">${esc(API_BASE || "(none)")}</span></div>
    </article>

    <div class="section-head"><h3>Storage</h3></div>
    <article class="card">
      <div class="info-row"><span class="info-key">Backend</span><span class="info-val mono">${esc(h.storage_backend || "–")}</span></div>
      <div class="info-row"><span class="info-key">Events file</span><span class="info-val mono">${esc(h.events_file || "–")}</span></div>
      <div class="info-row"><span class="info-key">Spool file</span><span class="info-val mono">${esc(h.spool_file || "–")}</span></div>
      <div class="info-row"><span class="info-key">Total events</span><span class="info-val">${safe(st.total_events || ss.total_events, 0)}</span></div>
    </article>

    <div class="section-head"><h3>API Health</h3></div>
    <article class="card">
      <p class="muted" style="font-size:12px;margin-bottom:10px">
        Based on last successful data load. Green = data received. Red = no data or load error.
      </p>
      ${renderApiHealthGrid()}
    </article>

    <div class="section-head"><h3>Operational Notes</h3></div>
    <article class="card">
      <ul style="padding-left:18px;font-size:13px;line-height:2;color:var(--text-muted)">
        <li>Events are append-only. Delete and archive are unavailable in this backend.</li>
        <li>Source and rule CRUD are not implemented. The UI shows read-only inventory and rule data.</li>
        <li>Demo data is never used. Empty panels mean the live API returned no data.</li>
        <li>The Splunk HEC token is never returned to the browser. Only <code>splunk_hec_token_set</code> (boolean) is exposed.</li>
        <li>Set <code>window.DMZ_COLLECTOR_API_BASE</code> or localStorage key <code>dmz_api_base</code> only if serving the UI from a different origin than the API.</li>
      </ul>
    </article>
  `;
}

/* ── Action helper ─────────────────────────────────────────── */
async function action(key, fn, success) {
  try {
    setError(key, null);
    state.notices[key] = "";
    const result = await fn();
    state.notices[key] = success || "Action completed.";
    return result;
  } catch (err) {
    setError(key, err);
    renderActiveTab();
    throw err;
  }
}

/* ── Data loaders (API contract unchanged) ─────────────────── */
async function loadEvents() {
  try {
    state.events = await api(`/events?${eventQueryParams().toString()}`);
    setError("events", null);
  } catch (err) {
    setError("events", err);
  }
  renderEvents();
}

async function loadSources() {
  try {
    const qs = sourceVisibilityQuery().toString();
    const [sources, sourcesSummary] = await Promise.all([api(`/sources?${qs}`), api(`/sources/summary?${qs}`)]);
    state.sources = sources;
    state.sourcesSummary = sourcesSummary;
    setError("sources", null);
  } catch (err) {
    setError("sources", err);
  }
}

async function loadRules() {
  try {
    const [rules, filterConfig] = await Promise.all([api("/config/rules"), api("/filter/config")]);
    state.rules = rules;
    state.filterConfig = filterConfig;
    setError("rules", null);
  } catch (err) {
    setError("rules", err);
  }
}

async function loadCore() {
  const loaders = {
    health:          () => api("/health"),
    stats:           () => api("/stats"),
    statsSummary:    () => api("/stats/summary"),
    queue:           () => api("/queue/status"),
    forwarding:      () => api("/config/forwarding"),
    forwardingStatus:() => api("/forwarding/status"),
    timeline:        () => api("/stats/timeline"),
  };
  const results = await Promise.allSettled(Object.entries(loaders).map(async ([key, fn]) => [key, await fn()]));
  const failures = [];
  for (const result of results) {
    if (result.status === "fulfilled") {
      const [key, value] = result.value;
      state[key] = value;
    } else {
      failures.push(result.reason?.message || String(result.reason));
    }
  }
  setError("core", failures.length ? new Error(failures.join(" | ")) : null);

  const status = state.health?.status || (failures.length ? "degraded" : "ok");
  const healthEl = document.getElementById("health-pill");
  healthEl.textContent = `● ${status}`;
  healthEl.className = `chip ${status === "ok" ? "chip-ok" : "chip-warn"}`;

  const eps = state.stats?.event_rate_per_second;
  const rateEl = document.getElementById("rate-pill");
  rateEl.textContent = eps !== undefined ? `${eps} ev/s` : `${state.statsSummary?.total_events || 0} total`;
  rateEl.className = "chip chip-dim";

  const fwdEl = document.getElementById("fwd-pill");
  if (fwdEl) {
    const fwdEnabled = state.forwarding?.splunk_enabled || state.forwarding?.syslog_forward_enabled;
    fwdEl.textContent = `→ ${fwdEnabled ? "fwd on" : "fwd off"}`;
    fwdEl.className = `chip ${fwdEnabled ? "chip-cyan" : "chip-dim"}`;
  }
}

async function refresh({ includeEvents = false } = {}) {
  await Promise.all([loadCore(), loadSources(), loadRules()]);
  if (includeEvents) await loadEvents();
  renderActiveTab();
}

function renderAll() {
  renderDashboard();
  renderEvents();
  renderSources();
  renderQueue();
  renderForwarding();
  renderRules();
  renderSplunk();
  renderSettings();
}

function renderActiveTab() {
  switch (state.activeTab) {
    case "dashboard":  renderDashboard();  break;
    case "events":     renderEvents();     break;
    case "sources":    renderSources();    break;
    case "queue":      renderQueue();      break;
    case "forwarding": renderForwarding(); break;
    case "rules":      renderRules();      break;
    case "splunk":     renderSplunk();     break;
    case "settings":   renderSettings();   break;
    default:           renderDashboard();
  }
}

/* ── SSE stream (unchanged) ────────────────────────────────── */
function connectStream() {
  if (!window.EventSource) {
    state.stream.connected = false;
    setError("events", new Error("This browser does not support EventSource."));
    renderEvents();
    return;
  }
  if (state.stream.source) state.stream.source.close();
  const source = new EventSource(`${API_BASE}/events/stream`);
  state.stream.source = source;
  source.addEventListener("ready", () => {
    state.stream.connected = true;
    renderEvents();
  });
  source.addEventListener("event", (msg) => {
    state.stream.connected = true;
    if (state.stream.paused) return;
    try {
      const ev = JSON.parse(msg.data);
      if (!state.events.some((existing) => existing.id === ev.id)) {
        state.events = [ev, ...state.events].slice(0, MAX_LIVE_EVENTS);
      }
      state.stream.lastEventAt = new Date().toISOString();
      if (state.activeTab === "events") renderEvents();
      else if (state.activeTab === "dashboard") renderDashboard();
    } catch (err) {
      setError("events", err);
    }
  });
  source.onerror = () => {
    state.stream.connected = false;
    if (state.activeTab === "events") renderEvents();
  };
}

/* ── Init ──────────────────────────────────────────────────── */
async function init() {
  initTheme();
  renderAll();
  await refresh({ includeEvents: true });
  connectStream();
  setInterval(() => refresh({ includeEvents: false }), 5000);
}

init();
