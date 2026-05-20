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

async function api(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...opts,
    headers: {
      ...(opts.headers || {}),
    },
  });
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    const msg = typeof body === "string" ? body : body?.error || body?.errors?.join(", ") || res.statusText;
    throw new Error(`${path}: ${res.status} ${msg}`);
  }
  return body ?? {};
}

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
    } catch {
      return { detail: v };
    }
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

function errorBlock(key) {
  if (!state.errors[key]) return "";
  return `<div class="notice error">${esc(state.errors[key])}</div>`;
}

function noticeBlock(key) {
  if (!state.notices[key]) return "";
  return `<div class="notice ok">${esc(state.notices[key])}</div>`;
}

function emptyState(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

function card(label, value, sub = "") {
  return `<article class="card"><div class="label">${esc(label)}</div><div class="kpi">${esc(value)}</div>${sub ? `<small>${esc(sub)}</small>` : ""}</article>`;
}

function badge(value, prefix = "sev") {
  const v = String(safe(value, "unknown")).toLowerCase();
  return `<span class="badge ${prefix}-${esc(v)}">${esc(value)}</span>`;
}

function objectEntriesBars(obj = {}) {
  const entries = Object.entries(obj || {}).sort((a, b) => Number(b[1]) - Number(a[1]));
  if (!entries.length) return emptyState("No data yet.");
  const max = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
  return `<div class="bars">${entries.map(([k, v]) => `
    <div class="bar-row">
      <span>${esc(k)}</span>
      <div class="bar"><span style="width:${Math.max(2, (Number(v) || 0) / max * 100)}%"></span></div>
      <strong>${esc(v)}</strong>
    </div>
  `).join("")}</div>`;
}

function renderDashboard() {
  const ss = state.statsSummary || {};
  const st = state.stats || {};
  const q = state.queue || {};
  const splunkState = ss.splunk_enabled ? "enabled" : "disabled";
  document.getElementById("tab-dashboard").innerHTML = `
    ${errorBlock("core")}
    <div class="grid">
      ${card("Total Events", ss.total_events || st.total_events || st.total_received || 0)}
      ${card("Sources", ss.source_count || st.source_count || 0)}
      ${card("Queued", q.queued || 0, q.paused ? "paused" : "active")}
      ${card("Forwarded", q.forwarded || 0)}
      ${card("Failed", q.failed || 0)}
      ${card("Critical", ss.critical_count || 0)}
      ${card("Warning", ss.warning_count || 0)}
      ${card("Splunk HEC", splunkState, ss.splunk_last_error || ss.splunk_last_success_at || "")}
    </div>
    <div class="dashboard-grid">
      <article class="card"><h3>Severity</h3>${objectEntriesBars(st.by_severity)}</article>
      <article class="card"><h3>Categories</h3>${objectEntriesBars(st.by_category)}</article>
      <article class="card"><h3>Source Types</h3>${objectEntriesBars(st.by_source_type)}</article>
      <article class="card"><h3>Timeline</h3>${renderTimeline()}</article>
    </div>
  `;
}

function renderTimeline() {
  const rows = state.timeline || [];
  if (!rows.length) return emptyState("No timeline buckets yet.");
  const max = Math.max(...rows.map((r) => Number(r.count) || 0), 1);
  return `<div class="timeline">${rows.slice(-24).map((r) => `
    <div class="timeline-col" title="${esc(r.timestamp)}: ${esc(r.count)}">
      <span style="height:${Math.max(4, (Number(r.count) || 0) / max * 100)}%"></span>
    </div>
  `).join("")}</div>`;
}

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
  const marker = active ? (state.eventSort.dir === "asc" ? " up" : " down") : "";
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
  document.getElementById("tab-events").innerHTML = `
    ${errorBlock("events")}
    <div class="toolbar">
      <input id="flt-source" placeholder="source_type" value="${esc(f.source_type)}" />
      <select id="flt-severity">
        <option value="">Any severity</option>
        ${["info", "warning", "error", "critical"].map((s) => `<option value="${s}" ${f.severity === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <input id="flt-category" placeholder="category" value="${esc(f.category)}" />
      <input id="flt-asset" placeholder="asset_ip/name" value="${esc(f.asset)}" />
      <input id="flt-decision" placeholder="decision" value="${esc(f.decision)}" />
      <input id="flt-search" placeholder="search message/raw/tags" value="${esc(f.search)}" />
      <button id="flt-apply" class="primary">Apply</button>
      <button id="flt-clear">Clear</button>
      <button id="events-refresh">Refresh</button>
    </div>
    <div class="stream-panel">
      <span class="pill ${state.stream.connected ? "ok-pill" : "warn-pill"}">stream ${state.stream.connected ? "connected" : "offline"}</span>
      <span class="pill">${state.stream.paused ? "paused" : "live"}</span>
      <span class="muted">last event: ${esc(state.stream.lastEventAt || "-")}</span>
      <button id="stream-toggle">${state.stream.paused ? "Resume stream" : "Pause stream"}</button>
      <button id="stream-reconnect">Reconnect</button>
    </div>
    <div class="table-meta">${allRows.length} matching events, page ${state.eventPage} of ${totalPages}</div>
    ${rows.length ? `
      <table>
        <thead>
          <tr>
            <th>${sortHeader("Time", "received_at")}</th>
            <th>${sortHeader("Source", "source_type")}</th>
            <th>${sortHeader("Severity", "severity")}</th>
            <th>${sortHeader("Category", "event_category")}</th>
            <th>Asset</th><th>Decision</th><th>Routing</th><th>Message</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((e) => `
            <tr>
              <td>${esc(e.received_display)}</td>
              <td>${esc(e.source_type)}<br><small>${esc(e.component)}</small></td>
              <td>${badge(e.severity)}</td>
              <td>${esc(e.event_category)}</td>
              <td>${esc(e.asset_name)}<br><small>${esc(e.asset_ip || e.source_ip)}</small></td>
              <td>${esc(e.collector_decision || "-")}<br><small>${esc(e.matched_rule_id || "-")}</small></td>
              <td>${esc(e.siem_index_hint || "-")}<br><small>${esc(e.splunk_sourcetype || "-")}</small></td>
              <td>${esc(e.message)}</td>
              <td><button data-id="${esc(e.id)}" class="show-json">JSON</button></td>
            </tr>
            <tr class="details-row">
              <td colspan="9">
                <details>
                  <summary>raw/tags preview</summary>
                  <pre>${esc(JSON.stringify({ raw: e.raw_object, tags: e.tags }, null, 2))}</pre>
                </details>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
      <div class="pager">
        <button id="page-prev" ${state.eventPage <= 1 ? "disabled" : ""}>Previous</button>
        <button id="page-next" ${state.eventPage >= totalPages ? "disabled" : ""}>Next</button>
      </div>
    ` : emptyState("No real events match the current filters.")}
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
  const existing = document.getElementById("copy-json");
  if (existing) existing.remove();
  const copy = document.createElement("button");
  copy.id = "copy-json";
  copy.textContent = "Copy JSON";
  copy.addEventListener("click", async () => {
    await navigator.clipboard?.writeText(jsonModalBody.textContent);
    copy.textContent = "Copied";
  });
  jsonModal.appendChild(copy);
  jsonModal.showModal();
}

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

function badgeList(counts = {}, clsPrefix = "sev") {
  const html = Object.entries(counts || {})
    .filter(([, v]) => v)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([k, v]) => `<span class="badge ${clsPrefix}-${esc(k)}">${esc(k)}: ${esc(v)}</span>`)
    .join(" ");
  return html || `<span class="muted">none</span>`;
}

function sourceCard(source) {
  return `
    <article class="source-card">
      <div class="source-card-header">
        <div>
          <div class="source-name">${esc(source.name || source.asset_name || source.id || source.source_key)}</div>
          <div class="source-meta">${esc(source.group)} | ${esc(source.zone || "-")} | ${esc(source.impact || "-")} | ${esc(source.protocol || "-")}</div>
        </div>
        <div class="source-badges">
          ${badge(source.enabled ? "enabled" : "disabled", source.enabled ? "sev" : "cat")}
          ${badge(source.forward_enabled ? "forward" : "no-forward", source.forward_enabled ? "sev" : "cat")}
          ${badge(source.configured ? "configured" : "discovered", source.configured ? "sev" : "cat")}
        </div>
      </div>
      <div class="source-body">
        <div><span class="label">IP</span> ${esc(source.asset_ip)}</div>
        <div><span class="label">Type</span> ${esc(source.source_type)}</div>
        <div><span class="label">Last Seen</span> ${esc(source.last_seen)}</div>
        <div><span class="label">Events</span> ${safe(source.event_count, 0)}</div>
        <div><span class="label">Index</span> ${esc(source.siem_index_hint)}</div>
        <div><span class="label">Sourcetype</span> ${esc(source.splunk_sourcetype)}</div>
      </div>
      <div class="source-section"><div class="label">Severity</div><div class="badge-row">${badgeList(source.severity_counts)}</div></div>
      <div class="source-section"><div class="label">Categories</div><div class="badge-row">${badgeList(source.category_counts, "cat")}</div></div>
      <div class="source-actions">
        <button class="source-detail" data-source-type="${esc(source.source_type)}" data-asset-ip="${esc(source.asset_ip)}">Detail</button>
        <button disabled title="Source CRUD is not implemented by the backend in this version.">Edit</button>
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
  document.getElementById("tab-sources").innerHTML = `
    ${errorBlock("sources")}
    <div class="card source-summary-bar">
      <div><span class="label">Visible</span> ${safe(snapshot.visible_sources, snapshot.total_sources || 0)}</div>
      <div><span class="label">Hidden</span> ${safe(snapshot.hidden_sources, 0)}</div>
      <div><span class="label">Configured</span> ${safe(snapshot.configured_sources_total, snapshot.configured_sources || 0)}</div>
      <div><span class="label">Discovered</span> ${safe(snapshot.discovered_sources_visible, snapshot.discovered_sources || 0)}</div>
      <div><span class="label">Generated</span> ${esc(snapshot.generated_at)}</div>
    </div>
    <div class="toolbar source-toggles">
      <label><input id="src-toggle-internal" type="checkbox" ${vis.includeInternal ? "checked" : ""}> Show internal DMZ services</label>
      <label><input id="src-toggle-disabled" type="checkbox" ${vis.includeDisabled ? "checked" : ""}> Show disabled sources</label>
      <label><input id="src-toggle-direct-siem" type="checkbox" ${vis.includeDirectSIEM ? "checked" : ""}> Show direct-to-SIEM sources</label>
      <button id="src-toggle-apply" class="primary">Refresh inventory</button>
    </div>
    <div class="toolbar source-filters">
      <select id="src-filter-group"><option value="">All groups</option>${groups.map((g) => `<option value="${esc(g)}" ${filter.group === g ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
      <select id="src-filter-type"><option value="">All source types</option>${sourceTypes.map((t) => `<option value="${esc(t)}" ${filter.sourceType === t ? "selected" : ""}>${esc(t)}</option>`).join("")}</select>
      <select id="src-filter-zone"><option value="">All zones</option>${zones.map((z) => `<option value="${esc(z)}" ${filter.zone === z ? "selected" : ""}>${esc(z)}</option>`).join("")}</select>
      <select id="src-filter-severity"><option value="">Any severity</option>${severityKeys.map((s) => `<option value="${esc(s)}" ${filter.severity === s ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <select id="src-filter-enabled"><option value="">Enabled or disabled</option><option value="true" ${filter.enabled === "true" ? "selected" : ""}>Enabled</option><option value="false" ${filter.enabled === "false" ? "selected" : ""}>Disabled</option></select>
      <select id="src-filter-configured"><option value="">Configured or discovered</option><option value="configured" ${filter.configured === "configured" ? "selected" : ""}>Configured</option><option value="discovered" ${filter.configured === "discovered" ? "selected" : ""}>Discovered</option></select>
      <input id="src-filter-search" placeholder="search by IP, name, id" value="${esc(filter.search)}" />
      <button id="src-filter-apply" class="primary">Apply</button>
      <button id="src-filter-clear">Clear</button>
    </div>
    ${filtered.length ? `<div class="source-groups">
      ${groups.map((group) => {
        const items = filtered.filter((s) => s.group === group);
        if (!items.length) return "";
        return `<section class="source-group"><div class="source-group-head"><h3>${esc(group)}</h3><span class="badge sev-info">${items.length} sources</span></div><div class="source-grid">${items.map(sourceCard).join("")}</div></section>`;
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
      configured: document.getElementById("src-filter-configured").value,
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

function renderQueue() {
  const q = state.queue || {};
  document.getElementById("tab-queue").innerHTML = `
    ${errorBlock("queue")}${noticeBlock("queue")}
    <div class="grid">
      ${card("Queued", q.queued || 0, q.paused ? "forwarding paused" : "worker active")}
      ${card("Forwarded", q.forwarded || 0)}
      ${card("Failed", q.failed || 0)}
      ${card("Last Success", fmtTime(q.last_success))}
      ${card("Last Failure", fmtTime(q.last_failure))}
      ${card("Spool File", q.spool_file || "-")}
    </div>
    <div class="toolbar actionbar">
      <button id="btn-flush" class="primary">Flush spool</button>
      <button id="btn-pause">${q.paused ? "Already paused" : "Pause forwarding"}</button>
      <button id="btn-resume">${q.paused ? "Resume forwarding" : "Already active"}</button>
      <button disabled title="Per-item retry is not implemented; use Flush spool to requeue pending records.">Retry failed item</button>
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

function renderForwarding() {
  const cfg = state.forwarding || {};
  const st = state.forwardingStatus || {};
  const tokenPlaceholder = cfg.splunk_hec_token_set ? "********" : "";
  document.getElementById("tab-forwarding").innerHTML = `
    ${errorBlock("forwarding")}${noticeBlock("forwarding")}
    <div class="card">
      <div class="toolbar">
        <label>Splunk Enabled<input id="splunk-enabled" type="checkbox" ${cfg.splunk_enabled ? "checked" : ""}></label>
        <label>HEC URL<input id="splunk-url" value="${esc(cfg.splunk_hec_url || "")}"></label>
        <label>HEC Token<input id="splunk-token" type="password" value="" placeholder="${tokenPlaceholder || "not set"}"></label>
        <label>Index<input id="splunk-index" value="${esc(cfg.splunk_index || "ot_security")}"></label>
        <label>Source<input id="splunk-source" value="${esc(cfg.splunk_source || "labshock_dmz_collector")}"></label>
        <label>Verify TLS<input id="splunk-verify-tls" type="checkbox" ${cfg.splunk_verify_tls ? "checked" : ""}></label>
      </div>
      <div class="toolbar">
        <label>Syslog Enabled<input id="syslog-enabled" type="checkbox" ${cfg.syslog_forward_enabled ? "checked" : ""}></label>
        <label>Host<input id="syslog-host" value="${esc(cfg.syslog_forward_host || "")}"></label>
        <label>Port<input id="syslog-port" type="number" min="1" max="65535" value="${esc(cfg.syslog_forward_port || 514)}"></label>
        <label>Protocol<select id="syslog-proto"><option value="udp" ${cfg.syslog_forward_protocol === "udp" ? "selected" : ""}>udp</option><option value="tcp" ${cfg.syslog_forward_protocol === "tcp" ? "selected" : ""}>tcp</option></select></label>
      </div>
      <div class="toolbar actionbar">
        <button id="save-forwarding" class="primary">Save</button>
        <button id="test-forwarding">Test forwarding</button>
      </div>
      <div class="status-grid">
        <div><span class="label">Queued</span> ${safe(st.queued, 0)}</div>
        <div><span class="label">Forwarded</span> ${safe(st.forwarded, 0)}</div>
        <div><span class="label">Failed</span> ${safe(st.failed, 0)}</div>
        <div><span class="label">Last response</span> ${esc(st.last_response || "-")}</div>
      </div>
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

function renderRules() {
  const rules = Array.isArray(state.rules) ? state.rules : (state.rules.rules || []);
  const filters = state.filterConfig?.filters || [];
  document.getElementById("tab-rules").innerHTML = `
    ${errorBlock("rules")}
    <div class="notice">Rules and filters are read-only in the current backend. Add/edit/delete controls are disabled until CRUD endpoints exist.</div>
    <div class="toolbar actionbar"><button disabled title="No source rule-create endpoint is implemented.">Add rule</button><button disabled title="No rule update endpoint is implemented.">Edit selected</button><button disabled title="No rule delete endpoint is implemented.">Delete selected</button></div>
    <article class="card">
      <h3>Rule Matrix</h3>
      ${rules.length ? `<table><thead><tr>${Object.keys(rules[0]).map((k) => `<th>${esc(k)}</th>`).join("")}</tr></thead><tbody>${rules.map((r) => `<tr>${Object.keys(rules[0]).map((k) => `<td>${esc(typeof r[k] === "object" ? JSON.stringify(r[k]) : r[k])}</td>`).join("")}</tr>`).join("")}</tbody></table>` : emptyState("No configured rules returned by /config/rules.")}
    </article>
    <article class="card"><h3>Filter Config</h3>${filters.length ? `<pre>${esc(JSON.stringify(filters, null, 2))}</pre>` : emptyState("No filter config returned by /filter/config.")}</article>
  `;
}

function renderSplunk() {
  const st = state.forwardingStatus || {};
  document.getElementById("tab-splunk").innerHTML = `
    <div class="grid">
      <article class="card"><h3>Sourcetype Mapping</h3>${objectEntriesBars({
        "labshock:net:firewall": 1,
        "labshock:ot:plc": 1,
        "labshock:ot:scada": 1,
        "labshock:ot:opcua": 1,
        "labshock:ot:ews": 1,
        "labshock:dmz:gds": 1,
        "labshock:dmz:opcua_gateway": 1,
        "labshock:dmz:jumphost": 1,
      })}</article>
      <article class="card"><h3>HEC Runtime</h3><p>Last response: <strong>${esc(st.last_response || "-")}</strong></p><p>Forwarded: <strong>${esc(st.forwarded || 0)}</strong></p><p>Failed: <strong>${esc(st.failed || 0)}</strong></p></article>
      <article class="card"><h3>Splunk Queries</h3><pre>index=ot_security zone="DMZ" source_type=*
| stats count by source_type sourcetype severity event_category</pre></article>
    </div>
  `;
}

function renderSettings() {
  const h = state.health || {};
  document.getElementById("tab-settings").innerHTML = `
    <div class="grid">
      ${card("Service", h.service || "dmz_collector", h.status || "-")}
      ${card("API", h.api_addr || "-", `base ${API_BASE || "same-origin"}`)}
      ${card("Storage", h.storage_backend || "-", h.events_file || "")}
      ${card("Spool", h.spool_file || "-")}
    </div>
    <article class="card">
      <h3>Operational Notes</h3>
      <ul>
        <li>Events are append-only; delete/archive is unavailable in this backend.</li>
        <li>Source and rule CRUD are unavailable; the UI shows read-only inventory and rule data.</li>
        <li>Demo data is not used. Empty panels mean the live API returned no data.</li>
        <li>Set <code>window.DMZ_COLLECTOR_API_BASE</code> or localStorage <code>dmz_api_base</code> only if serving the UI separately from the API.</li>
      </ul>
    </article>
  `;
}

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
    health: () => api("/health"),
    stats: () => api("/stats"),
    statsSummary: () => api("/stats/summary"),
    queue: () => api("/queue/status"),
    forwarding: () => api("/config/forwarding"),
    forwardingStatus: () => api("/forwarding/status"),
    timeline: () => api("/stats/timeline"),
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
  document.getElementById("health-pill").textContent = status;
  document.getElementById("health-pill").className = `pill ${status === "ok" ? "ok-pill" : "warn-pill"}`;
  const eps = state.stats?.event_rate_per_second;
  document.getElementById("rate-pill").textContent = eps !== undefined ? `${eps} ev/s` : `${state.statsSummary?.total_events || 0} total`;
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
    case "dashboard":
      renderDashboard();
      break;
    case "events":
      renderEvents();
      break;
    case "sources":
      renderSources();
      break;
    case "queue":
      renderQueue();
      break;
    case "forwarding":
      renderForwarding();
      break;
    case "rules":
      renderRules();
      break;
    case "splunk":
      renderSplunk();
      break;
    case "settings":
      renderSettings();
      break;
    default:
      renderDashboard();
  }
}

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
      renderEvents();
    } catch (err) {
      setError("events", err);
    }
  });
  source.onerror = () => {
    state.stream.connected = false;
    renderEvents();
  };
}

async function init() {
  renderAll();
  await refresh({ includeEvents: true });
  connectStream();
  setInterval(() => refresh({ includeEvents: false }), 5000);
}

init();
