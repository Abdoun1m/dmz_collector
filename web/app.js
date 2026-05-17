const state = {
  events: [],
  stats: {},
  statsSummary: {},
  queue: {},
  forwarding: {},
  forwardingStatus: {},
  sources: {},
  sourcesSummary: {},
  timeline: [],
  sourceVisibility: {
    includeInternal: false,
    includeDisabled: false,
    includeDirectSIEM: false,
  },
};

const tabs = document.querySelectorAll(".tabs button");
tabs.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabs.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

const jsonModal = document.getElementById("json-modal");
const jsonModalBody = document.getElementById("json-modal-body");
document.getElementById("json-modal-close").addEventListener("click", () => jsonModal.close());

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

function safe(v, d = "-") {
  if (v === undefined || v === null || v === "") return d;
  return v;
}

function esc(v) {
  return String(safe(v, "")).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function sourceGroups() {
  return [
    "Firewall",
    "PLCs",
    "SCADA / FUXA",
    "OPC UA",
    "GDS / PKI",
    "Engineering Workstation",
    "DMZ Services",
    "IDS / Future Monitoring",
    "Unknown / Other",
  ];
}

function sourceVisibilityState() {
  return state.sourceVisibility || {
    includeInternal: false,
    includeDisabled: false,
    includeDirectSIEM: false,
  };
}

function sourceVisibilityQuery() {
  const vis = sourceVisibilityState();
  return new URLSearchParams({
    include_internal: vis.includeInternal ? "true" : "false",
    include_disabled: vis.includeDisabled ? "true" : "false",
    include_direct_siem: vis.includeDirectSIEM ? "true" : "false",
  });
}

function sourceFilterState() {
  return {
    group: document.getElementById("src-filter-group")?.value || "",
    sourceType: document.getElementById("src-filter-type")?.value || "",
    zone: document.getElementById("src-filter-zone")?.value || "",
    severity: document.getElementById("src-filter-severity")?.value || "",
    enabled: document.getElementById("src-filter-enabled")?.value || "",
    configured: document.getElementById("src-filter-configured")?.value || "",
    search: document.getElementById("src-filter-search")?.value || "",
  };
}

function matchesSourceFilter(source, filter) {
  const hay = [
    source.source_key,
    source.id,
    source.name,
    source.asset_name,
    source.asset_ip,
    source.source_type,
    source.zone,
    source.group,
    source.impact,
    source.protocol,
  ].join(" ").toLowerCase();
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
  return Object.entries(counts)
    .filter(([, v]) => v)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<span class="badge ${clsPrefix}-${k}">${esc(k)}: ${v}</span>`)
    .join(" ");
}

function topMessagesList(messages = []) {
  if (!messages.length) return `<span class="muted">none</span>`;
  return messages.slice(0, 3).map((m) => `<li>${esc(m.message)} <span class="muted">(${m.count})</span></li>`).join("");
}

function sourceCard(source) {
  return `
    <article class="source-card">
      <div class="source-card-header">
        <div>
          <div class="source-name">${esc(source.name || source.asset_name || source.id || source.source_key)}</div>
          <div class="source-meta">${esc(source.group)} · ${esc(source.zone || "-")} · ${esc(source.impact || "-")} · ${esc(source.protocol || "-")}</div>
        </div>
        <div class="source-badges">
          <span class="badge ${source.enabled ? "sev-info" : "sev-warning"}">${source.enabled ? "enabled" : "disabled"}</span>
          <span class="badge ${source.forward_enabled ? "sev-info" : "sev-warning"}">${source.forward_enabled ? "forward" : "no-forward"}</span>
          <span class="badge ${source.configured ? "sev-info" : "sev-warning"}">${source.configured ? "configured" : "discovered"}</span>
        </div>
      </div>
      <div class="source-body">
        <div><span class="label">IP</span> ${esc(source.asset_ip)}</div>
        <div><span class="label">Type</span> ${esc(source.source_type)}</div>
        <div><span class="label">ID</span> ${esc(source.id)}</div>
        <div><span class="label">Last Seen</span> ${esc(source.last_seen)}</div>
        <div><span class="label">Event Count</span> ${safe(source.event_count, 0)}</div>
        <div><span class="label">SIEM Hint</span> ${esc(source.siem_index_hint)}</div>
        <div><span class="label">Splunk Sourcetype</span> ${esc(source.splunk_sourcetype)}</div>
      </div>
      <div class="source-section">
        <div class="label">Severity</div>
        <div class="badge-row">${badgeList(source.severity_counts)}</div>
      </div>
      <div class="source-section">
        <div class="label">Categories</div>
        <div class="badge-row">${badgeList(source.category_counts, "cat")}</div>
      </div>
      <div class="source-section">
        <div class="label">Top Messages</div>
        <ul class="top-messages">${topMessagesList(source.top_messages)}</ul>
      </div>
      <div class="source-actions">
        <button class="source-detail" data-source-type="${esc(source.source_type)}" data-asset-ip="${esc(source.asset_ip)}">Detail</button>
      </div>
    </article>
  `;
}

function renderDashboard() {
  const ss = state.statsSummary || {};
  const q = state.queue || {};
  const kpis = [
    ["Total Events", ss.total_events || 0],
    ["Sources", ss.source_count || 0],
    ["Queued", q.queued || 0],
    ["Forwarded", q.forwarded || 0],
    ["Failed", q.failed || 0],
    ["Critical", ss.critical_count || 0],
    ["Warning", ss.warning_count || 0],
    ["Latest Event", safe(ss.latest_event_timestamp)],
  ];
  document.getElementById("tab-dashboard").innerHTML = `
    <div class="grid">
      ${kpis.map(([k, v]) => `<article class="card"><div class="label">${k}</div><div class="kpi">${v}</div></article>`).join("")}
    </div>
  `;
}

function renderEvents() {
  const rows = state.events || [];
  document.getElementById("tab-events").innerHTML = `
    <div class="toolbar">
      <input id="flt-source" placeholder="source_type" />
      <input id="flt-severity" placeholder="severity" />
      <input id="flt-category" placeholder="category" />
      <input id="flt-asset" placeholder="asset_ip/name" />
      <input id="flt-search" placeholder="search" />
      <button id="flt-apply" class="primary">Apply</button>
    </div>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Source</th><th>Severity</th><th>Category</th><th>Asset</th><th>Decision</th><th>Routing</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map((e) => `
          <tr>
            <td>${safe(e.received_at)}</td>
            <td>${safe(e.source_type)}</td>
            <td><span class="badge sev-${safe(e.severity, "info")}">${safe(e.severity)}</span></td>
            <td>${safe(e.event_category)}</td>
            <td>${safe(e.asset_name)}<br/><small>${safe(e.asset_ip)}</small></td>
            <td>${safe(e.tags?.collector_decision)}<br/><small>${safe(e.tags?.matched_rule_id)}</small></td>
            <td>${safe(e.tags?.siem_index_hint)}<br/><small>${safe(e.tags?.splunk_sourcetype)}</small></td>
            <td><button data-id="${e.id}" class="show-json">JSON</button></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
  document.querySelectorAll(".show-json").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = rows.find((e) => e.id === btn.dataset.id);
      jsonModalBody.textContent = JSON.stringify(row, null, 2);
      jsonModal.showModal();
    });
  });
  document.getElementById("flt-apply").addEventListener("click", () => {
    loadEvents({
      source_type: document.getElementById("flt-source").value,
      severity: document.getElementById("flt-severity").value,
      category: document.getElementById("flt-category").value,
      asset: document.getElementById("flt-asset").value,
      search: document.getElementById("flt-search").value,
    });
  });
}

function renderSources() {
  const snapshot = state.sources || {};
  const rows = snapshot.sources || [];
  const filter = sourceFilterState();
  const vis = sourceVisibilityState();
  const filtered = rows.filter((s) => matchesSourceFilter(s, filter));
  const zones = [...new Set(rows.map((s) => s.zone).filter(Boolean))].sort();
  const sourceTypes = [...new Set(rows.map((s) => s.source_type).filter(Boolean))].sort();
  const severityKeys = [...new Set(rows.flatMap((s) => Object.keys(s.severity_counts || {})))].sort();
  const groups = sourceGroups();
  document.getElementById("tab-sources").innerHTML = `
    <div class="card source-summary-bar">
      <div><span class="label">Visible</span> ${safe(snapshot.visible_sources, snapshot.total_sources || 0)}</div>
      <div><span class="label">Hidden</span> ${safe(snapshot.hidden_sources, 0)}</div>
      <div><span class="label">Configured Total</span> ${safe(snapshot.configured_sources_total, snapshot.configured_sources || 0)}</div>
      <div><span class="label">Discovered Visible</span> ${safe(snapshot.discovered_sources_visible, snapshot.discovered_sources || 0)}</div>
      <div><span class="label">Generated</span> ${esc(snapshot.generated_at)}</div>
      <div><span class="label">OT Source</span> ${esc(snapshot.ot_collector_url)}</div>
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
    </div>
    <div class="source-groups">
      ${groups.map((group) => {
        const items = filtered.filter((s) => s.group === group);
        if (!items.length) return "";
        return `
          <section class="source-group">
            <div class="source-group-head">
              <h3>${esc(group)}</h3>
              <span class="badge sev-info">${items.length} sources</span>
            </div>
            <div class="source-grid">
              ${items.map((s) => sourceCard(s)).join("")}
            </div>
          </section>
        `;
      }).join("")}
    </div>
  `;
  document.getElementById("src-toggle-apply").addEventListener("click", () => {
    state.sourceVisibility = {
      includeInternal: document.getElementById("src-toggle-internal").checked,
      includeDisabled: document.getElementById("src-toggle-disabled").checked,
      includeDirectSIEM: document.getElementById("src-toggle-direct-siem").checked,
    };
    refresh();
  });
  document.getElementById("src-filter-apply").addEventListener("click", () => renderSources());
  document.querySelectorAll(".source-detail").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sourceType = btn.dataset.sourceType;
      const assetIp = btn.dataset.assetIp;
      const detail = await api(`/sources/detail?source_type=${encodeURIComponent(sourceType)}&asset_ip=${encodeURIComponent(assetIp)}&limit=10`);
      jsonModalBody.textContent = JSON.stringify(detail, null, 2);
      jsonModal.showModal();
    });
  });
}

function renderQueue() {
  const q = state.queue || {};
  document.getElementById("tab-queue").innerHTML = `
    <div class="grid">
      <article class="card"><div class="label">Queued</div><div class="kpi">${safe(q.queued, 0)}</div></article>
      <article class="card"><div class="label">Failed</div><div class="kpi">${safe(q.failed, 0)}</div></article>
      <article class="card"><div class="label">Last Success</div><div class="kpi">${safe(q.last_success)}</div></article>
      <article class="card"><div class="label">Last Failure</div><div class="kpi">${safe(q.last_failure)}</div></article>
    </div>
    <div class="toolbar" style="margin-top:10px;">
      <button id="btn-flush" class="primary">Flush</button>
      <button id="btn-pause">Pause</button>
      <button id="btn-resume">Resume</button>
    </div>
  `;
  document.getElementById("btn-flush").addEventListener("click", async () => {
    await api("/forwarding/flush", { method: "POST" });
    await refresh();
  });
  document.getElementById("btn-pause").addEventListener("click", async () => {
    const cfg = await api("/config/forwarding");
    cfg.paused = true;
    await api("/config/forwarding", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cfg) });
    await refresh();
  });
  document.getElementById("btn-resume").addEventListener("click", async () => {
    const cfg = await api("/config/forwarding");
    cfg.paused = false;
    await api("/config/forwarding", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cfg) });
    await refresh();
  });
}

function renderForwarding() {
  const cfg = state.forwarding || {};
  const st = state.forwardingStatus || {};
  const tokenMasked = cfg.splunk_hec_token ? "********" : "";
  document.getElementById("tab-forwarding").innerHTML = `
    <div class="card">
      <div class="toolbar">
        <label>Splunk Enabled<input id="splunk-enabled" type="checkbox" ${cfg.splunk_enabled ? "checked" : ""}></label>
        <label>HEC URL<input id="splunk-url" value="${safe(cfg.splunk_hec_url, "")}"></label>
        <label>HEC Token<input id="splunk-token" value="${tokenMasked}" placeholder="leave masked to keep"></label>
        <label>Index<input id="splunk-index" value="${safe(cfg.splunk_index, "ot_security")}"></label>
        <label>Source<input id="splunk-source" value="${safe(cfg.splunk_source, "labshock_dmz_collector")}"></label>
      </div>
      <div class="toolbar">
        <label>Syslog Enabled<input id="syslog-enabled" type="checkbox" ${cfg.syslog_forward_enabled ? "checked" : ""}></label>
        <label>Host<input id="syslog-host" value="${safe(cfg.syslog_forward_host, "")}"></label>
        <label>Port<input id="syslog-port" value="${safe(cfg.syslog_forward_port, 514)}"></label>
        <label>Protocol
          <select id="syslog-proto">
            <option value="udp" ${cfg.syslog_forward_protocol === "udp" ? "selected" : ""}>udp</option>
            <option value="tcp" ${cfg.syslog_forward_protocol === "tcp" ? "selected" : ""}>tcp</option>
          </select>
        </label>
      </div>
      <div class="toolbar">
        <button id="save-forwarding" class="primary">Save</button>
        <button id="test-forwarding">Test</button>
      </div>
      <small>Last response: ${safe(st.last_response)} | queued: ${safe(st.queued, 0)} | failed: ${safe(st.failed, 0)}</small>
    </div>
  `;
  document.getElementById("save-forwarding").addEventListener("click", saveForwarding);
  document.getElementById("test-forwarding").addEventListener("click", async () => {
    try {
      await api("/forwarding/test", { method: "POST" });
      alert("forwarding test succeeded");
    } catch (e) {
      alert(`forwarding test failed: ${e.message}`);
    }
  });
}

function renderSplunk() {
  const st = state.forwardingStatus || {};
  document.getElementById("tab-splunk").innerHTML = `
    <div class="grid">
      <article class="card">
        <div class="label">Sourcetype Mapping</div>
        <table>
          <tbody>
            <tr><td>plc</td><td>labshock:ot:plc</td></tr>
            <tr><td>scada</td><td>labshock:ot:scada</td></tr>
            <tr><td>opcua</td><td>labshock:ot:opcua</td></tr>
            <tr><td>ews</td><td>labshock:ot:ews</td></tr>
            <tr><td>firewall</td><td>labshock:net:firewall</td></tr>
            <tr><td>ids</td><td>labshock:ids:alert</td></tr>
            <tr><td>unknown</td><td>labshock:ot:unknown</td></tr>
          </tbody>
        </table>
      </article>
      <article class="card">
        <div class="label">Index Mapping</div>
        <table>
          <tbody>
            <tr><td>security / critical / error / ids / firewall</td><td>ot_security</td></tr>
            <tr><td>operator_action / operator_read / operator_write</td><td>ot_operations</td></tr>
            <tr><td>runtime / system / network / communication</td><td>ot_telemetry</td></tr>
          </tbody>
        </table>
      </article>
      <article class="card">
        <div class="label">HEC Runtime</div>
        <p>Last HEC response: <strong>${safe(st.last_response)}</strong></p>
        <p>Failed batches: <strong>${safe(st.failed, 0)}</strong></p>
      </article>
    </div>
  `;
}

function renderSettings() {
  document.getElementById("tab-settings").innerHTML = `
    <div class="card">
      <div><strong>Storage Backend</strong>: jsonl</div>
      <div><strong>Retention</strong>: append-only in v1 (documented limitation)</div>
      <div><strong>Auth</strong>: optional shared bearer token via DMZ_INGEST_TOKEN</div>
      <div><strong>Vault</strong>: config stub enabled for future secret loading</div>
    </div>
  `;
}

async function saveForwarding() {
  const current = await api("/config/forwarding");
  const tokenInput = document.getElementById("splunk-token").value.trim();
  const next = {
    ...current,
    splunk_enabled: document.getElementById("splunk-enabled").checked,
    splunk_hec_url: document.getElementById("splunk-url").value.trim(),
    splunk_hec_token: tokenInput === "********" ? current.splunk_hec_token : tokenInput,
    splunk_index: document.getElementById("splunk-index").value.trim(),
    splunk_source: document.getElementById("splunk-source").value.trim(),
    syslog_forward_enabled: document.getElementById("syslog-enabled").checked,
    syslog_forward_host: document.getElementById("syslog-host").value.trim(),
    syslog_forward_port: Number(document.getElementById("syslog-port").value || 514),
    syslog_forward_protocol: document.getElementById("syslog-proto").value,
  };
  await api("/config/forwarding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(next),
  });
  await refresh();
}

async function loadEvents(filters = {}) {
  const qs = new URLSearchParams({ limit: 300 });
  Object.entries(filters).forEach(([k, v]) => {
    if (v) qs.set(k, v);
  });
  state.events = await api(`/events?${qs.toString()}`);
  renderEvents();
}

async function refresh() {
  const visQuery = sourceVisibilityQuery();
  try {
    const [health, stats, statsSummary, queue, forwarding, forwardingStatus, sources, sourcesSummary, timeline] = await Promise.all([
      api("/health"),
      api("/stats"),
      api("/stats/summary"),
      api("/queue/status"),
      api("/config/forwarding"),
      api("/forwarding/status"),
      api(`/sources?${visQuery.toString()}`),
      api(`/sources/summary?${visQuery.toString()}`),
      api("/stats/timeline"),
    ]);
    state.stats = stats;
    state.statsSummary = statsSummary;
    state.queue = queue;
    state.forwarding = forwarding;
    state.forwardingStatus = forwardingStatus;
    state.sources = sources;
    state.sourcesSummary = sourcesSummary;
    state.timeline = timeline;
    document.getElementById("health-pill").textContent = health.status || "offline";
    document.getElementById("rate-pill").textContent = `${statsSummary.total_events || 0} total`;
  } catch (e) {
    document.getElementById("health-pill").textContent = "offline";
  }
  renderDashboard();
  renderSources();
  renderQueue();
  renderForwarding();
  renderSplunk();
  renderSettings();
}

async function init() {
  await refresh();
  await loadEvents();
  setInterval(refresh, 3000);

  if (window.EventSource) {
    const sse = new EventSource("/events/stream");
    sse.addEventListener("event", () => {
      loadEvents();
      refresh();
    });
  }
}

init();
