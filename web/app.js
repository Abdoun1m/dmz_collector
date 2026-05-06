const state = {
  events: [],
  summary: {},
  queue: {},
  forwarding: {},
  forwardingStatus: {},
  sources: [],
  timeline: [],
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

function renderDashboard() {
  const s = state.summary || {};
  const q = state.queue || {};
  const kpis = [
    ["Total Received", s.total_received || 0],
    ["Queued", q.queued || 0],
    ["Forwarded", q.forwarded || 0],
    ["Failed", q.failed || 0],
    ["Event Rate", `${s.event_rate_per_second || 0} ev/s`],
    ["Security Events", s.security_events || 0],
    ["Top Source", safe(s.top_source?.name)],
    ["Top Sourcetype", safe(s.top_sourcetype?.name)],
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
  const rows = state.sources || [];
  document.getElementById("tab-sources").innerHTML = `
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>Endpoint</th><th>Enabled</th><th>Last Seen</th><th>Events</th></tr></thead>
      <tbody>
        ${rows.map((s) => `
          <tr>
            <td>${safe(s.name)}</td>
            <td>${safe(s.type)}</td>
            <td>${safe(s.endpoint)}</td>
            <td>${String(!!s.enabled)}</td>
            <td>${safe(s.last_seen)}</td>
            <td>${safe(s.event_seen, 0)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
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
  try {
    const [health, summary, queue, forwarding, forwardingStatus, sources, timeline] = await Promise.all([
      api("/health"),
      api("/stats/summary"),
      api("/queue/status"),
      api("/config/forwarding"),
      api("/forwarding/status"),
      api("/sources"),
      api("/stats/timeline"),
    ]);
    state.summary = summary;
    state.queue = queue;
    state.forwarding = forwarding;
    state.forwardingStatus = forwardingStatus;
    state.sources = sources;
    state.timeline = timeline;
    document.getElementById("health-pill").textContent = health.status || "offline";
    document.getElementById("rate-pill").textContent = `${summary.event_rate_per_second || 0} ev/s`;
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
