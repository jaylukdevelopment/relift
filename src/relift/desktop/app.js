/*
  Relift desktop — operator console logic.

  Every action goes through /api with the one-time token the server injected.
  The page never talks to a target and cannot widen a scope: the Python engine
  is the only component that resolves, authorises and runs anything. Findings
  are treated as untrusted text and are rendered with textContent only.
*/
"use strict";

const boot = window.RELIFT_BOOT || {};
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const state = {
  meta: null,
  catalog: [],
  scope: null,
  scopePath: "",
  activeTab: "scan",
  jobId: null,
  jobDone: false,
  jobTimer: null,
  run: null,
  selectedTechnique: "",
};

// -- dom helpers -------------------------------------------------------------
const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function cell(text, cls) {
  return el("td", cls || "", text === undefined || text === null ? "" : text);
}

function emptyNote(text) {
  return el("p", "empty", text);
}

function buildTable(headers, rows, onRow) {
  const table = el("table");
  const thead = el("thead");
  const headRow = el("tr");
  headers.forEach((name) => headRow.appendChild(el("th", "", name)));
  thead.appendChild(headRow);
  table.appendChild(thead);

  const body = el("tbody");
  rows.forEach((cells, index) => {
    const tr = el("tr");
    if (onRow) {
      tr.className = "clickable";
      tr.tabIndex = 0;
      tr.addEventListener("click", () => onRow(index));
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onRow(index);
        }
      });
    }
    cells.forEach((item) => tr.appendChild(item instanceof Node ? item : cell(item)));
    body.appendChild(tr);
  });
  table.appendChild(body);
  return table;
}

function tag(severity) {
  const key = String(severity || "info").toLowerCase();
  return el("span", "tag sev-" + key, key);
}

// -- api ---------------------------------------------------------------------
async function api(path, options) {
  const opts = options || {};
  const headers = { "X-Relift-Token": boot.token || "" };
  let body;
  if (opts.body !== undefined && opts.body !== null) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const response = await fetch(path, { method: opts.method || "GET", headers, body });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (error) {
      data = { error: text.slice(0, 400) };
    }
  }
  if (!response.ok) {
    const message = (data && data.error) || response.statusText || "request failed";
    const failure = new Error(message);
    failure.status = response.status;
    failure.refusal = response.status === 403;
    throw failure;
  }
  return data || {};
}

// -- notices -----------------------------------------------------------------
function notify(message, kind) {
  const banner = $("banner");
  const text = String(message || "");
  $("banner-text").textContent = text;
  banner.className = "banner" + (kind && kind !== "error" ? " " + kind : "");
  banner.hidden = false;
}

function hideNotice() {
  $("banner").hidden = true;
}

function reportError(error) {
  if (error && error.refusal) {
    notify("Scope gate refused this action. Nothing was sent.\n" + error.message, "warn");
    return;
  }
  notify((error && error.message) || String(error));
}

// -- formatting --------------------------------------------------------------
function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (findings || []).forEach((item) => {
    const key = String(item.severity || "info").toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

// -- scope gate --------------------------------------------------------------
function renderGate() {
  const gate = $("gate");
  const text = $("gate-text");
  const scope = state.scope;
  if (!scope) {
    gate.className = "gate";
    text.textContent = "no scope loaded";
    $("scan-scope-state").textContent = "no scope loaded";
    return;
  }
  const days = Number(scope.expires_in_days);
  gate.className = "gate " + (days <= 0 ? "warn" : "ok");
  text.textContent =
    scope.engagement + " · " + days + "d left · ceiling " + (scope.max_risk || "safe");
  $("scan-scope-state").textContent =
    scope.engagement +
    " · " +
    (scope.allow_intrusive ? "intrusive allowed" : "intrusive blocked") +
    " · " +
    scope.allowed_hosts.length +
    " allow entr" +
    (scope.allowed_hosts.length === 1 ? "y" : "ies") +
    " · sha256 " +
    String(scope.sha256 || "").slice(0, 12);
}

function updateRunEnabled() {
  const enabled = Boolean(state.scope);
  $("scan-run").disabled = !enabled;
  $("scan-run-why").textContent = enabled
    ? ""
    : "load a scope to enable a run";
}

// -- panes and tabs ----------------------------------------------------------
function showPane(name) {
  document.querySelectorAll(".pane").forEach((pane) => {
    pane.hidden = pane.dataset.pane !== name;
  });
}

function showTab(name) {
  state.activeTab = name;
  document.querySelectorAll(".tab").forEach((tab) => {
    if (tab.dataset.tab === name) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  showPane(name);

  if (name !== "scan") stopPolling();
  else if (state.jobId && !state.jobDone) startPolling(state.jobId);

  if (name === "runs") loadRuns().catch(reportError);
  if (name === "audit") loadAudit().catch(reportError);
  if (name === "catalogue") renderCatalog();
  if (name === "scope") renderScopePreview();
}

// -- scan --------------------------------------------------------------------
function readScanBody() {
  const body = {
    target: $("scan-target").value.trim(),
    scope: $("scan-scope").value.trim() || state.scopePath,
    profile: $("scan-profile").value,
    timeout: Number($("scan-timeout").value || 6),
    insecure: $("scan-insecure").checked,
    ports: $("scan-ports").value.trim(),
    sqli_url: $("scan-sqli-url").value.trim(),
    sqli_param: $("scan-sqli-param").value.trim(),
  };
  const raw = $("scan-creds").value.trim();
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error("Credential JSON is not valid JSON: " + error.message);
    }
    const entries = Array.isArray(parsed) ? parsed : parsed.credentials;
    if (!Array.isArray(entries)) {
      throw new Error('Credential JSON must be an array or {"credentials": [...]}.');
    }
    body.db_creds = entries;
  }
  return body;
}

function setScanBusy(busy) {
  $("scan-plan").disabled = busy;
  $("scan-run").disabled = busy || !state.scope;
  $("scan-spinner").hidden = !busy;
  $("scan-run-why").textContent = busy
    ? "scan running — the log is live"
    : state.scope
    ? ""
    : "load a scope to enable a run";
}

async function ensureScopeLoaded() {
  const typed = $("scan-scope").value.trim();
  if (!typed) throw new Error("Enter a scope file path first.");
  // The header chip must describe what would actually run, so a path that was
  // typed but not loaded is loaded first (and shown) rather than used silently.
  if (!state.scope || typed !== state.scopePath) await loadScope(typed, true);
  return state.scope;
}

async function doPlan() {
  let body;
  try {
    await ensureScopeLoaded();
    body = readScanBody();
  } catch (error) {
    reportError(error);
    return;
  }
  const output = $("scan-output");
  clear(output);
  output.appendChild(el("p", "hint", "planning…"));
  try {
    const plan = await api("/api/plan", { method: "POST", body });
    clear(output);
    const head = el("div", "pane-head");
    head.appendChild(
      el(
        "p",
        "hint",
        "ceiling " +
          plan.ceiling +
          " · analyst " +
          plan.analyst +
          (plan.note ? " · " + plan.note : "")
      )
    );
    output.appendChild(head);

    const rows = (plan.techniques || []).map((spec, index) => [
      cell(String(index + 1), "num"),
      cell(spec.id, "id"),
      cell(spec.name),
      cell(spec.risk),
      cell(spec.status),
    ]);
    if (!rows.length) {
      output.appendChild(
        emptyNote("Nothing is allowed for this target and profile combination.")
      );
      return;
    }
    output.appendChild(buildTable(["#", "Technique", "Name", "Tier", "Status"], rows));
    output.appendChild(
      el("p", "hint", rows.length + " technique(s) would run. Planning sends nothing.")
    );
  } catch (error) {
    clear(output);
    reportError(error);
  }
}

function logPanel(job) {
  const pre = el("pre", "log");
  const lines = (job.lines || []).slice();
  lines.push("");
  lines.push("status: " + job.status + (job.error ? " — " + job.error : ""));
  pre.textContent = lines.join("\n");
  return pre;
}

async function doScan() {
  let body;
  try {
    await ensureScopeLoaded();
    body = readScanBody();
  } catch (error) {
    reportError(error);
    return;
  }
  if (!state.scope) {
    notify("Load a scope file first: nothing runs without an authorisation.");
    return;
  }
  const output = $("scan-output");
  clear(output);
  setScanBusy(true);
  hideNotice();
  try {
    const started = await api("/api/scan", { method: "POST", body });
    state.jobId = started.job_id;
    state.jobDone = false;
    output.appendChild(el("p", "hint", "job " + state.jobId));
    output.appendChild(el("pre", "log", "waiting for the engine…"));
    startPolling(started.job_id);
  } catch (error) {
    setScanBusy(false);
    reportError(error);
  }
}

function stopPolling() {
  if (state.jobTimer) {
    clearInterval(state.jobTimer);
    state.jobTimer = null;
  }
}

function startPolling(jobId) {
  stopPolling();
  state.jobId = jobId;

  const tick = async () => {
    if (!state.jobId || state.activeTab !== "scan") return;
    try {
      const job = await api("/api/jobs/" + encodeURIComponent(jobId));
      const output = $("scan-output");
      const existing = output.querySelector("pre.log");
      const panel = logPanel(job);
      if (existing) output.replaceChild(panel, existing);
      else output.appendChild(panel);

      if (["done", "error", "refused"].includes(job.status)) {
        state.jobDone = true;
        stopPolling();
        setScanBusy(false);
        if (job.status === "done") {
          const payload =
            job.run && job.run.run_id
              ? job.run
              : await api("/api/runs/" + encodeURIComponent(job.run_id));
          renderRun(payload);
          notify("Run complete: " + payload.run_id, "ok");
        } else if (job.status === "refused") {
          notify("Refused by the scope gate. Nothing was sent.\n" + job.error, "warn");
        } else {
          reportError(new Error(job.error || "scan failed"));
        }
      }
    } catch (error) {
      stopPolling();
      setScanBusy(false);
      reportError(error);
    }
  };

  tick();
  state.jobTimer = setInterval(tick, 700);
}

// -- run view ----------------------------------------------------------------
function renderFindings(findings) {
  const host = $("run-findings");
  clear(host);
  if (!findings.length) {
    host.appendChild(emptyNote("No findings were recorded in this run."));
    return;
  }
  findings.forEach((item) => {
    const article = el("article", "finding");
    article.appendChild(tag(item.severity));

    const body = el("div", "body");
    body.appendChild(el("div", "title", item.title || "(untitled)"));
    const meta = el("div", "meta");
    meta.textContent =
      (item.attack_id || "") +
      " · confidence " +
      (item.confidence || "high") +
      (item.target ? " · " + item.target : "");
    body.appendChild(meta);

    if (item.detail) body.appendChild(el("div", "detail", item.detail));

    const evidence = item.evidence || {};
    const keys = Object.keys(evidence);
    if (keys.length) {
      const details = el("details", "evidence");
      details.appendChild(el("summary", "", "evidence · " + keys.length + " field(s)"));
      details.appendChild(el("pre", "", JSON.stringify(evidence, null, 2)));
      body.appendChild(details);
    }
    article.appendChild(body);
    host.appendChild(article);
  });
}

function renderThreads(chains) {
  const host = $("run-threads");
  const note = $("run-threads-note");
  clear(host);
  if (!chains.length) {
    note.textContent =
      "No multi-stage path completed from these findings. That is a statement about the evidence, not about the target.";
    return;
  }
  note.textContent =
    chains.length +
    " correlated thread(s). Each stage below is backed by a finding from this run.";

  chains.forEach((chain) => {
    const severity = String(chain.severity || "info").toLowerCase();
    const box = el("article", "thread sev-" + severity);

    const head = el("div", "thread-head");
    head.appendChild(tag(severity));
    head.appendChild(el("span", "thread-title", chain.title || chain.id || "thread"));
    box.appendChild(head);

    const stages = el("div", "stages");
    (chain.stages || []).forEach((step, index) => {
      if (index > 0) stages.appendChild(el("span", "arrow", "→"));
      const chip = el("span", "stage" + (index === 0 ? " lead" : ""), step.stage || "?");
      chip.title =
        (step.attack_id || "") + " — " + (step.title || "") + (step.detail ? "\n" + step.detail : "");
      stages.appendChild(chip);
    });
    if (stages.childNodes.length) box.appendChild(stages);

    if (chain.summary) box.appendChild(el("p", "thread-summary", chain.summary));

    if (chain.break_at) {
      const brk = el("p", "break");
      brk.appendChild(el("span", "k", "BREAK THE PATH"));
      brk.appendChild(document.createTextNode(chain.break_at));
      box.appendChild(brk);
    }
    host.appendChild(box);
  });
}

function renderRun(payload) {
  if (!payload || !payload.run_id) {
    notify("This job produced no run record.");
    return;
  }
  state.run = payload;
  const target = payload.target || {};
  $("run-title").textContent = target.raw || payload.run_id;
  $("run-meta").textContent = [
    payload.run_id,
    payload.engagement ? "engagement " + payload.engagement : "",
    payload.profile ? "profile " + payload.profile : "",
    payload.provider ? "analyst " + payload.provider : "",
    payload.started || "",
  ]
    .filter(Boolean)
    .join("  ·  ");

  const counts = severityCounts(payload.findings || []);
  const sevHost = $("run-severities");
  clear(sevHost);
  const total = el("div", "item total");
  total.appendChild(el("span", "n", String((payload.findings || []).length)));
  total.appendChild(el("span", "k", "findings"));
  sevHost.appendChild(total);
  SEVERITIES.forEach((name) => {
    if (!counts[name]) return;
    const item = el("div", "item");
    item.appendChild(el("span", "n", String(counts[name])));
    item.appendChild(tag(name));
    sevHost.appendChild(item);
  });

  renderFindings(payload.findings || []);
  renderThreads(payload.chains || []);

  const narrative = (payload.narrative || "").trim();
  $("run-narrative-wrap").hidden = !narrative;
  $("run-narrative").textContent = narrative;
  clear($("run-report-fallback"));

  showPane("run");
}

async function copyReport() {
  if (!state.run || !state.run.run_id) return;
  try {
    const data = await api(
      "/api/runs/" + encodeURIComponent(state.run.run_id) + "/report?format=md"
    );
    const text = String(data.text || "");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      notify("Markdown report copied to the clipboard.", "ok");
      return;
    }
    throw new Error("clipboard unavailable");
  } catch (error) {
    if (error && (error.status || error.refusal)) {
      reportError(error);
      return;
    }
    // No clipboard: show the report so it can be selected by hand.
    try {
      const data = await api(
        "/api/runs/" + encodeURIComponent(state.run.run_id) + "/report?format=md"
      );
      const host = $("run-report-fallback");
      clear(host);
      const area = el("textarea");
      area.rows = 20;
      area.value = String(data.text || "");
      host.appendChild(el("p", "hint", "Clipboard blocked — select and copy the report below."));
      host.appendChild(area);
      area.focus();
      area.select();
    } catch (nested) {
      reportError(nested);
    }
  }
}

async function regenerateNarrative() {
  if (!state.run || !state.run.run_id) return;
  const button = $("run-narrate");
  button.disabled = true;
  try {
    const data = await api(
      "/api/runs/" + encodeURIComponent(state.run.run_id) + "/narrative",
      { method: "POST" }
    );
    const narrative = String(data.narrative || "").trim();
    state.run.narrative = narrative;
    $("run-narrative-wrap").hidden = !narrative;
    $("run-narrative").textContent = narrative;
    $("run-narrative-wrap").open = true;
    notify("Narrative regenerated with " + String(data.provider || "the analyst") + ".", "ok");
  } catch (error) {
    reportError(error);
  } finally {
    button.disabled = false;
  }
}

// -- catalogue ---------------------------------------------------------------
function renderCatalog() {
  const host = $("cat-table");
  if (!host) return;
  const category = $("cat-category").value;
  const query = $("cat-search").value.trim().toLowerCase();
  const shown = state.catalog.filter((spec) => {
    if (category && spec.category !== category) return false;
    if (!query) return true;
    return (
      (spec.id + " " + spec.name + " " + spec.summary + " " + spec.category)
        .toLowerCase()
        .indexOf(query) !== -1
    );
  });

  $("cat-count").textContent = shown.length + " of " + state.catalog.length + " techniques";
  clear(host);
  if (!shown.length) {
    host.appendChild(emptyNote("No technique matches that filter."));
    renderTechniqueDetail("");
    return;
  }

  const rows = shown.map((spec) => [
    cell(spec.id, "id"),
    cell(spec.name),
    cell(spec.risk),
    cell(spec.status),
    cell((spec.families || []).join(", "), "num"),
  ]);
  host.appendChild(
    buildTable(["ID", "Technique", "Tier", "Status", "Families"], rows, (index) => {
      renderTechniqueDetail(shown[index].id);
    })
  );

  if (state.selectedTechnique && shown.some((s) => s.id === state.selectedTechnique)) {
    renderTechniqueDetail(state.selectedTechnique);
  } else {
    renderTechniqueDetail("");
  }
}

function renderTechniqueDetail(id) {
  const panel = $("cat-detail");
  const spec = state.catalog.find((item) => item.id === id);
  clear(panel);
  if (!spec) {
    panel.hidden = true;
    return;
  }
  state.selectedTechnique = id;
  panel.hidden = false;

  panel.appendChild(el("h2", "", spec.id + " — " + spec.name));
  const list = el("dl");
  const pairs = [
    ["Category", spec.category],
    ["Risk tier", spec.risk],
    ["Status", spec.status],
    ["Families", (spec.families || []).join(", ")],
    ["Produces", (spec.produces || []).join(", ") || "—"],
    ["Requires", (spec.requires || []).join(", ") || "—"],
    ["MITRE", spec.mitre || "—"],
    ["Summary", spec.summary],
    ["Analyst note", spec.ai_hint || "—"],
    ["Notes", spec.notes || "—"],
  ];
  pairs.forEach(([key, value]) => {
    list.appendChild(el("dt", "", key));
    list.appendChild(el("dd", "", value));
  });
  panel.appendChild(list);
}

// -- scope -------------------------------------------------------------------
function scopePairs(scope) {
  return [
    ["Engagement", scope.engagement],
    ["Authorised by", (scope.authorized_by || "") + (scope.organization ? " · " + scope.organization : "")],
    ["Path", scope.path],
    ["Expires", scope.expires + " (" + scope.expires_in_days + "d)"],
    ["Max risk", scope.max_risk],
    ["Intrusive", scope.allow_intrusive ? "allowed" : "blocked"],
    ["Rate limit", scope.rate_limit_rps + " rps"],
    ["Ports", (scope.ports || []).join(", ")],
    ["Allow", (scope.allowed_hosts || []).join("\n")],
    ["Deny", (scope.denied_hosts || []).join("\n") || "—"],
    ["SHA-256", scope.sha256],
  ];
}

function renderScopePreview() {
  const host = $("scope-preview");
  clear(host);
  if (!state.scope) {
    host.appendChild(emptyNote("No scope loaded."));
    return;
  }
  const list = el("dl");
  scopePairs(state.scope).forEach(([key, value]) => {
    list.appendChild(el("dt", "", key));
    list.appendChild(el("dd", "", value));
  });
  host.appendChild(list);
  host.appendChild(
    el(
      "p",
      "hint",
      "Nothing runs outside this allow list. Deny rules win, the file expires, and the hash above is recorded with every run and every audit line."
    )
  );
}

async function loadScope(path, quiet) {
  const wanted = String(path || "").trim();
  if (!wanted) throw new Error("Enter a scope file path first.");
  const scope = await api("/api/scope", { method: "POST", body: { path: wanted } });
  state.scope = scope;
  state.scopePath = scope.path || wanted;
  $("scan-scope").value = state.scopePath;
  $("scope-path").value = state.scopePath;
  renderGate();
  renderScopePreview();
  updateRunEnabled();
  if (!quiet) notify("Scope loaded: " + scope.engagement, "ok");
  return scope;
}

async function createScope(event) {
  if (event) event.preventDefault();
  const split = (value) =>
    String(value || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

  const body = {
    engagement: $("scope-engagement").value.trim(),
    hosts: split($("scope-hosts").value),
    denied: split($("scope-denied").value),
    expires_in_days: Number($("scope-days").value || 30),
    max_risk: $("scope-risk").value,
    authorized_by: $("scope-author").value.trim(),
    organization: $("scope-org").value.trim(),
    path: $("scope-path").value.trim(),
    notes: $("scope-notes").value.trim(),
  };
  try {
    const result = await api("/api/init-scope", { method: "POST", body });
    state.scope = result.scope;
    state.scopePath = result.path;
    $("scan-scope").value = result.path;
    renderGate();
    renderScopePreview();
    updateRunEnabled();
    notify("Scope written to " + result.path, "ok");
  } catch (error) {
    reportError(error);
  }
}

// -- runs --------------------------------------------------------------------
async function loadRuns() {
  const data = await api("/api/runs");
  $("runs-root").textContent = "runs root: " + data.runs_root;
  const host = $("runs-table");
  clear(host);
  const runs = data.runs || [];
  if (!runs.length) {
    host.appendChild(emptyNote("No runs yet. Start one from the Scan tab."));
    return;
  }
  const rows = runs.map((run) => {
    const worst = SEVERITIES.find((name) => (run.severities || {})[name]) || "";
    const sevCell = cell(worst ? "" : "—");
    if (worst) sevCell.appendChild(tag(worst));
    return [
      cell(run.started, "num"),
      cell(run.target, "id"),
      cell(run.engagement || "—"),
      cell(run.profile || "—"),
      cell(String(run.findings), "num"),
      cell(String(run.chains), "num"),
      sevCell,
    ];
  });
  host.appendChild(
    buildTable(["Started", "Target", "Engagement", "Profile", "Findings", "Threads", "Worst"], rows, async (index) => {
      try {
        const payload = await api("/api/runs/" + encodeURIComponent(runs[index].run_id));
        renderRun(payload);
      } catch (error) {
        reportError(error);
      }
    })
  );
}

// -- audit -------------------------------------------------------------------
async function loadAudit() {
  const data = await api("/api/audit");
  $("audit-path").textContent = data.path + " · " + (data.lines || []).length + " line(s)";
  $("audit-log").textContent = (data.lines || []).join("\n") || "audit log is empty";
}

// -- settings ----------------------------------------------------------------
function applyMeta(meta) {
  state.meta = meta;
  $("version").textContent = "v" + (meta.version || "0.2.0");

  const profile = $("scan-profile");
  clear(profile);
  (meta.profiles || []).forEach((item) => {
    const option = el("option", "", item.name + " — " + item.max_risk);
    option.value = item.name;
    if (item.name === meta.default_profile) option.selected = true;
    profile.appendChild(option);
  });

  const category = $("cat-category");
  clear(category);
  const all = el("option", "", "all categories");
  all.value = "";
  category.appendChild(all);
  (meta.categories || []).forEach((name) => {
    const option = el("option", "", name);
    option.value = name;
    category.appendChild(option);
  });

  renderGate();
  renderSettings();
}

function renderSettings() {
  const hosts = { providers: $("settings-providers"), paths: $("settings-paths") };
  if (!hosts.providers) return;
  clear(hosts.providers);
  clear(hosts.paths);
  const meta = state.meta;
  if (!meta) {
    hosts.providers.appendChild(emptyNote("Backend metadata unavailable."));
    return;
  }

  const rows = (meta.providers || []).map((p) => [
    cell(p.id, "id"),
    cell(p.kind),
    cell(p.ready ? "ready" : "not ready"),
    cell(p.endpoint || "—", "num"),
    cell(p.model || "—", "num"),
    cell(p.id === meta.selected_provider ? "selected" : "", "num"),
  ]);
  hosts.providers.appendChild(
    rows.length
      ? buildTable(["ID", "Kind", "Ready", "Endpoint", "Model", ""], rows)
      : emptyNote("No provider matrix returned.")
  );

  const list = el("dl");
  [
    ["Runs", meta.runs_root],
    ["Audit", meta.audit_path],
    ["Working dir", meta.cwd],
    ["Catalogue", meta.counts.total + " techniques · " + meta.counts.implemented + " implemented · " + meta.counts.design_only + " design-only"],
  ].forEach(([key, value]) => {
    list.appendChild(el("dt", "", key));
    list.appendChild(el("dd", "", value));
  });
  hosts.paths.appendChild(list);
}

// -- wiring ------------------------------------------------------------------
function wire() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  });

  $("banner-close").addEventListener("click", hideNotice);
  // Enter in a text input must not navigate away from the app.
  $("scan-form").addEventListener("submit", (event) => event.preventDefault());
  $("scan-plan").addEventListener("click", doPlan);
  $("scan-run").addEventListener("click", doScan);
  $("scope-load").addEventListener("click", () => {
    loadScope($("scan-scope").value).catch(reportError);
  });
  $("scan-scope").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      loadScope($("scan-scope").value).catch(reportError);
    }
  });
  $("run-copy").addEventListener("click", copyReport);
  $("run-narrate").addEventListener("click", regenerateNarrative);
  $("run-close").addEventListener("click", () =>
    showTab(state.activeTab === "scan" ? "scan" : "runs")
  );
  $("scope-form").addEventListener("submit", createScope);
  $("runs-refresh").addEventListener("click", () => loadRuns().catch(reportError));
  $("audit-refresh").addEventListener("click", () => loadAudit().catch(reportError));
  $("cat-category").addEventListener("change", renderCatalog);
  $("cat-search").addEventListener("input", renderCatalog);

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("pane-run").hidden) {
      showTab(state.activeTab === "scan" ? "scan" : "runs");
    }
  });
}

async function init() {
  wire();
  $("version").textContent = "v" + (boot.version || "0.2.0");
  try {
    applyMeta(await api("/api/meta"));
  } catch (error) {
    reportError(error);
  }
  try {
    const catalog = await api("/api/catalog");
    state.catalog = catalog.techniques || [];
  } catch (error) {
    reportError(error);
  }
  renderCatalog();
  renderScopePreview();
  updateRunEnabled();
  showTab("scan");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
