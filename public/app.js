const state = {
  view: "dashboard",
  credentials: [],
  recommendations: [],
  notifications: [],
  audit: [],
  analytics: null,
  summary: null,
  selectedId: null,
  filters: {
    search: "",
    environment: "All",
    risk: "All",
    account_type: "All",
  },
};

const riskColors = {
  Low: "#15803d",
  Medium: "#b45309",
  High: "#ea580c",
  Critical: "#b91c1c",
  Production: "#0e7490",
  Staging: "#6d28d9",
  Development: "#15803d",
  Expired: "#b91c1c",
  "0-7 days": "#ea580c",
  "8-15 days": "#b45309",
  "16-30 days": "#0e7490",
  "31+ days": "#15803d",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function queryString() {
  const params = new URLSearchParams();
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value && value !== "All") params.set(key, value);
  });
  if (state.filters.search) params.set("search", state.filters.search);
  return params.toString();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function refreshAll() {
  const qs = queryString();
  const [summary, credentials, recommendations, notifications, audit, analytics] = await Promise.all([
    api(`/api/summary?${qs}`),
    api(`/api/credentials?${qs}`),
    api(`/api/recommendations?${qs}`),
    api("/api/notifications"),
    api("/api/audit"),
    api(`/api/analytics?${qs}`),
  ]);
  state.summary = summary;
  state.credentials = credentials;
  state.recommendations = recommendations;
  state.notifications = notifications;
  state.audit = audit;
  state.analytics = analytics;
  if (!state.selectedId && credentials.length) state.selectedId = credentials[0].id;
  if (!credentials.some((item) => item.id === state.selectedId) && credentials.length) {
    state.selectedId = credentials[0].id;
  }
  render();
}

function selectedCredential() {
  return state.credentials.find((item) => item.id === state.selectedId) || state.credentials[0];
}

function riskPill(risk) {
  return `<span class="pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span>`;
}

function environmentPill(environment) {
  return `<span class="pill env">${escapeHtml(environment)}</span>`;
}

function render() {
  renderMetrics();
  renderBars("#riskBars", Object.entries(state.summary.risk_distribution).map(([label, value]) => ({ label, value })));
  renderExpiryList();
  renderCredentialRows();
  renderExplorerRows();
  renderDetailPanel();
  renderRecommendations();
  renderRotationTarget();
  renderNotifications();
  renderAudit();
  renderAnalytics();
  $("#modelVersion").textContent = state.summary.model_version;
}

function renderMetrics() {
  const metrics = [
    ["Total Accounts", state.summary.total, "monitored metadata records"],
    ["Expiring Soon", state.summary.expiring, "inside seven-day alert window"],
    ["Critical Risk", state.summary.critical, "requires urgent ownership"],
    ["Expired", state.summary.expired, "access outage risk"],
    ["Verified Rotations", state.summary.rotation_success, "successful demo executions"],
  ];
  $("#metricGrid").innerHTML = metrics
    .map(([label, value, hint]) => `
      <article class="metric">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
        <small>${escapeHtml(hint)}</small>
      </article>
    `)
    .join("");
}

function renderBars(selector, rows) {
  const max = Math.max(1, ...rows.map((row) => Number(row.value)));
  $(selector).innerHTML = rows
    .map((row) => {
      const width = Math.max(4, (Number(row.value) / max) * 100);
      const color = riskColors[row.label] || "#0e7490";
      return `
        <div class="bar-row">
          <span class="bar-label">${escapeHtml(row.label)}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${width}%;background:${color}"></span></span>
          <span class="bar-value">${escapeHtml(row.value)}</span>
        </div>
      `;
    })
    .join("");
}

function renderExpiryList() {
  const items = [...state.credentials]
    .sort((a, b) => a.days_to_expiry - b.days_to_expiry)
    .slice(0, 5);
  $("#expiryList").innerHTML = items
    .map((item) => `
      <button class="expiry-item ${item.id === state.selectedId ? "selected" : ""}" data-select="${item.id}">
        <span>
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.owner)}</span>
        </span>
        ${riskPill(item.risk)}
        <span class="${item.days_to_expiry < 0 ? "danger-text" : "muted"}">
          ${escapeHtml(expiryText(item.days_to_expiry))}
        </span>
      </button>
    `)
    .join("");
}

function expiryText(days) {
  if (days < 0) return `${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} overdue`;
  if (days === 0) return "expires today";
  return `${days} days left`;
}

function renderCredentialRows() {
  $("#credentialRows").innerHTML = state.credentials
    .map((item) => credentialTableRow(item, ["name", "environment", "risk", "expiry", "action"]))
    .join("");
}

function renderExplorerRows() {
  $("#explorerRows").innerHTML = state.credentials
    .map((item) => credentialTableRow(item, ["database", "username", "owner", "privilege", "dependencies", "risk", "action"]))
    .join("");
}

function credentialTableRow(item, columns) {
  const cells = {
    name: `
      <td>
        <div class="credential-name">
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.account_type)}</span>
        </div>
      </td>`,
    database: `<td>${escapeHtml(item.database_name)}</td>`,
    username: `<td>${escapeHtml(item.username)}</td>`,
    owner: `<td>${escapeHtml(item.owner)}</td>`,
    privilege: `<td>${escapeHtml(item.privilege_level)}</td>`,
    dependencies: `<td>${escapeHtml(item.dependency_count)}</td>`,
    environment: `<td>${environmentPill(item.environment)}</td>`,
    risk: `<td>${riskPill(item.risk)} <span class="muted">${Math.round(item.risk_probability * 100)}%</span></td>`,
    expiry: `<td class="${item.days_to_expiry < 0 ? "danger-text" : ""}">${escapeHtml(expiryText(item.days_to_expiry))}</td>`,
    action: `<td>${escapeHtml(item.recommendation.action)}</td>`,
  };
  return `<tr data-select="${item.id}" class="${item.id === state.selectedId ? "selected" : ""}">${columns.map((key) => cells[key]).join("")}</tr>`;
}

function renderDetailPanel() {
  const item = selectedCredential();
  if (!item) {
    $("#detailPanel").innerHTML = "<p>No credential selected.</p>";
    return;
  }
  const timelineWidth = Math.max(3, Math.min(100, ((90 - Math.max(0, item.days_to_expiry)) / 90) * 100));
  $("#detailPanel").innerHTML = `
    <p class="eyebrow">Credential details</p>
    <h2>${escapeHtml(item.database_name)}</h2>
    <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.secret_ref)}</p>
    <div class="detail-grid">
      <div class="detail-stat"><span>Risk</span><strong>${riskPill(item.risk)} ${Math.round(item.risk_probability * 100)}%</strong></div>
      <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(expiryText(item.days_to_expiry))}</strong></div>
      <div class="detail-stat"><span>Privilege</span><strong>${escapeHtml(item.privilege_level)}</strong></div>
      <div class="detail-stat"><span>Dependencies</span><strong>${escapeHtml(item.dependency_count)} apps/services</strong></div>
      <div class="detail-stat"><span>Owner</span><strong>${escapeHtml(item.owner)}</strong></div>
      <div class="detail-stat"><span>DBA</span><strong>${escapeHtml(item.dba)}</strong></div>
    </div>
    <div class="timeline" title="Credential age vs expiry cycle"><span style="width:${timelineWidth}%"></span></div>
    <p class="muted">Expiry timeline: ${escapeHtml(item.credential_age)} days old, expires ${escapeHtml(item.expiry_date)}.</p>
    <h3>${escapeHtml(item.recommendation.action)}</h3>
    <p>${escapeHtml(item.recommendation.explanation)}</p>
    <div class="stakeholders">${item.recommendation.stakeholders.map((name) => `<span>${escapeHtml(name)}</span>`).join("")}</div>
    <div class="factor-list">
      ${item.risk_factors
        .map((factor) => `
          <div class="factor">
            <span><strong>${escapeHtml(factor.label)}</strong><br><span class="muted">${escapeHtml(factor.evidence)}</span></span>
            <span class="muted">${Math.round(factor.weight * 100)} pts</span>
          </div>
        `)
        .join("")}
    </div>
  `;
}

function renderRecommendations() {
  $("#recommendationList").innerHTML = state.recommendations
    .map((item) => `
      <article class="recommendation-item">
        <div class="rec-topline">
          <div>
            <p class="eyebrow">${escapeHtml(item.urgency)} urgency</p>
            <h2>${escapeHtml(item.database_name)}</h2>
            <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(expiryText(item.days_to_expiry))}</p>
          </div>
          ${riskPill(item.risk)}
        </div>
        <h3>${escapeHtml(item.action)}</h3>
        <p>${escapeHtml(item.explanation)}</p>
        <div class="stakeholders">${item.stakeholders.map((name) => `<span>${escapeHtml(name)}</span>`).join("")}</div>
        <button class="small-button" data-select="${item.credential_id}" data-view-target="rotation">Inspect Rotation</button>
      </article>
    `)
    .join("");
}

function renderRotationTarget() {
  const item = selectedCredential();
  if (!item) return;
  $("#rotationTarget").innerHTML = `
    <p class="eyebrow">Selected account</p>
    <h2>${escapeHtml(item.database_name)}</h2>
    <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.environment)} - ${escapeHtml(item.account_type)}</p>
    <div class="detail-grid">
      <div class="detail-stat"><span>Risk</span><strong>${escapeHtml(item.risk)} ${Math.round(item.risk_probability * 100)}%</strong></div>
      <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(expiryText(item.days_to_expiry))}</strong></div>
      <div class="detail-stat"><span>Approval</span><strong>${item.recommendation.approval_required ? "Required" : "Not required"}</strong></div>
      <div class="detail-stat"><span>Secret</span><strong>Never displayed</strong></div>
    </div>
    <p>${escapeHtml(item.recommendation.explanation)}</p>
  `;
}

function renderNotifications() {
  $("#notificationList").innerHTML = state.notifications
    .map((item) => `
      <article class="notification-item">
        <div class="notification-topline">
          <div>
            <p class="eyebrow">${escapeHtml(item.channel)}</p>
            <h2>${escapeHtml(item.database_name)}</h2>
            <p class="muted">${escapeHtml(item.username)} - ${escapeHtml(item.created_at)}</p>
          </div>
          <span class="pill ${item.status === "Acknowledged" ? "risk-Low" : item.status === "Resolved" ? "env" : "risk-High"}">${escapeHtml(item.status)}</span>
        </div>
        <p>${escapeHtml(item.message)}</p>
        <p class="muted">Recipients: ${escapeHtml(item.recipients)}</p>
        ${item.status === "Sent" ? `<button class="small-button" data-ack="${item.id}">Acknowledge</button>` : ""}
      </article>
    `)
    .join("");
}

function renderAudit() {
  $("#auditList").innerHTML = state.audit
    .map((item) => `
      <article class="audit-item">
        <div class="audit-topline">
          <strong>${escapeHtml(item.action)}</strong>
          <span class="muted">${escapeHtml(item.created_at)}</span>
        </div>
        <span class="muted">${escapeHtml(item.actor)} - ${escapeHtml(item.entity)} #${escapeHtml(item.entity_id)}</span>
        <p>${escapeHtml(item.details)}</p>
      </article>
    `)
    .join("");
}

function renderAnalytics() {
  if (!state.analytics) return;
  renderBars("#expiryBuckets", state.analytics.expiry_buckets);
  renderBars("#factorBars", state.analytics.top_factors);
}

function setView(view) {
  state.view = view;
  $$(".view").forEach((section) => section.classList.toggle("active", section.id === view));
  $$(".nav-tabs button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
}

function setStepper(index) {
  $$("#rotationStepper .step").forEach((step, stepIndex) => {
    step.classList.toggle("active", stepIndex <= index);
  });
}

async function rotateSelected() {
  const item = selectedCredential();
  if (!item) return;
  const button = $("#rotateButton");
  button.disabled = true;
  const lines = [
    `Approval owner: demo-admin`,
    `Target: ${item.database_name}/${item.username}`,
    `Current risk: ${item.risk} (${Math.round(item.risk_probability * 100)}%)`,
  ];
  $("#rotationOutput").textContent = lines.join("\n");
  for (let i = 0; i < 5; i += 1) {
    setStepper(i);
    const labels = ["approval captured", "strong password generated", "vault secret updated", "database login verified", "audit event committed"];
    $("#rotationOutput").textContent += `\n${i + 1}. ${labels[i]}...`;
    await new Promise((resolve) => setTimeout(resolve, 360));
  }
  try {
    const result = await api("/api/rotate", {
      method: "POST",
      body: JSON.stringify({ credential_id: item.id, approved_by: "demo-admin" }),
    });
    $("#rotationOutput").textContent += `\n\nResult: ${result.status}`;
    $("#rotationOutput").textContent += `\nVerification: ${result.verification_status}`;
    $("#rotationOutput").textContent += `\n${result.details}`;
    showToast(
      result.status === "Completed" ? "Rotation Successful" : "Rotation Failed",
      result.details
    );
    await refreshAll();
  } catch (error) {
    $("#rotationOutput").textContent += `\n\nRotation failed: ${error.message}`;
    showToast("Rotation Error", error.message);
  } finally {
    button.disabled = false;
  }
}

function bindEvents() {
  $$(".nav-tabs button").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  $("#searchInput").addEventListener("input", (event) => {
    state.filters.search = event.target.value;
    debounceRefresh();
  });
  $("#envFilter").addEventListener("change", (event) => {
    state.filters.environment = event.target.value;
    refreshAll();
  });
  $("#riskFilter").addEventListener("change", (event) => {
    state.filters.risk = event.target.value;
    refreshAll();
  });
  $("#typeFilter").addEventListener("change", (event) => {
    state.filters.account_type = event.target.value;
    refreshAll();
  });
  document.body.addEventListener("click", async (event) => {
    const selectTarget = event.target.closest("[data-select]");
    if (selectTarget) {
      state.selectedId = Number(selectTarget.dataset.select);
      render();
      if (selectTarget.dataset.viewTarget) setView(selectTarget.dataset.viewTarget);
    }
    const ackTarget = event.target.closest("[data-ack]");
    if (ackTarget) {
      await api(`/api/notifications/${ackTarget.dataset.ack}/ack`, {
        method: "POST",
        body: JSON.stringify({ actor: "demo-admin" }),
      });
      showToast("Acknowledged", "Notification has been acknowledged and audited.");
      await refreshAll();
    }
  });
  $("#rotateButton").addEventListener("click", rotateSelected);
  $("#resetDemo").addEventListener("click", async () => {
    await api("/api/demo/reset", { method: "POST", body: "{}" });
    state.selectedId = null;
    $("#rotationOutput").textContent = "Demo state reset. Select a credential, then run a controlled rotation.";
    setStepper(-1);
    await refreshAll();
  });
}

let refreshTimer = null;
function debounceRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshAll, 250);
}

function showToast(title, message) {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<h4>${escapeHtml(title)}</h4><p>${escapeHtml(message)}</p>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("hiding");
    toast.addEventListener("animationend", () => toast.remove());
  }, 4000);
}

bindEvents();
setStepper(-1);
refreshAll().catch((error) => {
  document.body.innerHTML = `<main class="workspace"><section class="panel"><h1>SecureRotate could not load</h1><p>${escapeHtml(error.message)}</p></section></main>`;
});

// Auto-polling for live updates every 10 seconds
setInterval(() => {
  if (document.visibilityState === "visible") refreshAll();
}, 10000);
