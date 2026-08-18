const state = {
  view: "dashboard",
  credentials: [],
  notifications: [],
  recommendations: [],
  audit: [],
  analytics: null,
  analyticsPlots: null,
  filters: {
    search: "",
    risk: "All",
  },
  selectedId: null,
  notificationFilter: "All",
};

const riskColors = {
  Low: "#15803d",
  Medium: "#b45309",
  High: "#ea580c",
  Critical: "#b91c1c",
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

let isRefreshing = false;
async function refreshAll() {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    const qs = queryString();
    const [summary, credentials, recommendations, notifications, audit, analytics, analyticsPlotsRaw] = await Promise.all([
      api(`/api/summary?${qs}`),
      api(`/api/credentials?${qs}`),
      api(`/api/recommendations?${qs}`),
      api("/api/notifications"),
      api("/api/audit"),
      api(`/api/analytics?${qs}`),
      api(`/api/analytics/plots`).catch(() => null),
    ]);
    state.summary = summary;
    state.credentials = credentials;
    state.recommendations = recommendations;
    state.notifications = notifications;
    state.audit = audit;
    state.analytics = analytics;
    state.analyticsPlots = typeof analyticsPlotsRaw === 'string' ? JSON.parse(analyticsPlotsRaw) : analyticsPlotsRaw;
    if (!state.selectedId && credentials.length) state.selectedId = credentials[0].id;
    if (!credentials.some((item) => item.id === state.selectedId) && credentials.length) {
      state.selectedId = credentials[0].id;
    }
    render();
  } finally {
    isRefreshing = false;
  }
}

function selectedCredential() {
  return state.credentials.find((item) => item.id === state.selectedId) || state.credentials[0];
}

function riskPill(risk) {
  return `<span class="pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span>`;
}

function render() {
  renderMetrics();
  renderBars("#riskBars", Object.entries(state.summary.risk_distribution).map(([label, value]) => ({ label, value })));
  renderExpiryList();
  renderCredentialRows();
  renderExplorerRows();
  renderDetailPanel();
  renderRecommendations();
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
    .map((item) => credentialTableRow(item, ["name", "risk", "expiry", "action"]))
    .join("");
}

function renderExplorerRows() {
  $("#explorerRows").innerHTML = state.credentials
    .map((item) => credentialTableRow(item, ["database", "username", "owner", "expiry_action"]))
    .join("");
}

function credentialTableRow(item, columns) {
  const cells = {
    name: `
      <td>
        <div class="credential-name">
          <strong>${escapeHtml(item.database_name)}</strong>
          <span class="muted">${escapeHtml(item.username)}</span>
        </div>
      </td>`,
    database: `<td>${escapeHtml(item.database_name)}</td>`,
    username: `<td>${escapeHtml(item.username)}</td>`,
    owner: `<td>${escapeHtml(item.owner)}</td>`,
    risk: `<td>${riskPill(item.risk)} <span class="muted">${Math.round(item.risk_probability * 100)}%</span></td>`,
    expiry: `<td class="${item.days_to_expiry < 0 ? "danger-text" : ""}">${escapeHtml(expiryText(item.days_to_expiry))}</td>`,
    action: `<td>${escapeHtml(item.recommendation.action)}</td>`,
    expiry_action: `<td style="display: flex; align-items: center; justify-content: space-between;">
      <span class="${item.days_to_expiry < 0 ? "danger-text" : ""}">${escapeHtml(expiryText(item.days_to_expiry))}</span>
      <button class="small-button ghost-button" style="padding: 2px 6px;" data-edit-expiry="${item.id}">✏️ Edit</button>
    </td>`,
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
      <div class="detail-stat"><span>Owner</span><strong>${escapeHtml(item.owner)}</strong></div>
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
    .map(function (item) {
      var factors = (item.top_factors || []).slice(0, 5);
      var factorBarsHtml = "";
      if (factors.length) {
        factorBarsHtml = '<div class="factor-bars">';
        for (var i = 0; i < factors.length; i++) {
          var f = factors[i];
          var absWeight = Math.min(Math.abs(f.weight) * 100, 100);
          var cls = f.weight >= 0 ? "positive" : "negative";
          factorBarsHtml += '<div class="factor-bar">' +
            '<span class="factor-label">' + escapeHtml(f.label) + '</span>' +
            '<span class="factor-track"><span class="factor-fill ' + cls + '" style="width:' + absWeight + '%"></span></span>' +
            '<span class="factor-evidence">' + escapeHtml(f.evidence) + '</span>' +
            '</div>';
        }
        factorBarsHtml += '</div>';
      }

      var badgesHtml = '<div class="rec-badges">';
      if (item.approval_required) {
        badgesHtml += '<span class="approval-badge">\u26A0 Approval Required</span>';
      }
      if (item.uses_mfa) {
        badgesHtml += '<span class="mfa-badge mfa-on">\uD83D\uDD12 MFA On</span>';
      } else {
        badgesHtml += '<span class="mfa-badge mfa-off">\u26A0 No MFA</span>';
      }
      badgesHtml += '</div>';

      var stakeholdersHtml = item.stakeholders.map(function(name) {
        return '<span>' + escapeHtml(name) + '</span>';
      }).join("");

      return '<article class="recommendation-item">' +
        '<div class="rec-topline">' +
          '<div>' +
            '<p class="eyebrow">' + escapeHtml(item.urgency) + ' urgency</p>' +
            '<h2>' + escapeHtml(item.database_name) + '</h2>' +
            '<p class="muted">' + escapeHtml(item.username) + ' - ' + escapeHtml(expiryText(item.days_to_expiry)) + '</p>' +
          '</div>' +
          riskPill(item.risk) +
        '</div>' +
        '<h3>' + escapeHtml(item.action) + '</h3>' +
        '<p>' + escapeHtml(item.explanation) + '</p>' +
        factorBarsHtml +
        badgesHtml +
        '<div class="stakeholders">' + stakeholdersHtml + '</div>' +
      '</article>';
    })
    .join("");
}

function renderNotifications() {
  const search = state.filters.search.trim().toLowerCase();

  const filtered = state.notifications.filter(item => {
    const matchesStatus =
      state.notificationFilter === "All" ||
      item.notification_status === state.notificationFilter;

    const matchesSearch =
      !search ||
      String(item.database_name || "").toLowerCase().includes(search) ||
      String(item.username || "").toLowerCase().includes(search) ||
      String(item.owner || "").toLowerCase().includes(search) ||
      String(item.notification_status || "").toLowerCase().includes(search);

    return matchesStatus && matchesSearch;
  });

  $("#notificationList").innerHTML = filtered
    .map((item) => {
      const status = item.notification_status;
      const days = item.days_to_expiry;
      const daysText = days < 0 ? `${Math.abs(days)}d overdue` : days === 0 ? "Today" : `${days} days`;
      const daysClass = days <= 3 ? "danger-text" : days <= 7 ? "warning-text" : "";

      let statusClass = "env";
      if (status === "Escalated") statusClass = "risk-Critical";
      else if (status === "Sent") statusClass = "risk-High";
      else if (status === "Reminded") statusClass = "risk-Low";
      else if (status === "No Alerts") statusClass = "env";

      let actions = "";
      if (status === "Sent" && item.notification_id) {
        actions = `<button class="small-button" data-ack="${item.notification_id}">Acknowledge</button> <button class="small-button ghost-button" style="margin-left: 8px; border: 1px solid var(--border);" data-remind="${item.notification_id}">Send Reminder</button>`;
      } else if (status === "No Alerts") {
        actions = `<span class="muted" style="color: #10b981;">✓ Secure</span> <button class="small-button ghost-button" style="margin-left: 8px; font-size: 0.8em; padding: 2px 6px;" data-test-alert="${item.id}">Test Alert</button>`;
      } else if (item.notification_id) {
        actions = `<span class="muted">${escapeHtml(status)}</span> <button class="small-button ghost-button" style="margin-left: 8px; font-size: 0.8em; padding: 2px 6px;" data-undo="${item.notification_id}">Undo</button>`;
      } else {
        actions = `<span class="muted">${escapeHtml(status)}</span>`;
      }

      const isEscalated = status === "Escalated";

      return `
      <tr class="${isEscalated ? "danger-text" : ""}" style="${isEscalated ? "background: #fef2f2;" : ""}">
        <td>
          <div class="credential-name">
            <strong>${escapeHtml(item.database_name)}</strong>
            <span class="muted">${escapeHtml(item.username)}</span>
          </div>
        </td>
        <td>${escapeHtml(item.owner)}</td>
        <td class="${daysClass}"><strong>${daysText}</strong></td>
        <td><span class="pill ${statusClass}">${escapeHtml(status)}</span></td>
        <td>${actions}</td>
      </tr>
      `;
    })
    .join("");
}

function renderAudit() {
  const search = state.filters.search.trim().toLowerCase();

  const filtered = state.audit.filter(item =>
    !search ||
    String(item.action || "").toLowerCase().includes(search) ||
    String(item.actor || "").toLowerCase().includes(search) ||
    String(item.entity || "").toLowerCase().includes(search) ||
    String(item.entity_id || "").toLowerCase().includes(search) ||
    String(item.details || "").toLowerCase().includes(search) ||
    String(item.created_at || "").toLowerCase().includes(search)
  );

  $("#auditList").innerHTML = filtered
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
  if (state.analytics) {
    renderBars("#expiryBuckets", state.analytics.expiry_buckets);
    renderBars("#factorBars", state.analytics.top_factors);
  }

  if (state.analyticsPlots && typeof Plotly !== "undefined") {
    const config = { responsive: true, displayModeBar: false };

    if (state.analyticsPlots.credentials_by_role) {
      Plotly.react("plot-credentials-by-role", state.analyticsPlots.credentials_by_role.data, state.analyticsPlots.credentials_by_role.layout, config);
    }
    if (state.analyticsPlots.credentials_by_department) {
      Plotly.react("plot-credentials-by-department", state.analyticsPlots.credentials_by_department.data, state.analyticsPlots.credentials_by_department.layout, config);
    }
    if (state.analyticsPlots.expiry_timeline) {
      Plotly.react("plot-expiry-timeline", state.analyticsPlots.expiry_timeline.data, state.analyticsPlots.expiry_timeline.layout, config);
    }
    if (state.analyticsPlots.action_distribution) {
      Plotly.react("plot-action-distribution", state.analyticsPlots.action_distribution.data, state.analyticsPlots.action_distribution.layout, config);
    }
    if (state.analyticsPlots.audit_activity) {
      Plotly.react("plot-audit-activity", state.analyticsPlots.audit_activity.data, state.analyticsPlots.audit_activity.layout, config);
    }
    if (state.analyticsPlots.rotation_status) {
      Plotly.react("plot-rotation-status", state.analyticsPlots.rotation_status.data, state.analyticsPlots.rotation_status.layout, config);
    }
    if (state.analyticsPlots.verification_status) {
      Plotly.react("plot-verification-status", state.analyticsPlots.verification_status.data, state.analyticsPlots.verification_status.layout, config);
    }
    if (state.analyticsPlots.rotation_vs_verification) {
      Plotly.react("plot-rotation-vs-verification", state.analyticsPlots.rotation_vs_verification.data, state.analyticsPlots.rotation_vs_verification.layout, config);
    }
  }
}

function setView(view) {
  state.view = view;
  $$(".view").forEach((section) => section.classList.toggle("active", section.id === view));
  $$(".nav-tabs button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
}

function bindEvents() {
  $$(".nav-tabs button").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  $("#searchInput").addEventListener("input", (event) => {
    state.filters.search = event.target.value;
    debounceRefresh();
  });
  $("#riskFilter").addEventListener("change", (event) => {
    state.filters.risk = event.target.value;
    refreshAll();
  });
  document.body.addEventListener("click", async (event) => {
    const editExpiryTarget = event.target.closest("[data-edit-expiry]");
    if (editExpiryTarget) {
      event.stopPropagation(); // prevent row selection
      const credId = editExpiryTarget.dataset.editExpiry;
      const cred = state.credentials.find(c => String(c.id) === credId);
      if (!cred) return;
      const newDays = prompt(`Enter new days to expiry for ${cred.database_name} (${cred.owner}):`, cred.days_to_expiry);
      if (newDays !== null) {
        const parsedDays = parseInt(newDays, 10);
        if (!isNaN(parsedDays)) {
          await api(`/api/credentials/${credId}/expiry`, {
            method: "PUT",
            body: JSON.stringify({ days: parsedDays, actor: "demo-admin" })
          });
          showToast("Success", "Expiry updated globally.");
          await refreshAll();
        } else {
          showToast("Error", "Invalid number entered.");
        }
      }
      return;
    }
    if (event.target.matches("#notificationFilters button")) {
      const filter = event.target.dataset.filter;
      state.notificationFilter = filter;
      $$("#notificationFilters button").forEach(btn => btn.className = "small-button ghost-button");
      event.target.className = "active small-button";
      renderNotifications();
      return;
    }
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
    const remindTarget = event.target.closest("[data-remind]");
    if (remindTarget) {
      const res = await api(`/api/notifications/${remindTarget.dataset.remind}/remind`, {
        method: "POST",
        body: JSON.stringify({ actor: "demo-admin" }),
      });
      if (res && res.mailto) {
        const m = res.mailto;
        const gmailUrl = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(m.to)}&su=${encodeURIComponent(m.subject)}&body=${encodeURIComponent(m.body)}`;
        window.open(gmailUrl, '_blank');

        // Extract the magic link to make it clickable on the dashboard
        const magicLinkMatch = m.body.match(/(https?:\/\/[^\s]+reset\/[a-zA-Z0-9_-]+)/);
        if (magicLinkMatch) {
            showToast("Reminder Drafted", `Gmail opened in a new tab.<br><br><b>For testing:</b> <a href="${magicLinkMatch[1]}" target="_blank" style="color: #60a5fa; text-decoration: underline;">Click here to open the Magic Link</a> directly.`, true, 10000);
        } else {
            showToast("Gmail Opened", "A new tab has been opened with your drafted message.");
        }
      } else {
        showToast("Email Drafted", "Notification status updated.");
      }
      await refreshAll();
    }
    const undoTarget = event.target.closest("[data-undo]");
    if (undoTarget) {
      await api(`/api/notifications/${undoTarget.dataset.undo}/undo`, { method: "POST" });
      showToast("Undone", "Notification status reverted to Sent.");
      await refreshAll();
    }
    const testAlertTarget = event.target.closest("[data-test-alert]");
    if (testAlertTarget) {
      await api(`/api/credentials/${testAlertTarget.dataset.testAlert}/test-alert`, { method: "POST" });
      showToast("Alert Generated", "A test notification has been created for this credential.");
      await refreshAll();
    }
  });
  $("#resetDemo").addEventListener("click", async () => {
    await api("/api/demo/reset", { method: "POST", body: "{}" });
    state.selectedId = null;
    await refreshAll();
  });
}

let refreshTimer = null;
function debounceRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshAll, 250);
}

function showToast(title, message, isHtml = false, duration = 4000) {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `<h4>${escapeHtml(title)}</h4><p style="margin-top: 4px;">${isHtml ? message : escapeHtml(message)}</p>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("hiding");
    toast.addEventListener("animationend", () => toast.remove());
  }, duration);
}

bindEvents();
refreshAll().catch((error) => {
  document.body.innerHTML = `<main class="workspace"><section class="panel"><h1>SecureRotate could not load</h1><p>${escapeHtml(error.message)}</p></section></main>`;
});

// Auto-polling for live updates every 10 seconds
setInterval(() => {
  if (document.visibilityState === "visible") refreshAll();
}, 10000);
