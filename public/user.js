const form = document.querySelector("#credentialForm");
const result = document.querySelector("#submitResult");
const expiryInput = form.elements.expiry_date;

function defaultExpiryDate() {
  const date = new Date();
  date.setDate(date.getDate() + 6);
  return date.toISOString().slice(0, 10);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

expiryInput.value = defaultExpiryDate();

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  result.className = "submit-result loading";
  result.textContent = "Submitting credential and running risk recommendation...";

  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const response = await fetch("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Submission failed");

    result.className = "submit-result success";
    result.innerHTML = `
      <h2>Submitted successfully</h2>
      <p>Your credential is now visible in the admin dashboard.</p>
      <div class="detail-grid">
        <div class="detail-stat"><span>Risk</span><strong>${escapeHtml(data.risk)} ${Math.round(data.risk_probability * 100)}%</strong></div>
        <div class="detail-stat"><span>Expiry</span><strong>${escapeHtml(data.days_to_expiry)} days left</strong></div>
        <div class="detail-stat"><span>Recommendation</span><strong>${escapeHtml(data.recommendation.action)}</strong></div>
        <div class="detail-stat"><span>Password</span><strong>Stored as hash only</strong></div>
      </div>
      <p>${escapeHtml(data.recommendation.explanation)}</p>
      <a class="primary-link" href="/admin">View in Admin Dashboard</a>
    `;
    form.reset();
    expiryInput.value = defaultExpiryDate();
  } catch (error) {
    result.className = "submit-result error";
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
