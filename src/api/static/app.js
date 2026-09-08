const keyStorageName = "keyframe-ca-api-key";
let apiKey = sessionStorage.getItem(keyStorageName) || "";

const notice = document.querySelector("#notice");
const keyDialog = document.querySelector("#key-dialog");
const connectionStatus = document.querySelector("#connection-status");
const connectionDot = document.querySelector("#connection-dot");
const pqcAvailability = document.querySelector("#pqc-availability");
const certificateList = document.querySelector("#certificate-list");
const certificateCount = document.querySelector("#certificate-count");
const certificateDetail = document.querySelector("#certificate-detail");
const revokeDialog = document.querySelector("#revoke-dialog");
const revokeSerial = document.querySelector("#revoke-serial");
let certificateRecords = [];
let activeFilter = "all";
let pendingRevocationSerial = null;

function showNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = false;
}

function artifactName(commonName) {
  return commonName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64) || "certificate";
}

function setConnection(connected) {
  connectionStatus.textContent = connected ? "Connected to CA API" : "API key required";
  connectionDot.classList.toggle("connected", connected);
}

function setJourney(health) {
  const hasCertificates = certificateRecords.length > 0;
  document.querySelector("#step-connect").className = apiKey ? "complete" : "current";
  document.querySelector("#step-initialize").className = health.ca_initialized ? "complete" : apiKey ? "current" : "";
  document.querySelector("#step-issue").className = hasCertificates ? "complete" : health.ca_initialized ? "current" : "";
}

function setBusy(button, busy, label) {
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? label : button.dataset.label;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers);
  headers.set("X-API-Key", apiKey);
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response;
}

function download(content, filename, type = "application/x-pem-file") {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function renderCertificates(records) {
  certificateRecords = records;
  certificateCount.textContent = `${records.length} record${records.length === 1 ? "" : "s"}`;
  const query = document.querySelector("#certificate-search").value.trim().toLowerCase();
  const visibleRecords = records.filter((record) =>
    (activeFilter === "all" || record.status === activeFilter)
    && (`${record.common_name} ${record.serial}`).toLowerCase().includes(query)
  );
  if (!visibleRecords.length) {
    certificateList.innerHTML = `<tr class="empty-row"><td colspan="5">${
      records.length ? "No certificates match this view. Clear the search or change the status filter." : "No certificates have been issued yet. Start by creating an identity above."
    }</td></tr>`;
    return;
  }
  certificateList.innerHTML = visibleRecords
    .sort((left, right) => `${right.issued_at}`.localeCompare(`${left.issued_at}`) || `${right.serial}`.localeCompare(`${left.serial}`))
    .map((record) => `
      <tr>
        <td>${escapeHtml(record.common_name)}</td>
        <td class="serial" title="${record.serial}">${record.serial}</td>
        <td>${record.has_pqc_identity ? "Attached" : "—"}</td>
        <td><span class="status ${record.status}">${record.status}</span></td>
        <td><div class="table-actions">
          <button class="button button-secondary" data-action="view" data-serial="${record.serial}">View</button>
          <button class="button button-secondary" data-action="download" data-serial="${record.serial}">Download</button>
          ${record.has_pqc_identity ? `<button class="button button-secondary" data-action="verify" data-serial="${record.serial}">Verify PQC</button>` : ""}
          ${record.status === "valid" ? `<button class="button button-danger" data-action="revoke" data-serial="${record.serial}">Revoke</button>` : ""}
        </div></td>
      </tr>
    `)
    .join("");
}

function renderDetail(record) {
  const revocation = record.revoked_at ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(record.revoked_at)) : "—";
  certificateDetail.innerHTML = `
    <p class="section-label">Certificate detail</p>
    <h3>${escapeHtml(record.common_name)}</h3>
    <ul class="detail-list">
      <li><span>Serial</span><code title="${record.serial}">${record.serial}</code></li>
      <li><span>Status</span><strong>${record.status}</strong></li>
      <li><span>PQC identity</span><strong>${record.has_pqc_identity ? "Attached" : "Not attached"}</strong></li>
      ${record.revoked_at ? `<li><span>Revoked</span><strong>${revocation}</strong></li>` : ""}
    </ul>
    <div class="detail-actions">
      <button class="button button-secondary" data-detail-action="copy" data-serial="${record.serial}">Copy serial</button>
      <button class="button button-secondary" data-detail-action="download" data-serial="${record.serial}">Download</button>
    </div>
  `;
}

function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}

async function refreshCertificates() {
  if (!apiKey) {
    setConnection(false);
    return;
  }
  try {
    const [healthResponse, certResponse] = await Promise.all([fetch("/health"), request("/certs")]);
    const health = await healthResponse.json();
    pqcAvailability.textContent = health.pqc_available ? "PQC ready" : "PQC unavailable";
    pqcAvailability.classList.toggle("available", health.pqc_available);
    renderCertificates(await certResponse.json());
    setConnection(true);
    setJourney(health);
  } catch (error) {
    setConnection(false);
    showNotice(error.message, true);
    setJourney({ ca_initialized: false });
  }
}

document.querySelectorAll("#open-key-dialog, #open-key-dialog-top").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelector("#api-key").value = apiKey;
    keyDialog.showModal();
  });
});

document.querySelector("#key-form").addEventListener("submit", (event) => {
  event.preventDefault();
  apiKey = document.querySelector("#api-key").value.trim();
  sessionStorage.setItem(keyStorageName, apiKey);
  keyDialog.close();
  refreshCertificates();
});

document.querySelector("#issue-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    csr_pem: form.get("csr_pem").trim(),
    valid_days: Number(form.get("valid_days")),
    enable_pqc: form.get("enable_pqc") === "on",
  };
  const button = event.submitter;
  try {
    setBusy(button, true, "Issuing…");
    const response = await request("/certs/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const certificate = await response.json();
    const filename = artifactName(certificate.common_name);
    download(certificate.classical_cert_pem, `${filename}.crt`);
    if (certificate.pqc_identity_pem) download(certificate.pqc_identity_pem, `${filename}.pqc-identity.pem`);
    showNotice("Certificate issued. Certificate artifact downloads have started; your private key remains on your device.");
    event.currentTarget.reset();
    refreshCertificates();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#init-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const force = form.get("force") === "on";
  const button = event.submitter;
  try {
    setBusy(button, true, "Initializing…");
    await request(`/ca/init?common_name=${encodeURIComponent(form.get("common_name"))}&force=${force}`, { method: "POST" });
    showNotice(force ? "CA replaced and certificate records cleared." : "Root CA initialized.");
    refreshCertificates();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#refresh-certificates").addEventListener("click", refreshCertificates);
document.querySelector("#certificate-search").addEventListener("input", () => renderCertificates(certificateRecords));
document.querySelectorAll(".filter-button").forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter;
    document.querySelectorAll(".filter-button").forEach((candidate) => candidate.classList.toggle("active", candidate === button));
    renderCertificates(certificateRecords);
  });
});

document.querySelector("#download-crl").addEventListener("click", async () => {
  try {
    const response = await request("/crl");
    download((await response.json()).crl_pem, "certificate-revocation-list.pem");
    showNotice("Current CRL download started.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

certificateList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, serial } = button.dataset;
  try {
    if (action === "revoke") {
      pendingRevocationSerial = serial;
      revokeSerial.textContent = serial;
      revokeDialog.showModal();
      return;
    }
    if (action === "view") {
      renderDetail(certificateRecords.find((record) => `${record.serial}` === serial));
      return;
    }
    if (action === "verify") {
      const result = await (await request(`/certs/${serial}/verify-pqc`, { method: "POST" })).json();
      showNotice(result.pqc_signature_valid ? "PQC identity signature verified." : "PQC identity signature could not be verified.", !result.pqc_signature_valid);
      return;
    }
    const record = await (await request(`/certs/${serial}`)).json();
    const filename = artifactName(record.common_name);
    download(record.classical_cert_pem, `${filename}.crt`);
    if (record.pqc_identity_pem) download(record.pqc_identity_pem, `${filename}.pqc-identity.pem`);
    showNotice("Certificate download started.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

document.querySelector("#revoke-form").addEventListener("submit", async (event) => {
  if (event.submitter.value === "cancel") return;
  event.preventDefault();
  const button = event.submitter;
  try {
    setBusy(button, true, "Revoking…");
    await request(`/certs/${pendingRevocationSerial}/revoke`, { method: "POST" });
    revokeDialog.close();
    showNotice(`Certificate ${pendingRevocationSerial} revoked.`);
    await refreshCertificates();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    setBusy(button, false);
  }
});

certificateDetail.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-detail-action]");
  if (!button) return;
  const record = certificateRecords.find((candidate) => `${candidate.serial}` === button.dataset.serial);
  if (button.dataset.detailAction === "copy") {
    try {
      await navigator.clipboard.writeText(`${record.serial}`);
      showNotice("Certificate serial copied to the clipboard.");
    } catch (error) {
      showNotice("Could not copy the serial. Select and copy it from the detail panel.", true);
    }
    return;
  }
  try {
    const fullRecord = await (await request(`/certs/${record.serial}`)).json();
    const filename = artifactName(fullRecord.common_name);
    download(fullRecord.classical_cert_pem, `${filename}.crt`);
    if (fullRecord.pqc_identity_pem) download(fullRecord.pqc_identity_pem, `${filename}.pqc-identity.pem`);
    showNotice("Certificate download started.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

setConnection(Boolean(apiKey));
fetch("/health")
  .then((response) => response.json())
  .then((health) => {
    pqcAvailability.textContent = health.pqc_available ? "PQC ready" : "PQC unavailable";
    pqcAvailability.classList.toggle("available", health.pqc_available);
    setJourney(health);
  });
refreshCertificates();
