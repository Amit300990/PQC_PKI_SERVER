const keyStorageName = "keyframe-ca-api-key";
let apiKey = sessionStorage.getItem(keyStorageName) || "";

const notice = document.querySelector("#notice");
const keyDialog = document.querySelector("#key-dialog");
const connectionStatus = document.querySelector("#connection-status");
const connectionDot = document.querySelector("#connection-dot");
const pqcAvailability = document.querySelector("#pqc-availability");
const certificateList = document.querySelector("#certificate-list");
const certificateCount = document.querySelector("#certificate-count");

function showNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = false;
}

function setConnection(connected) {
  connectionStatus.textContent = connected ? "Connected to CA API" : "API key required";
  connectionDot.classList.toggle("connected", connected);
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
  certificateCount.textContent = `${records.length} record${records.length === 1 ? "" : "s"}`;
  if (!records.length) {
    certificateList.innerHTML = '<tr class="empty-row"><td colspan="5">No certificates have been issued yet. Start by creating an identity above.</td></tr>';
    return;
  }
  certificateList.innerHTML = records
    .sort((left, right) => right.serial - left.serial)
    .map((record) => `
      <tr>
        <td>${escapeHtml(record.common_name)}</td>
        <td class="serial" title="${record.serial}">${record.serial}</td>
        <td>${record.has_pqc_identity ? "Attached" : "—"}</td>
        <td><span class="status ${record.status}">${record.status}</span></td>
        <td><div class="table-actions">
          <button class="button button-secondary" data-action="download" data-serial="${record.serial}">Download</button>
          ${record.has_pqc_identity ? `<button class="button button-secondary" data-action="verify" data-serial="${record.serial}">Verify PQC</button>` : ""}
          ${record.status === "valid" ? `<button class="button button-danger" data-action="revoke" data-serial="${record.serial}">Revoke</button>` : ""}
        </div></td>
      </tr>
    `)
    .join("");
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
  } catch (error) {
    setConnection(false);
    showNotice(error.message, true);
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
  const sans = form.get("sans").split("\n").map((value) => value.trim()).filter(Boolean);
  const payload = {
    common_name: form.get("common_name").trim(),
    sans,
    valid_days: Number(form.get("valid_days")),
    enable_pqc: form.get("enable_pqc") === "on",
  };
  try {
    const response = await request("/certs/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const certificate = await response.json();
    download(certificate.classical_cert_pem, `${payload.common_name}.crt`);
    download(certificate.classical_key_pem, `${payload.common_name}.key`);
    if (certificate.pqc_identity_pem) download(certificate.pqc_identity_pem, `${payload.common_name}.pqc-identity.pem`);
    showNotice("Certificate issued. Your certificate and private key downloads have started.");
    event.currentTarget.reset();
    refreshCertificates();
  } catch (error) {
    showNotice(error.message, true);
  }
});

document.querySelector("#init-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const force = form.get("force") === "on";
  try {
    await request(`/ca/init?common_name=${encodeURIComponent(form.get("common_name"))}&force=${force}`, { method: "POST" });
    showNotice(force ? "CA replaced and certificate records cleared." : "Root CA initialized.");
    refreshCertificates();
  } catch (error) {
    showNotice(error.message, true);
  }
});

document.querySelector("#refresh-certificates").addEventListener("click", refreshCertificates);

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
      await request(`/certs/${serial}/revoke`, { method: "POST" });
      showNotice(`Certificate ${serial} revoked.`);
      refreshCertificates();
      return;
    }
    if (action === "verify") {
      const result = await (await request(`/certs/${serial}/verify-pqc`, { method: "POST" })).json();
      showNotice(result.pqc_signature_valid ? "PQC identity signature verified." : "PQC identity signature could not be verified.", !result.pqc_signature_valid);
      return;
    }
    const record = await (await request(`/certs/${serial}`)).json();
    download(record.classical_cert_pem, `${record.common_name}.crt`);
    if (record.pqc_identity_pem) download(record.pqc_identity_pem, `${record.common_name}.pqc-identity.pem`);
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
  });
refreshCertificates();
