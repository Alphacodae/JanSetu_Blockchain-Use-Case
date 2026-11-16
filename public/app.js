const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const state = {
  records: [],
  beneficiaries: [],
  activity: [],
  view: "dashboard",
  status: null,
  session: null,
  csrfToken: null,
  hasMore: false,
  nextOffset: 0,
};
const THEME_KEY = "jansetu-theme";
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const button = document.getElementById("themeToggle");
  if (button) {
    const isDark = theme === "dark";
    const icon = button.querySelector(".theme-icon");
    const label = button.querySelector(".theme-label");
    if (icon) {
      icon.innerHTML = isDark
        ? '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"></path>'
        : '<path d="M20.5 15.2A8.5 8.5 0 0 1 8.8 3.5 8.5 8.5 0 1 0 20.5 15.2Z"></path>';
    }
    if (label) label.textContent = isDark ? "Light mode" : "Dark mode";
    button.setAttribute(
      "aria-label",
      `Switch to ${isDark ? "light" : "dark"} mode`,
    );
    button.dataset.tooltip = `Switch to ${isDark ? "light" : "dark"} mode`;
    button.setAttribute("aria-checked", String(isDark));
    button.classList.toggle("is-on", isDark);
  }
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {}
}
try {
  applyTheme(
    localStorage.getItem(THEME_KEY) ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  );
} catch {
  document.documentElement.dataset.theme = "light";
}
const labels = {
  dashboard: [
    "Land records",
    "Land records overview",
    "Shared parcel records with approvals written to the local blockchain.",
  ],
  land: [
    "Land records",
    "Land records directory",
    "Search live contract records and review their on-chain approval status.",
  ],
  transfers: [
    "Transfer requests",
    "Transfer requests",
    "Request or approve an ownership change. Two departments must approve.",
  ],
  history: [
    "Audit trail",
    "Network audit trail",
    "Recent contract transactions and government workflow actions.",
  ],
  identity: [
    "Digital identity",
    "Digital identity services",
    "Check a synthetic eligibility reference against the issuer's live contract claim.",
  ],
  welfare: [
    "Welfare register",
    "Public distribution system",
    "Check PDS eligibility and record a monthly delivery receipt on-chain.",
  ],
};
const $ = (id) => document.getElementById(id);
const toast = (message) => {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 3400);
};
async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = {
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...options.headers,
  };
  if (
    method !== "GET" &&
    !["/auth/challenge", "/auth/login"].includes(path) &&
    state.csrfToken
  )
    headers["X-CSRF-Token"] = state.csrfToken;
  if (
    ["POST", "PUT", "PATCH", "DELETE"].includes(method) &&
    !path.startsWith("/auth/")
  )
    headers["Idempotency-Key"] ||= crypto.randomUUID();
  const response = await fetch(`/api${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  const result = await response.json().catch(() => ({}));
  if (response.status === 401)
    showAuthGate("Your session ended. Connect your department wallet again.");
  if (!response.ok)
    throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}
function showAuthGate(
  message = "Connect an authorized local wallet to continue.",
) {
  state.session = null;
  state.status = null;
  state.csrfToken = null;
  $("authGate").hidden = false;
  document.querySelector(".content").hidden = true;
  $("authStatus").textContent = message;
  $("walletButton").textContent = "Connect wallet";
  $("logoutButton").hidden = true;
  $("connectWallet").hidden = false;
}
function applySession(session) {
  state.session = session;
  state.csrfToken = session.csrfToken;
  $("authGate").hidden = true;
  document.querySelector(".content").hidden = false;
  $("walletButton").textContent =
    `${session.address.slice(0, 6)}…${session.address.slice(-4)}`;
  $("logoutButton").hidden = false;
  const names = session.roles.map(
    (role) =>
      ({
        registrar: "Registrar",
        landOffice: "Land office",
        surveyOffice: "Survey office",
        identityIssuer: "Identity issuer",
        welfareOffice: "Welfare operator",
      })[role],
  );
  document.querySelector(".profile small").textContent =
    `${names.join(" · ")} · wallet authenticated`;
  document.querySelector('[data-view="identity"]').hidden = !session.roles.some(
    (role) => ["identityIssuer", "welfareOffice"].includes(role),
  );
  document.querySelector('[data-view="welfare"]').hidden =
    !session.roles.includes("welfareOffice");
  document.querySelector('[data-view="transfers"]').hidden =
    !session.roles.some((role) =>
      ["registrar", "landOffice", "surveyOffice"].includes(role),
    );
  document.querySelector('[data-view="land"]').hidden = !session.roles.some(
    (role) => ["registrar", "landOffice", "surveyOffice"].includes(role),
  );
  $("connectWallet").hidden = true;
  const canLand = session.roles.some((role) =>
    ["registrar", "landOffice", "surveyOffice"].includes(role),
  );
  document.querySelector('[data-view="dashboard"]').hidden = !canLand;
  if (!canLand) {
    const initialView = session.roles.includes("welfareOffice")
      ? "welfare"
      : "identity";
    updateHeading(initialView);
  }
}
async function connectWallet() {
  if (!window.ethereum)
    throw new Error(
      "Install or open a browser wallet such as MetaMask, then connect a local Hardhat account.",
    );
  const chainId = await window.ethereum.request({ method: "eth_chainId" });
  if (chainId !== "0x7a69") {
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x7a69" }],
      });
    } catch (error) {
      if (error.code !== 4902) throw error;
      await window.ethereum.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId: "0x7a69",
            chainName: "JanSetu Local Hardhat",
            nativeCurrency: { name: "Demo Ether", symbol: "ETH", decimals: 18 },
            rpcUrls: ["http://127.0.0.1:8545"],
          },
        ],
      });
    }
  }
  const [address] = await window.ethereum.request({
    method: "eth_requestAccounts",
  });
  if (!address) throw new Error("No wallet account was selected.");
  const challenge = await api("/auth/challenge", {
    method: "POST",
    body: JSON.stringify({ address }),
  });
  const signature = await window.ethereum.request({
    method: "personal_sign",
    params: [challenge.message, address],
  });
  const session = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({ address, message: challenge.message, signature }),
  });
  applySession(session);
  await refresh();
  toast(
    `Connected as ${session.roles.map((role) => role.replace(/([A-Z])/g, " $1")).join(", ")}.`,
  );
}
async function restoreSession() {
  try {
    applySession(await api("/auth/session"));
    await refresh();
  } catch (error) {
    showAuthGate(
      error.message === "Sign in with an authorized wallet."
        ? "Connect an authorized local wallet to continue."
        : error.message,
    );
  }
}
const initials = (name) =>
  name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
const shortHash = (hash) =>
  hash && hash !== "—" ? `${hash.slice(0, 8)}…${hash.slice(-6)}` : "—";
const timeAgo = (timestamp) => {
  const seconds = Math.max(
    0,
    Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000),
  );
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  return new Date(timestamp).toLocaleDateString("en-IN");
};
let modalReturnFocus = null;
function showModal(id) {
  modalReturnFocus = document.activeElement;
  const modal = $(id);
  modal.classList.add("open");
  modal
    .querySelector("input:not([type=hidden]),button,select,textarea")
    ?.focus();
}
function hideModal(id) {
  $(id).classList.remove("open");
  if (modalReturnFocus?.isConnected) modalReturnFocus.focus();
}
function setBusy(button, busy, text = "Working…") {
  if (!button) return;
  if (busy) {
    button.dataset.label = button.textContent;
    button.disabled = true;
    button.textContent = text;
  } else {
    button.disabled = false;
    if (button.dataset.label) button.textContent = button.dataset.label;
    delete button.dataset.label;
  }
}
function updateHeading(view) {
  state.view = view;
  const [crumb, title, subtitle] = labels[view];
  $("crumb").textContent = crumb;
  $("pageTitle").textContent = title;
  $("pageSubtitle").textContent = subtitle;
  $("newRecord").hidden = !(
    ["dashboard", "land"].includes(view) &&
    state.session?.roles.includes("registrar")
  );
  document
    .querySelectorAll(".nav button")
    .forEach((button) =>
      button.classList.toggle(
        "active",
        button.dataset.view === view ||
          (view === "dashboard" && button.dataset.view === "dashboard"),
      ),
    );
  $("sidebar").classList.remove("open");
}
async function refresh() {
  if (!state.session) return;
  const hasLandAccess = state.session.roles.some((role) =>
    ["registrar", "landOffice", "surveyOffice"].includes(role),
  );
  const [status, recordData, activityData] = await Promise.all([
    api("/status"),
    hasLandAccess
      ? api("/records?limit=50&offset=0")
      : Promise.resolve({ records: [], hasMore: false, offset: 0 }),
    api("/activity?limit=50&offset=0"),
  ]);
  state.status = status;
  state.records = recordData.records;
  state.hasMore = recordData.hasMore;
  state.nextOffset = recordData.offset + recordData.records.length;
  state.activity = activityData.activity;
  state.beneficiaries = state.session.roles.includes("welfareOffice")
    ? (await api("/welfare")).beneficiaries
    : [];
  $("chainStatus").innerHTML =
    `<span class="dot chain-status-dot"></span><span class="chain-status-label">Local Chain <span class="chain-status-separator">·</span> block ${status.blockNumber}</span>`;
  const net = document.querySelector(".network .network-top");
  if (net) net.innerHTML = '<span class="dot"></span> Local chain operational';
  const netSmall = document.querySelector(".network small");
  if (netSmall)
    netSmall.textContent = `Hardhat · chain ${status.chainId} · ${status.contractAddress.slice(0, 10)}…`;
  const profile = document.querySelector(".profile small");
  if (profile)
    profile.textContent = `${status.roles.length} authorized role${status.roles.length === 1 ? "" : "s"} · wallet ${status.address.slice(0, 6)}…`;
  const chainNum = document.querySelector(".chain-num");
  if (chainNum)
    chainNum.textContent = `Block #${Number(status.blockNumber).toLocaleString("en-IN")}`;
  const chainDesc = document.querySelector(".chain-desc");
  if (chainDesc)
    chainDesc.textContent = `JanSetu contract ${status.contractAddress.slice(0, 10)}… · local Hardhat EVM`;
  $("totalCount").textContent = state.records.length.toLocaleString("en-IN");
  $("verifiedCount").textContent = state.records
    .filter((record) => record.status === "Verified")
    .length.toLocaleString("en-IN");
  $("pendingCount").textContent = state.records
    .filter((record) => record.status === "Pending" || record.transferPending)
    .length.toLocaleString("en-IN");
  $("blockCount").textContent = Number(status.blockNumber).toLocaleString(
    "en-IN",
  );
  const chainTag = document.querySelector(".chain-tag");
  if (chainTag) chainTag.textContent = "LOCAL DEMO";
  const chainFoot = document.querySelector(".chain-foot");
  if (chainFoot)
    chainFoot.innerHTML = `<span>Chain ID <b>${status.chainId}</b></span><span>Roles <b>${status.roles.length}</b></span><span>Mode <b>Local demo</b></span>`;
  render();
  renderActivity();
}
function render() {
  if (state.view === "welfare") return renderWelfare();
  if (state.view === "identity") return renderIdentity();
  if (state.view === "history") return renderHistory();
  renderRecords();
}
function renderRecords() {
  const card = document.querySelector(".table-card");
  if (!card.querySelector("#recordRows")) {
    card.innerHTML = `<div class="card-head"><div><div class="card-title">Recent land records</div><div class="card-sub">Parcel status read from the deployed local contract</div></div><button class="text-link" id="viewAll">View all records&nbsp; →</button></div><div class="filters"><div class="search"><span class="mag">⌕</span><input id="searchInput" placeholder="Search parcel ID, owner or village…" aria-label="Search records"></div><select class="select" id="statusFilter" aria-label="Filter records"><option value="all">All statuses</option><option value="Verified">Verified</option><option value="Pending">Pending</option><option value="transfer">Transfer pending</option></select></div><div class="table-wrap"><table><thead><tr><th>Parcel / location</th><th>Registered owner</th><th>Area</th><th>Last updated</th><th>Status</th><th>Workflow</th></tr></thead><tbody id="recordRows"></tbody></table></div>`;
    $("searchInput").addEventListener("input", renderRecords);
    $("statusFilter").addEventListener("change", renderRecords);
    $("viewAll").onclick = () => navigate("land");
  }
  const query = $("searchInput").value.toLowerCase();
  const filter =
    state.view === "transfers" ? "transfer" : $("statusFilter").value;
  const roles = state.status?.roles || [];
  const hasRole = (role) => roles.includes(role);
  const records = state.records.filter((record) => {
    const text =
      `${record.id} ${record.owner} ${record.village} ${record.status}`.toLowerCase();
    const filterMatch =
      filter === "all" ||
      (filter === "transfer"
        ? record.transferPending || record.status === "Pending"
        : record.status === filter);
    return filterMatch && text.includes(query);
  });
  $("recordRows").innerHTML = records.length
    ? records
        .map((record) => {
          const status = record.transferPending
            ? '<span class="badge pending">◷ Transfer pending</span>'
            : record.status === "Verified"
              ? '<span class="badge verified">✓ Verified</span>'
              : `<span class="badge pending">◷ Pending · ${record.approvalCount}/2 approvals</span>`;
          let actions = "";
          if (record.transferPending) {
            const approvals = record.pendingTransfer?.approvals || [];
            actions = `${["land", "survey"]
              .filter(
                (dept) =>
                  hasRole(dept === "land" ? "landOffice" : "surveyOffice") &&
                  !approvals.includes(
                    dept === "land" ? "Land office" : "Survey office",
                  ),
              )
              .map(
                (dept) =>
                  `<button class="text-link action-button" data-action="approve-transfer" data-id="${escapeHtml(record.id)}" data-department="${dept}">Approve ${dept} →</button>`,
              )
              .join(" ")}`;
            if (approvals.length)
              actions += `<div class="location">Approved: ${escapeHtml(approvals.join(" + "))}</div>`;
          } else if (record.status === "Pending") {
            actions = `${["land", "survey"]
              .filter(
                (dept) =>
                  hasRole(dept === "land" ? "landOffice" : "surveyOffice") &&
                  !record.approvals.includes(
                    dept === "land" ? "Land office" : "Survey office",
                  ),
              )
              .map(
                (dept) =>
                  `<button class="text-link action-button" data-action="approve-record" data-id="${escapeHtml(record.id)}" data-department="${dept}">Approve ${dept} →</button>`,
              )
              .join(" ")}`;
          } else {
            actions = hasRole("registrar")
              ? `<button class="text-link action-button" data-action="request-transfer" data-id="${escapeHtml(record.id)}">Transfer →</button>`
              : '<span class="location">Verified</span>';
          }
          return `<tr><td><div class="land-id">${escapeHtml(record.id)}</div><div class="location">${escapeHtml(record.village)}</div></td><td><div class="owner"><span class="mini-avatar">${escapeHtml(initials(record.owner))}</span>${escapeHtml(record.owner)}</div></td><td>${escapeHtml(record.area)}</td><td>${escapeHtml(record.date)}</td><td>${status}</td><td>${actions}<div class="location" title="Transaction hash">${escapeHtml(shortHash(record.transactionHash))}</div></td></tr>`;
        })
        .join("")
    : '<tr><td colspan="6" class="empty">No matching on-chain records.</td></tr>';
}
function renderWelfare() {
  const card = document.querySelector(".table-card");
  card.innerHTML = `<div class="card-head"><div><div class="card-title">PDS entitlement & delivery register</div><div class="card-sub">Synthetic households · receipts are recorded on the local chain</div></div><span class="badge verified">● Eligibility issuer online</span></div><div class="filters"><div class="search"><span class="mag">⌕</span><input id="welfareSearch" placeholder="Search masked beneficiary or fair price shop…"></div><select class="select" id="welfareFilter"><option value="all">All deliveries</option><option value="pending">Pending pickup</option><option value="delivered">Delivered</option></select></div><div class="table-wrap"><table><thead><tr><th>Beneficiary reference</th><th>Household / FPS</th><th>Monthly entitlement</th><th>Cycle</th><th>Delivery</th><th>Action</th></tr></thead><tbody id="welfareRows"></tbody></table></div><div class="notice welfare-notice"><b>Demo data only.</b> Eligibility is verified against an issuer claim. Do not enter real identity numbers or household records.</div>`;
  const draw = () => {
    const query = $("welfareSearch").value.toLowerCase(),
      filter = $("welfareFilter").value;
    const matches = state.beneficiaries.filter(
      (person) =>
        (filter === "all" ||
          (filter === "delivered" ? person.delivered : !person.delivered)) &&
        `${person.id} ${person.shop}`.toLowerCase().includes(query),
    );
    $("welfareRows").innerHTML = matches.length
      ? matches
          .map(
            (person) =>
              `<tr><td><span class="land-id">${escapeHtml(person.id)}</span><div class="location">Eligibility check available</div></td><td><div class="land-id">${escapeHtml(person.household)}</div><div class="location">${escapeHtml(person.shop)}</div></td><td>${escapeHtml(person.ration)}</td><td>${escapeHtml(person.cycle)}</td><td><span class="badge ${person.delivered ? "verified" : "pending"}">${person.delivered ? "✓ Delivered" : "◷ Pending pickup"}</span></td><td>${person.delivered ? `<span class="hash" title="${escapeHtml(person.receiptHash || "")}">Receipt ${escapeHtml(shortHash(person.receiptHash))}</span>` : `<button class="text-link action-button" data-action="deliver" data-id="${escapeHtml(person.id)}">Confirm delivery →</button>`}</td></tr>`,
          )
          .join("")
      : '<tr><td colspan="6" class="empty">No matching beneficiaries.</td></tr>';
  };
  $("welfareSearch").addEventListener("input", draw);
  $("welfareFilter").addEventListener("change", draw);
  draw();
}
function renderIdentity() {
  const card = document.querySelector(".table-card");
  const roles = state.session?.roles || [];
  const canIssue = roles.includes("identityIssuer");
  card.innerHTML = `<div class="card-head"><div><div class="card-title">Privacy preserving identity check</div><div class="card-sub">The issuer confirms eligibility without revealing a full identity record</div></div><span class="badge verified">● Local issuer connected</span></div><div class="identity-body"><div class="identity-panel"><div class="eyebrow identity-heading">Live contract verification</div><label class="identity-label" for="identityRef">Synthetic beneficiary reference</label><input id="identityRef" class="form-control identity-input" placeholder="DEMO-BENEFICIARY-0421"><div class="identity-actions"><button class="btn primary" id="verifyIdentity">Verify claim</button>${canIssue ? '<button class="btn" id="issueClaim">Issue 90-day claim</button><button class="btn" id="revokeClaim">Revoke claim</button>' : ""}</div><div class="card-sub small-gap">Use a sample reference from the welfare register. Never enter a real government ID number.</div></div><div id="identityResult" class="identity-result" hidden></div><div class="card-title identity-summary">Connected government services</div><div class="identity-services"><div class="network"><div class="network-top">✓ District identity issuer</div><small>Signs expiring eligibility claims</small></div><div class="network"><div class="network-top">✓ Public distribution system</div><small>Checks only the required entitlement</small></div></div></div>`;
  $("verifyIdentity").onclick = async () => {
    const button = $("verifyIdentity");
    setBusy(button, true);
    try {
      const result = await api("/identity/verify", {
        method: "POST",
        body: JSON.stringify({ referenceId: $("identityRef").value.trim() }),
      });
      const panel = $("identityResult");
      panel.hidden = false;
      panel.className = `identity-result ${result.eligible ? "eligible" : "ineligible"}`;
      panel.innerHTML = `<div class="badge ${result.eligible ? "verified" : "pending"}">${result.eligible ? "✓ Claim verified on-chain" : "! No current claim found"}</div><div class="identity-result-title">${result.eligible ? "Eligible for public distribution system" : "Eligibility could not be confirmed"}</div><div class="card-sub small-gap">${result.eligible ? `Issuer: ${escapeHtml(result.issuer)} · Claim: ${escapeHtml(result.claim)} · No personal identity data was disclosed.` : "Check the synthetic reference and ask the authorized issuer to update the claim."}</div>`;
    } catch (error) {
      toast(error.message);
    } finally {
      setBusy(button, false);
    }
  };
  if (canIssue) {
    $("issueClaim").onclick = async () => {
      const button = $("issueClaim");
      setBusy(button, true);
      try {
        const result = await api("/identity/claims", {
          method: "POST",
          body: JSON.stringify({
            referenceId: $("identityRef").value.trim(),
            validDays: 90,
          }),
        });
        toast(
          `Eligibility claim ${result.transaction.status} · ${shortHash(result.transaction.hash)}`,
        );
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(button, false);
      }
    };
    $("revokeClaim").onclick = async () => {
      const button = $("revokeClaim");
      setBusy(button, true);
      try {
        const result = await api("/identity/claims", {
          method: "DELETE",
          body: JSON.stringify({ referenceId: $("identityRef").value.trim() }),
        });
        toast(
          `Eligibility claim ${result.transaction.status} · ${shortHash(result.transaction.hash)}`,
        );
      } catch (error) {
        toast(error.message);
      } finally {
        setBusy(button, false);
      }
    };
  }
}
function renderHistory() {
  const card = document.querySelector(".table-card");
  card.innerHTML = `<div class="card-head"><div><div class="card-title">Recent contract activity</div><div class="card-sub">Recorded by the JanSetu demo API and anchored to local EVM transactions</div></div></div><div class="table-wrap"><table><thead><tr><th>Action</th><th>Subject</th><th>Demo role</th><th>Time</th><th>Transaction</th></tr></thead><tbody>${state.activity.length ? state.activity.map((item) => `<tr><td><span class="land-id">${escapeHtml(item.action)}</span></td><td>${escapeHtml(item.subject)}</td><td>${escapeHtml(item.role)}</td><td>${escapeHtml(timeAgo(item.timestamp))}</td><td class="hash">${escapeHtml(shortHash(item.transactionHash))}</td></tr>`).join("") : '<tr><td class="empty" colspan="5">No transactions yet.</td></tr>'}</tbody></table></div>`;
}
function renderActivity() {
  const list = $("activityList");
  list.innerHTML =
    state.activity
      .slice(0, 4)
      .map(
        (item) =>
          `<div class="activity-item"><div class="activity-icon">${item.action.includes("PDS") ? "▤" : item.action.includes("Transfer") || item.action.includes("Ownership") ? "⇄" : "✓"}</div><div class="activity-copy"><b>${escapeHtml(item.action)}</b> · ${escapeHtml(item.subject)}<small>${escapeHtml(item.role)} · ${escapeHtml(timeAgo(item.timestamp))}</small></div></div>`,
      )
      .join("") ||
    '<div class="card-sub activity-empty">No on-chain activity yet.</div>';
}
async function navigate(view) {
  updateHeading(view);
  const filter = $("statusFilter");
  if (filter && ["transfers", "land", "dashboard"].includes(view))
    filter.value = view === "transfers" ? "transfer" : "all";
  render();
  if (view === "transfers") {
    $("statusFilter").value = "transfer";
    renderRecords();
  }
  if (view === "history") {
    try {
      state.activity = (await api("/activity")).activity;
      renderHistory();
      renderActivity();
    } catch (error) {
      toast(error.message);
    }
  }
}
async function doAction(button) {
  const action = button.dataset.action,
    id = button.dataset.id;
  setBusy(button, true);
  try {
    if (action === "approve-record") {
      await api(`/records/${encodeURIComponent(id)}/approve`, {
        method: "POST",
        body: JSON.stringify({ department: button.dataset.department }),
      });
      toast(`${button.dataset.department} office approval recorded on-chain.`);
    } else if (action === "approve-transfer") {
      await api(`/transfers/${encodeURIComponent(id)}/approve`, {
        method: "POST",
        body: JSON.stringify({ department: button.dataset.department }),
      });
      toast(`${button.dataset.department} office transfer approval recorded.`);
    } else if (action === "deliver") {
      await api(`/welfare/${encodeURIComponent(id)}/deliver`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      toast("PDS delivery receipt recorded on-chain.");
    } else if (action === "request-transfer") {
      $("transferParcel").value = id;
      $("transferParcelLabel").textContent = id;
      showModal("transferModal");
    }
    await refresh();
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(button, false);
  }
}
function bind() {
  $("today").textContent = new Intl.DateTimeFormat("en-IN", {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(new Date());
  $("menu").onclick = () => $("sidebar").classList.toggle("open");
  $("themeToggle").onclick = () =>
    applyTheme(
      document.documentElement.dataset.theme === "dark" ? "light" : "dark",
    );
  $("connectWallet").onclick = $("walletButton").onclick = async () => {
    $("authStatus").textContent = "Connecting wallet…";
    try {
      await connectWallet();
    } catch (error) {
      $("authStatus").textContent = error.message;
    }
  };
  $("logoutButton").onclick = async () => {
    try {
      await api("/auth/logout", { method: "POST", body: JSON.stringify({}) });
    } catch {}
    showAuthGate("Signed out. Connect another authorized department wallet.");
  };
  if (window.ethereum?.on) {
    const invalidateWalletSession = async (message) => {
      try {
        if (state.csrfToken)
          await api("/auth/logout", {
            method: "POST",
            body: JSON.stringify({}),
          });
      } catch {}
      showAuthGate(message);
    };
    window.ethereum.on("accountsChanged", () =>
      invalidateWalletSession(
        "Wallet account changed. Connect again to authenticate the selected department account.",
      ),
    );
    window.ethereum.on("chainChanged", () =>
      invalidateWalletSession(
        "Wallet network changed. Switch back to JanSetu Local Hardhat and connect again.",
      ),
    );
  }
  $("searchInput").addEventListener("input", renderRecords);
  $("statusFilter").addEventListener("change", renderRecords);
  $("viewAll").onclick = () => navigate("land");
  document
    .querySelectorAll("[data-view]")
    .forEach((button) =>
      button.addEventListener("click", () => navigate(button.dataset.view)),
    );
  document
    .querySelectorAll("[data-nav]")
    .forEach((button) =>
      button.addEventListener("click", () => navigate("history")),
    );
  $("newRecord").onclick = () => showModal("modal");
  $("closeModal").onclick = $("cancelModal").onclick = () => hideModal("modal");
  $("recordForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Submitting…");
    const payload = {
      id: $("parcel").value.trim(),
      owner: $("owner").value.trim(),
      village: $("village").value.trim(),
      area: $("area").value,
      documentRef: $("doc").value.trim(),
    };
    try {
      const result = await api("/records", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      $("recordForm").reset();
      hideModal("modal");
      await navigate("land");
      await refresh();
      toast(`Record submitted in block ${state.status.blockNumber}.`);
    } catch (error) {
      toast(error.message);
    } finally {
      setBusy(button, false, "Submitting…");
    }
  });
  $("transferModal").addEventListener("click", (event) => {
    if (event.target === $("transferModal")) hideModal("transferModal");
  });
  $("modal").addEventListener("click", (event) => {
    if (event.target === $("modal")) hideModal("modal");
  });
  document.addEventListener("keydown", (event) => {
    const activeModal = document.querySelector(".modal-backdrop.open");
    if (!activeModal) return;
    if (event.key === "Escape") {
      hideModal(activeModal.id);
      return;
    }
    if (event.key === "Tab") {
      const controls = [
        ...activeModal.querySelectorAll(
          'button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])',
        ),
      ].filter((item) => item.offsetParent !== null);
      if (!controls.length) return;
      const first = controls[0],
        last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  $("transferForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Submitting…");
    try {
      await api("/transfers", {
        method: "POST",
        body: JSON.stringify({
          parcelId: $("transferParcel").value,
          newOwner: $("newOwner").value.trim(),
        }),
      });
      $("transferForm").reset();
      hideModal("transferModal");
      await navigate("transfers");
      await refresh();
      toast("Transfer request submitted; two office approvals are required.");
    } catch (error) {
      toast(error.message);
    } finally {
      setBusy(button, false, "Submitting…");
    }
  });
  document.querySelector(".table-card").addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (button) doAction(button);
  });
}
document.body.insertAdjacentHTML(
  "beforeend",
  `<div class="modal-backdrop" id="transferModal"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="transferTitle"><header class="modal-header"><div><h2 id="transferTitle">Request ownership transfer</h2><p>Two distinct government offices must approve this change.</p></div><button class="close" type="button" id="closeTransfer" aria-label="Close">×</button></header><form class="form" id="transferForm"><div class="field full"><label>Parcel</label><div class="form-control" id="transferParcelLabel"></div><input type="hidden" id="transferParcel"></div><div class="field full"><label for="newOwner">New registered owner reference</label><input class="form-control" id="newOwner" required maxlength="100" placeholder="Sample name or synthetic reference"></div><div class="form-actions"><button class="btn" type="button" id="cancelTransfer">Cancel</button><button class="btn primary" type="submit">Submit transfer request →</button></div></form></section></div>`,
);
bind();
$("closeTransfer").onclick = $("cancelTransfer").onclick = () =>
  hideModal("transferModal");
restoreSession().catch((error) => {
  $("chainStatus").textContent = "Local chain not ready";
  const card = document.querySelector(".table-card");
  card.innerHTML = `<div class="card-head"><div><div class="card-title">Local demo setup required</div><div class="card-sub">Start Hardhat, deploy the contract, then launch the JanSetu API.</div></div></div><div class="notice setup-notice">${escapeHtml(error.message)}<br><br>See the README for the three terminal commands.</div>`;
});
