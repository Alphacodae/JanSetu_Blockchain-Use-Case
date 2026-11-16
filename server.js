const crypto = require("node:crypto");
const fs = require("node:fs");
const express = require("express");
const { ethers } = require("ethers");
const { Database } = require("./lib/database");
const { createPrivacy } = require("./lib/privacy");
const { createAuth } = require("./lib/auth");
const { loadConfig } = require("./lib/config");
const { requiredText, parcelId, ownerName, villageName, documentReference, areaAcres, beneficiaryReference, cycle, validDays, department, page, offset, bad } = require("./lib/validation");
const { requestId, securityHeaders, fixedWindowLimit, sendError } = require("./lib/http-security");

const ROOT = __dirname;
const config = loadConfig(ROOT);
const deployment = JSON.parse(fs.readFileSync(config.deploymentFile, "utf8"));
if (deployment.chainId !== 31337 || !ethers.isAddress(deployment.address)) throw new Error("Invalid local deployment metadata.");
const privacy = createPrivacy(ROOT);
const db = new Database(config.databaseFile, privacy);
const provider = new ethers.JsonRpcProvider(config.rpcUrl, 31337, { staticNetwork: true, polling: true });
const ABI = [
  "function admin() view returns (address)",
  "function REGISTRAR_ROLE() view returns (bytes32)",
  "function LAND_OFFICE_ROLE() view returns (bytes32)",
  "function SURVEY_OFFICE_ROLE() view returns (bytes32)",
  "function IDENTITY_ISSUER_ROLE() view returns (bytes32)",
  "function WELFARE_OPERATOR_ROLE() view returns (bytes32)",
  "function PDS_ELIGIBILITY() view returns (bytes32)",
  "function hasRole(bytes32,address) view returns (bool)",
  "function submitRecord(bytes32,bytes32,bytes32)",
  "function verifyRecord(bytes32,bytes32)",
  "function requestTransfer(bytes32,bytes32)",
  "function approveTransfer(bytes32,bytes32)",
  "function getParcel(bytes32) view returns (bytes32,bytes32,uint8,uint8,address,bytes32,uint8,address)",
  "function issueEligibilityClaim(bytes32,bytes32,uint64)",
  "function revokeEligibilityClaim(bytes32,bytes32)",
  "function verifyEligibilityClaim(bytes32,bytes32) view returns (bool)",
  "function recordPdsDelivery(bytes32,bytes32,bytes32)",
  "event RecordSubmitted(bytes32 indexed parcelId,address indexed registrar)",
  "event RecordVerified(bytes32 indexed parcelId,address indexed verifier,bytes32 role)",
  "event TransferRequested(bytes32 indexed parcelId,bytes32 indexed newOwnerHash,address registrar)",
  "event TransferApproved(bytes32 indexed parcelId,address indexed verifier,bytes32 role)",
  "event OwnershipUpdated(bytes32 indexed parcelId,bytes32 indexed newOwnerHash)",
  "event EligibilityClaimIssued(bytes32 indexed referenceHash,bytes32 indexed claimType,uint64 validUntil,address issuer)",
  "event EligibilityClaimRevoked(bytes32 indexed referenceHash,bytes32 indexed claimType,address issuer)",
  "event PdsDeliveryRecorded(bytes32 indexed referenceHash,bytes32 indexed cycleHash,bytes32 itemsHash,address operator)"
];
const registry = new ethers.Contract(deployment.address, ABI, provider);
const auth = createAuth(db, { secureCookie: false });
const roleSpecs = {
  registrar: { roleFn: "REGISTRAR_ROLE", address: deployment.roles.registrar, signer: 0, label: "District registrar" },
  landOffice: { roleFn: "LAND_OFFICE_ROLE", address: deployment.roles.landOffice, signer: 1, label: "Land office" },
  surveyOffice: { roleFn: "SURVEY_OFFICE_ROLE", address: deployment.roles.surveyOffice, signer: 2, label: "Survey office" },
  identityIssuer: { roleFn: "IDENTITY_ISSUER_ROLE", address: deployment.roles.identityIssuer, signer: 3, label: "District identity issuer" },
  welfareOffice: { roleFn: "WELFARE_OPERATOR_ROLE", address: deployment.roles.welfareOffice, signer: 4, label: "Fair price shop operator" }
};
const userLimiter = fixedWindowLimit({ name: "api-user", windowMs: 60_000, max: 60 });
const signerIndexes = Object.fromEntries(Object.values(roleSpecs).map((item) => [item.address.toLowerCase(), item.signer]));
const rpcMetrics = { reads: 0, readErrors: 0, writes: 0, lastReadMs: 0, lastWriteMs: 0 };
let writeQueue = Promise.resolve();
const enqueueWrite = (operation) => {
  const next = writeQueue.then(operation, operation);
  writeQueue = next.catch(() => {});
  return next;
};
const hashInput = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function readChain(operation) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const started = Date.now();
    let timer;
    try {
      const result = await Promise.race([
        operation(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error("RPC read timed out"), { code: "RPC_TIMEOUT" })), 8000); timer.unref?.(); })
      ]);
      rpcMetrics.reads += 1;
      rpcMetrics.lastReadMs = Date.now() - started;
      return result;
    } catch (error) {
      lastError = error;
      rpcMetrics.readErrors += 1;
      if (attempt === 0) await sleep(150);
    } finally { if (timer) clearTimeout(timer); }
  }
  throw Object.assign(new Error("Local blockchain read is temporarily unavailable."), { status: 503, code: lastError?.code || "RPC_READ_FAILED" });
}

async function readRoles(address) {
  const roles = [];
  for (const [key, spec] of Object.entries(roleSpecs)) {
    const role = await readChain(() => registry[spec.roleFn]());
    if (await readChain(() => registry.hasRole(role, address))) roles.push(key);
  }
  return roles;
}

async function requireActorRole(req, roleKey) {
  const spec = roleSpecs[roleKey];
  if (!spec) throw Object.assign(new Error("Role is not configured."), { status: 403 });
  const role = await readChain(() => registry[spec.roleFn]());
  const allowed = await readChain(() => registry.hasRole(role, req.user.address));
  if (!allowed) throw Object.assign(new Error("Your connected wallet is not authorized for this department."), { status: 403 });
  req.actorRole = roleKey;
  return { spec, role };
}

async function signerFor(req, roleKey) {
  const { spec } = await requireActorRole(req, roleKey);
  const configuredAddress = spec.address.toLowerCase();
  const index = signerIndexes[req.user.address.toLowerCase()];
  if (req.user.address.toLowerCase() !== configuredAddress || index !== spec.signer) {
    throw Object.assign(new Error("Wallet is not the configured local signer for this department."), { status: 403 });
  }
  const signer = await provider.getSigner(index);
  const actualAddress = await signer.getAddress();
  if (actualAddress.toLowerCase() !== req.user.address.toLowerCase()) throw Object.assign(new Error("Local signer identity did not match the authenticated wallet."), { status: 503 });
  return { signer, spec, role: await readChain(() => registry[spec.roleFn]()) };
}

async function currentRecords(limit, start) {
  const rows = db.listRecords(limit, start);
  const records = await Promise.all(rows.map(async (item) => {
    const parcel = await readChain(() => registry.getParcel(item.key));
    const verified = Number(parcel[2]) === 2;
    const transferPending = parcel[5] !== ethers.ZeroHash;
    return {
      ...item,
      status: verified ? "Verified" : "Pending",
      approvalCount: Number(parcel[3]),
      transferPending,
      pendingOwner: transferPending ? item.pendingTransfer?.newOwner || "New owner" : null,
      transactionHash: item.transactionHash || null,
      transactionStatus: item.transactionStatus || "confirmed"
    };
  }));
  return records;
}

function actorAudit(req, action, subjectRef, txHash) {
  const role = roleSpecs[req.actorRole]?.label || req.actorRole || "authorized operator";
  return db.appendAudit({ actor: req.user.address.toLowerCase(), role, action, subjectRef, txHash });
}

function applyIntent(intent, txHash, { recovering = false } = {}) {
  return db.transaction(() => {
  const payload = intent.payload;
  if (intent.operation === "RECORD_SUBMIT") {
    const record = { ...payload.record, transactionHash: txHash, transactionStatus: "confirmed" };
    db.saveRecord(record);
    actorAudit({ user: { address: intent.actor }, actorRole: "registrar" }, "Record submitted", record.id, txHash);
  } else if (intent.operation === "RECORD_VERIFY") {
    const record = db.getRecord(payload.recordId);
    if (record) {
      const label = roleSpecs[payload.department === "land" ? "landOffice" : "surveyOffice"].label;
      record.approvals = [...new Set([...(record.approvals || []), label])];
      record.transactionHash = txHash;
      record.transactionStatus = "confirmed";
      db.saveRecord(record);
      actorAudit({ user: { address: intent.actor }, actorRole: payload.department === "land" ? "landOffice" : "surveyOffice" }, "Department approved parcel", record.id, txHash);
    }
  } else if (intent.operation === "TRANSFER_REQUEST") {
    const record = db.getRecord(payload.recordId);
    if (record) {
      record.pendingTransfer = { newOwner: payload.newOwner, newOwnerHash: payload.newOwnerHash, approvals: [] };
      record.transactionHash = txHash;
      record.transactionStatus = "confirmed";
      db.saveRecord(record);
      actorAudit({ user: { address: intent.actor }, actorRole: "registrar" }, "Ownership transfer requested", record.id, txHash);
    }
  } else if (intent.operation === "TRANSFER_APPROVE") {
    const record = db.getRecord(payload.recordId);
    if (record?.pendingTransfer) {
      const roleKey = payload.department === "land" ? "landOffice" : "surveyOffice";
      const label = roleSpecs[roleKey].label;
      record.pendingTransfer.approvals = [...new Set([...(record.pendingTransfer.approvals || []), label])];
      if (record.pendingTransfer.approvals.length === 2) {
        record.owner = record.pendingTransfer.newOwner;
        record.pendingTransfer = null;
      }
      record.transactionHash = txHash;
      record.transactionStatus = "confirmed";
      db.saveRecord(record);
      actorAudit({ user: { address: intent.actor }, actorRole: roleKey }, "Transfer department approval", record.id, txHash);
    }
  } else if (intent.operation === "CLAIM_ISSUE" || intent.operation === "CLAIM_REVOKE") {
    actorAudit({ user: { address: intent.actor }, actorRole: "identityIssuer" }, intent.operation === "CLAIM_ISSUE" ? "PDS eligibility claim issued" : "PDS eligibility claim revoked", intent.subjectRef, txHash);
  } else if (intent.operation === "PDS_DELIVERY") {
    const beneficiary = db.getBeneficiary(payload.beneficiaryId);
    if (beneficiary) {
      beneficiary.delivered = true;
      beneficiary.receiptHash = txHash;
      db.saveBeneficiary(beneficiary);
      actorAudit({ user: { address: intent.actor }, actorRole: "welfareOffice" }, "PDS delivery recorded", beneficiary.id, txHash);
    }
  }
  db.finishIntent(intent.id, recovering ? "reconciled" : "confirmed");
  });
}

async function findEventReceipt(intent) {
  const p = intent.payload;
  const startBlock = Number(deployment.deployedBlock || 0);
  const filters = {
    RECORD_SUBMIT: () => registry.filters.RecordSubmitted(p.record.key),
    RECORD_VERIFY: () => registry.filters.RecordVerified(p.key, null, p.role),
    TRANSFER_REQUEST: () => registry.filters.TransferRequested(p.key, p.newOwnerHash),
    TRANSFER_APPROVE: () => registry.filters.TransferApproved(p.key, null, p.role),
    CLAIM_ISSUE: () => registry.filters.EligibilityClaimIssued(p.referenceHash, p.claimType),
    CLAIM_REVOKE: () => registry.filters.EligibilityClaimRevoked(p.referenceHash, p.claimType),
    PDS_DELIVERY: () => registry.filters.PdsDeliveryRecorded(p.referenceHash, p.cycleHash)
  };
  if (!filters[intent.operation]) return null;
  const logs = await readChain(() => registry.queryFilter(filters[intent.operation](), startBlock, "latest"));
  for (const log of logs.reverse()) {
    const receipt = await readChain(() => provider.getTransactionReceipt(log.transactionHash));
    if (receipt?.status === 1) return receipt;
  }
  return null;
}

async function reconcileIntents() {
  for (const intent of db.listOpenIntents()) {
    try {
      let receipt = intent.tx_hash ? await readChain(() => provider.getTransactionReceipt(intent.tx_hash)) : null;
      if (!receipt && !intent.tx_hash) receipt = await findEventReceipt(intent);
      if (receipt?.status === 1) applyIntent({ ...intent, id: intent.intent_id }, receipt.hash, { recovering: true });
      else if (receipt?.status === 0) db.finishIntent(intent.intent_id, "failed");
      else if (Date.now() - Date.parse(intent.created_at) > 10 * 60 * 1000) db.finishIntent(intent.intent_id, "expired");
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "intent_reconciliation_failed", intentId: intent.intent_id, code: error.code || "RECONCILE" }));
    }
  }
}

function responseCacheMiddleware(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method) || req.path.startsWith("/auth/")) return next();
  const key = req.get("Idempotency-Key");
  if (!key || key.length > 80 || !/^[A-Za-z0-9_-]{16,80}$/.test(key)) return res.status(400).json({ error: "A valid Idempotency-Key is required." });
  const scope = `${req.user.address.toLowerCase()}:${key}`;
  const requestHash = hashInput(`${req.method}\n${req.originalUrl}\n${JSON.stringify(req.body ?? {})}`);
  const existing = db.getIdempotency(scope);
  if (existing) {
    if (existing.request_hash !== requestHash) return res.status(409).json({ error: "Idempotency key was reused with a different request." });
    if (existing.status === "pending") return res.status(409).json({ error: "The original request is still being processed. Check its transaction status." });
    return res.status(existing.response?.statusCode || 200).json(existing.response?.payload || {});
  }
  try { db.beginIdempotency(scope, requestHash, Date.now() + 24 * 60 * 60 * 1000); }
  catch { return res.status(409).json({ error: "An identical request is already being processed." }); }
  req.idempotencyScope = scope;
  const originalJson = res.json.bind(res);
  res.json = (payload) => {
    try { db.finishIdempotency(scope, "complete", { statusCode: res.statusCode, payload }); }
    catch (error) { console.error(JSON.stringify({ level: "error", event: "idempotency_persist_failed", requestId: req.requestId, code: error.code || "DB_WRITE" })); }
    return originalJson(payload);
  };
  next();
}

async function main() {
  const network = await provider.getNetwork();
  if (network.chainId !== 31337n) throw new Error("Safety stop: local demo mode accepts only Hardhat chain 31337.");
  const code = await provider.getCode(deployment.address);
  if (code === "0x") throw new Error("The saved contract address has no code on the local chain. Redeploy the demo.");
  await reconcileIntents();
  db.pruneSessions();
  db.pruneIdempotency();

  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  app.use(securityHeaders);
  app.use((req, res, next) => {
    req.requestId = requestId();
    req.startedAt = Date.now();
    res.setHeader("X-Request-ID", req.requestId);
    res.setHeader("Cache-Control", "no-store");
    res.once("finish", () => console.log(JSON.stringify({ level: "info", event: "http_request", requestId: req.requestId, method: req.method, path: req.path, status: res.statusCode, durationMs: Date.now() - req.startedAt, actor: req.user?.address || null, role: req.actorRole || null })));
    next();
  });
  app.use(express.json({ limit: config.maxBodyBytes, strict: true, type: "application/json" }));
  app.use("/api", fixedWindowLimit({ name: "api-ip", windowMs: 60_000, max: 120 }));
  app.use("/api", (req, res, next) => {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
      const origin = req.get("Origin");
      if (origin !== config.origin) return res.status(403).json({ error: "Request origin is not allowed.", requestId: req.requestId });
      if (!req.is("application/json")) return res.status(415).json({ error: "Send JSON content for write requests.", requestId: req.requestId });
    }
    next();
  });
  app.get("/api/health/live", (_req, res) => res.json({ live: true }));
  app.get("/api/health/ready", async (_req, res) => {
    const started = Date.now();
    try {
      const [chainId, blockNumber, codeCheck] = await Promise.all([readChain(() => provider.getNetwork()), readChain(() => provider.getBlockNumber()), readChain(() => provider.getCode(deployment.address))]);
      if (chainId.chainId !== 31337n || codeCheck === "0x" || !db.quickCheck()) return res.status(503).json({ ready: false, requestId: _req.requestId });
      res.json({ ready: true, chainId: Number(chainId.chainId), blockNumber, rpcLatencyMs: Date.now() - started, database: "ready" });
    } catch { res.status(503).json({ ready: false, requestId: _req.requestId }); }
  });

  app.post("/api/auth/challenge", fixedWindowLimit({ name: "auth-challenge", windowMs: 60_000, max: 8 }), (req, res, next) => {
    try {
      const address = ethers.getAddress(requiredText(req.body.address, "Wallet address", 42));
      if (!ethers.isAddress(address)) return bad("Wallet address is invalid.");
      const now = Date.now();
      const nonce = crypto.randomBytes(24).toString("hex");
      const expiresAt = now + 5 * 60_000;
      const message = [
        "JanSetu wallet sign-in",
        `URI: ${config.origin}`,
        `Chain ID: ${deployment.chainId}`,
        `Address: ${address}`,
        `Nonce: ${nonce}`,
        `Issued At: ${new Date(now).toISOString()}`,
        `Expiration Time: ${new Date(expiresAt).toISOString()}`
      ].join("\n");
      db.putNonce(address, nonce, message, expiresAt);
      res.json({ address, message, expiresAt });
    } catch (error) { next(error); }
  });

  app.post("/api/auth/login", fixedWindowLimit({ name: "auth-login", windowMs: 60_000, max: 8 }), async (req, res, next) => {
    try {
      const address = ethers.getAddress(requiredText(req.body.address, "Wallet address", 42));
      const message = req.body.message;
      if (typeof message !== "string" || Buffer.byteLength(message, "utf8") > 1024 || message.includes("\0")) return bad("Sign-in message is invalid.");
      const signature = requiredText(req.body.signature, "Wallet signature", 200);
      const challenge = db.getNonce(address);
      if (!challenge || challenge.expires_at <= Date.now() || challenge.message !== message) return res.status(401).json({ error: "Sign-in challenge is missing, expired, or already used." });
      let recovered;
      try { recovered = ethers.verifyMessage(message, signature); } catch { return res.status(401).json({ error: "Wallet signature could not be verified." }); }
      if (recovered.toLowerCase() !== address.toLowerCase()) return res.status(401).json({ error: "Wallet signature does not match the address." });
      db.consumeNonce(address);
      const roles = await readRoles(address);
      if (roles.length === 0) return res.status(403).json({ error: "This wallet has no active JanSetu department role." });
      const session = auth.issue(res, address);
      res.json({ address, roles, csrfToken: session.csrfToken, expiresAt: session.expiresAt });
    } catch (error) { next(error); }
  });

  app.get("/api/auth/session", async (req, res, next) => {
    try {
      const session = auth.read(req);
      if (!session) return res.status(401).json({ error: "Sign in with an authorized wallet." });
      const roles = await readRoles(session.address);
      if (!roles.length) { auth.clear(res, session); return res.status(403).json({ error: "This wallet no longer has an active department role." }); }
      const csrfToken = crypto.randomBytes(24).toString("base64url");
      db.raw.prepare("UPDATE sessions SET csrf_hash=? WHERE token_hash=?").run(hashInput(csrfToken), session.tokenHash);
      res.json({ address: session.address, roles, csrfToken, expiresAt: session.expiresAt });
    } catch (error) { next(error); }
  });

  app.use("/api", (req, res, next) => {
    if (["/auth/challenge", "/auth/login", "/auth/session"].includes(req.path) || req.path.startsWith("/health/")) return next();
    const session = auth.read(req);
    if (!session) return res.status(401).json({ error: "Sign in with an authorized wallet.", requestId: req.requestId });
    req.user = { address: session.address, session };
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && !auth.verifyCsrf(session, req.get("X-CSRF-Token"))) return res.status(403).json({ error: "CSRF token is missing or invalid.", requestId: req.requestId });
    return userLimiter(req, res, next);
  });
  app.use("/api", responseCacheMiddleware);

  app.post("/api/auth/logout", (req, res) => {
    const session = auth.read(req);
    if (session) auth.clear(res, session);
    res.json({ loggedOut: true });
  });

  app.get("/api/status", async (req, res, next) => {
    try {
      const [blockNumber, net, roles] = await Promise.all([readChain(() => provider.getBlockNumber()), readChain(() => provider.getNetwork()), readRoles(req.user.address)]);
      res.json({ connected: true, network: "Local Hardhat demo", chainId: Number(net.chainId), blockNumber, contractAddress: deployment.address, deployedAt: deployment.deployedAt, address: req.user.address, roles, parcelCount: db.countRecords(), welfareCount: db.listBeneficiaries().length, rpc: { reads: rpcMetrics.reads, readErrors: rpcMetrics.readErrors, lastReadMs: rpcMetrics.lastReadMs, lastWriteMs: rpcMetrics.lastWriteMs } });
    } catch (error) { next(error); }
  });

  app.get("/api/records", async (req, res, next) => {
    try {
      const roles = await readRoles(req.user.address);
      if (!roles.some((role) => ["registrar", "landOffice", "surveyOffice"].includes(role))) return res.status(403).json({ error: "Land record access is not granted to this department." });
      const limit = page(req.query.limit, 50, 100), start = offset(req.query.offset), total = db.countRecords();
      res.json({ records: await currentRecords(limit, start), limit, offset: start, total, hasMore: start + limit < total });
    } catch (error) { next(error); }
  });

  app.post("/api/records", async (req, res, next) => {
    try {
      await requireActorRole(req, "registrar");
      const id = parcelId(req.body.id);
      if (db.getRecord(id)) return res.status(409).json({ error: "That parcel ID already exists." });
      const owner = ownerName(req.body.owner), village = villageName(req.body.village), documentRef = documentReference(req.body.documentRef), area = areaAcres(req.body.area);
      const key = privacy.digest("PARCEL_ID", id);
      const record = { id, key, owner, village, area: `${area.toFixed(2)} ac`, date: new Date().toLocaleString("en-IN"), documentRef, approvals: [], pendingTransfer: null, transactionStatus: "prepared" };
      const { transaction } = await executeIntent(req, "registrar", "RECORD_SUBMIT", id, { record }, (signer) => registry.connect(signer).submitRecord(key, privacy.digest("OWNER", owner), privacy.digest("DOCUMENT_PROOF", documentRef)));
      res.status(transaction.status === "confirmed" ? 201 : 202).json({ record: { ...record, status: "Pending", approvalCount: 0, transferPending: false }, transaction });
    } catch (error) { next(error); }
  });

  app.post("/api/records/:id/approve", async (req, res, next) => {
    try {
      const id = parcelId(req.params.id), dept = department(req.body.department);
      const roleKey = dept === "land" ? "landOffice" : "surveyOffice";
      await requireActorRole(req, roleKey);
      const record = db.getRecord(id);
      if (!record) return res.status(404).json({ error: "Parcel record was not found." });
      const role = await readChain(() => registry[roleSpecs[roleKey].roleFn]());
      const { transaction } = await executeIntent(req, roleKey, "RECORD_VERIFY", id, { recordId: id, department: dept, key: record.key, role }, (signer) => registry.connect(signer).verifyRecord(record.key, role));
      res.json({ record: (await currentRecords(100, Math.max(0, db.countRecords() - 100))).find((item) => item.id === id), transaction });
    } catch (error) { next(error); }
  });

  app.post("/api/transfers", async (req, res, next) => {
    try {
      await requireActorRole(req, "registrar");
      const id = parcelId(req.body.parcelId), newOwner = ownerName(req.body.newOwner), record = db.getRecord(id);
      if (!record) return res.status(404).json({ error: "Parcel record was not found." });
      if (record.pendingTransfer) return res.status(409).json({ error: "A transfer is already awaiting approvals." });
      const newOwnerHash = privacy.digest("OWNER", newOwner);
      const { transaction } = await executeIntent(req, "registrar", "TRANSFER_REQUEST", id, { recordId: id, newOwner, newOwnerHash, key: record.key }, (signer) => registry.connect(signer).requestTransfer(record.key, newOwnerHash));
      res.status(transaction.status === "confirmed" ? 201 : 202).json({ transaction });
    } catch (error) { next(error); }
  });

  app.post("/api/transfers/:id/approve", async (req, res, next) => {
    try {
      const id = parcelId(req.params.id), dept = department(req.body.department), roleKey = dept === "land" ? "landOffice" : "surveyOffice";
      await requireActorRole(req, roleKey);
      const record = db.getRecord(id);
      if (!record) return res.status(404).json({ error: "Parcel record was not found." });
      const role = await readChain(() => registry[roleSpecs[roleKey].roleFn]());
      const { transaction } = await executeIntent(req, roleKey, "TRANSFER_APPROVE", id, { recordId: id, department: dept, key: record.key, role }, (signer) => registry.connect(signer).approveTransfer(record.key, role));
      res.json({ transaction });
    } catch (error) { next(error); }
  });

  app.post("/api/identity/verify", async (req, res, next) => {
    try {
      const roles = await readRoles(req.user.address);
      if (!roles.some((role) => ["identityIssuer", "welfareOffice"].includes(role))) return res.status(403).json({ error: "Identity claim access is not granted to this department." });
      const ref = beneficiaryReference(req.body.referenceId), referenceHash = privacy.digest("BENEFICIARY", ref), claimType = await readChain(() => registry.PDS_ELIGIBILITY());
      const eligible = await readChain(() => registry.verifyEligibilityClaim(referenceHash, claimType));
      res.json({ eligible, claim: eligible ? "PDS eligibility" : null, issuer: eligible ? "District Identity Office" : null, networkVerified: true });
    } catch (error) { next(error); }
  });

  app.post("/api/identity/claims", async (req, res, next) => {
    try {
      await requireActorRole(req, "identityIssuer");
      const ref = beneficiaryReference(req.body.referenceId), valid = validDays(req.body.validDays), referenceHash = privacy.digest("BENEFICIARY", ref), claimType = await readChain(() => registry.PDS_ELIGIBILITY());
      const validUntil = BigInt(Math.floor(Date.now() / 1000) + valid * 86400);
      const { transaction } = await executeIntent(req, "identityIssuer", "CLAIM_ISSUE", referenceHash, { referenceHash, claimType, validDays: valid, validUntil: String(validUntil) }, (signer) => registry.connect(signer).issueEligibilityClaim(referenceHash, claimType, validUntil));
      res.status(transaction.status === "confirmed" ? 201 : 202).json({ eligible: true, validDays: valid, transaction });
    } catch (error) { next(error); }
  });

  app.delete("/api/identity/claims", async (req, res, next) => {
    try {
      await requireActorRole(req, "identityIssuer");
      const ref = beneficiaryReference(req.body.referenceId), referenceHash = privacy.digest("BENEFICIARY", ref), claimType = await readChain(() => registry.PDS_ELIGIBILITY());
      const { transaction } = await executeIntent(req, "identityIssuer", "CLAIM_REVOKE", referenceHash, { referenceHash, claimType }, (signer) => registry.connect(signer).revokeEligibilityClaim(referenceHash, claimType));
      res.json({ revoked: true, transaction });
    } catch (error) { next(error); }
  });

  app.get("/api/welfare", async (req, res, next) => {
    try {
      await requireActorRole(req, "welfareOffice");
      res.json({ beneficiaries: db.listBeneficiaries() });
    } catch (error) { next(error); }
  });

  app.post("/api/welfare/:id/deliver", async (req, res, next) => {
    try {
      await requireActorRole(req, "welfareOffice");
      const id = requiredText(req.params.id, "Beneficiary ID", 32), beneficiary = db.getBeneficiary(id);
      if (!beneficiary) return res.status(404).json({ error: "Beneficiary record was not found." });
      if (beneficiary.delivered) return res.status(409).json({ error: "A delivery receipt is already recorded for this cycle." });
      const refHash = privacy.digest("BENEFICIARY", beneficiary.referenceId), cycleHash = privacy.digest("PDS_CYCLE", cycle(beneficiary.cycle)), itemsHash = privacy.digest("PDS_ITEMS", requiredText(beneficiary.ration, "Entitlement", 120)), claimType = await readChain(() => registry.PDS_ELIGIBILITY());
      if (!await readChain(() => registry.verifyEligibilityClaim(refHash, claimType))) return res.status(403).json({ error: "No current eligibility claim exists on the ledger." });
      const { transaction } = await executeIntent(req, "welfareOffice", "PDS_DELIVERY", refHash, { beneficiaryId: id, referenceHash: refHash, cycleHash, itemsHash }, (signer) => registry.connect(signer).recordPdsDelivery(refHash, cycleHash, itemsHash));
      res.json({ beneficiary: { ...beneficiary, delivered: transaction.status === "confirmed", receiptHash: transaction.hash }, transaction });
    } catch (error) { next(error); }
  });

  app.get("/api/activity", async (req, res, next) => {
    try {
      const limit = page(req.query.limit, 50, 100), start = offset(req.query.offset);
      res.json({ activity: db.listAudit(limit, start), limit, offset: start });
    } catch (error) { next(error); }
  });

  app.get("/api/transactions/:id", async (req, res, next) => {
    try {
      const id = requiredText(req.params.id, "Transaction request", 100);
      if (!id.startsWith(`${req.user.address.toLowerCase()}:`)) return res.status(403).json({ error: "This transaction request belongs to another wallet." });
      const intent = db.getIntent(id);
      if (!intent) return res.status(404).json({ error: "Transaction request was not found." });
      if (["prepared", "submitted"].includes(intent.state)) {
        const receipt = intent.tx_hash ? await readChain(() => provider.getTransactionReceipt(intent.tx_hash)) : await findEventReceipt({ ...intent, id: intent.intent_id });
        if (receipt?.status === 1) applyIntent({ ...intent, id: intent.intent_id }, receipt.hash, { recovering: true });
        else if (receipt?.status === 0) db.finishIntent(intent.intent_id, "failed");
      }
      const current = db.getIntent(id);
      res.json({ status: current.state, transactionHash: current.tx_hash });
    } catch (error) { next(error); }
  });

  app.use(express.static(`${ROOT}/public`, {
    index: "index.html", etag: false, maxAge: 0,
    setHeaders: (res) => res.setHeader("Cache-Control", "no-store")
  }));
  app.use((_req, res) => res.status(404).json({ error: "Route not found." }));
  app.use(sendError);
  app.listen(config.port, config.host, () => console.log(JSON.stringify({ level: "info", event: "server_ready", host: config.host, port: config.port, chainId: Number(network.chainId), contractAddress: deployment.address, signerMode: config.signerMode })));
}

async function executeIntent(req, roleKey, operation, subjectRef, payload, sendTransaction) {
  return enqueueWrite(async () => {
    const { signer, spec } = await signerFor(req, roleKey);
    const intent = { id: req.idempotencyScope, actor: req.user.address.toLowerCase(), operation, subjectRef, payload };
    db.createIntent(intent);
    let tx;
    try {
      const started = Date.now();
      tx = await sendTransaction(signer);
      rpcMetrics.writes += 1;
      rpcMetrics.lastWriteMs = Date.now() - started;
      db.setIntentTx(intent.id, tx.hash);
      const receipt = await tx.wait(1, config.confirmationTimeoutMs);
      if (!receipt) {
        db.finishIntent(intent.id, "submitted");
        return { transaction: { hash: tx.hash, status: "pending", intentId: intent.id }, spec };
      }
      if (receipt.status !== 1) {
        db.finishIntent(intent.id, "failed");
        throw Object.assign(new Error("Blockchain transaction reverted."), { status: 409, code: "TX_REVERTED" });
      }
      applyIntent(intent, receipt.hash);
      return { transaction: { hash: receipt.hash, status: "confirmed", blockNumber: receipt.blockNumber, intentId: intent.id }, spec };
    } catch (error) {
      if (!tx) db.finishIntent(intent.id, "failed");
      else if (error.code !== "TX_REVERTED") {
        db.setIntentTx(intent.id, tx.hash);
        if (["TIMEOUT", "TIMEOUT_EXCEEDED"].includes(error.code)) {
          return { transaction: { hash: tx.hash, status: "pending", intentId: intent.id }, spec };
        }
      }
      throw error;
    }
  });
}

main().catch((error) => {
  console.error(JSON.stringify({ level: "fatal", event: "startup_failed", message: error.message, code: error.code || "STARTUP" }));
  process.exitCode = 1;
});
