const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const validation = require("../lib/validation");
const { Database } = require("../lib/database");
const { sendError } = require("../lib/http-security");

function withDatabase(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "jansetu-test-"));
  const key = Buffer.alloc(32, 7);
  const privacy = {
    encrypt(value) { return `v1:${Buffer.from(JSON.stringify(value)).toString("base64")}`; },
    decrypt(value) { return JSON.parse(Buffer.from(value.slice(3), "base64").toString()); }
  };
  const db = new Database(path.join(root, "demo.sqlite"), privacy);
  try { return run({ db, root }); }
  finally { db.close(); fs.rmSync(root, { recursive: true, force: true }); void key; }
}

test("validates and normalizes parcel and welfare inputs", () => {
  assert.equal(validation.parcelId(" lr-2026-00001 "), "LR-2026-00001");
  assert.equal(validation.cycle("Nov-2026"), "2026-11");
  assert.equal(validation.areaAcres("2.50"), 2.5);
  assert.throws(() => validation.beneficiaryReference("123456789012"), { status: 400 });
  assert.throws(() => validation.cycle("November 2026"), { status: 400 });
  assert.throws(() => validation.areaAcres("-1"), { status: 400 });
});

test("persists encrypted record state and paginates deterministically", () => withDatabase(({ db }) => {
  db.saveRecord({ id: "LR-1", key: "0x01", date: "2026-01-01", owner: "Synthetic Person" });
  db.saveRecord({ id: "LR-2", key: "0x02", date: "2026-01-02", owner: "Another Person" });
  assert.equal(db.countRecords(), 2);
  assert.equal(db.listRecords(1, 0)[0].id, "LR-2");
  assert.equal(db.getRecord("LR-1").owner, "Synthetic Person");
  const raw = db.raw.prepare("SELECT data FROM records WHERE id=?").get("LR-1").data;
  assert.equal(raw.includes("Synthetic Person"), false);
  db.appendAudit({ actor: "0xactor", role: "registrar", action: "submitted", subjectRef: "LR-SENSITIVE-1", txHash: "0xtx" });
  const auditRaw = db.raw.prepare("SELECT subject_ref FROM audit WHERE tx_hash=?").get("0xtx").subject_ref;
  assert.equal(auditRaw.includes("LR-SENSITIVE-1"), false);
  assert.equal(db.listAudit(1)[0].subject, "LR-SENSITIVE-1");
  assert.equal(db.quickCheck(), true);
}));

test("tracks idempotency and recoverable transaction intents", () => withDatabase(({ db }) => {
  db.beginIdempotency("actor:key-123456789012", "payload-hash", Date.now() + 60000);
  assert.equal(db.getIdempotency("actor:key-123456789012").status, "pending");
  db.finishIdempotency("actor:key-123456789012", "complete", { statusCode: 201, payload: { ok: true } });
  assert.deepEqual(db.getIdempotency("actor:key-123456789012").response, { statusCode: 201, payload: { ok: true } });
  db.createIntent({ id: "intent-1", actor: "0xactor", operation: "RECORD_SUBMIT", subjectRef: "LR-3", payload: { record: { id: "LR-3" } } });
  db.setIntentTx("intent-1", "0xtx");
  assert.equal(db.listOpenIntents()[0].payload.record.id, "LR-3");
  db.finishIntent("intent-1", "confirmed");
  assert.equal(db.listOpenIntents().length, 0);
}));


test("returns controlled API error responses for contract and internal failures", () => {
  const responseFor = (error) => {
    const response = { statusCode: 200, payload: null, status(code) { this.statusCode = code; return this; }, json(payload) { this.payload = payload; return this; }, getHeader() { return "request-test"; } };
    sendError(error, {}, response, () => {});
    return response;
  };
  const contract = responseFor(Object.assign(new Error("private RPC revert detail"), { code: "CALL_EXCEPTION" }));
  assert.equal(contract.statusCode, 409);
  assert.equal(contract.payload.error, "The request could not be completed.");
  const internal = responseFor(new Error("internal secret detail"));
  assert.equal(internal.statusCode, 500);
  assert.equal(internal.payload.error, "The request could not be completed.");
});
