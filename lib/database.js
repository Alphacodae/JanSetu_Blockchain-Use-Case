const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

class Database {
  constructor(filename, privacy = null) {
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    this.raw = new DatabaseSync(filename);
    this.privacy = privacy;
    this.raw.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
    this.raw.exec(`
      CREATE TABLE IF NOT EXISTS records (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        key TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS records_created_idx ON records(created_at DESC);
      CREATE TABLE IF NOT EXISTS beneficiaries (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        tx_hash TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS audit_created_idx ON audit(seq DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS audit_tx_event_idx ON audit(tx_hash,action,subject_ref) WHERE tx_hash IS NOT NULL;
      CREATE TABLE IF NOT EXISTS auth_nonces (
        address TEXT PRIMARY KEY,
        nonce TEXT NOT NULL,
        message TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        address TEXT NOT NULL,
        csrf_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
      CREATE TABLE IF NOT EXISTS idempotency (
        scope_key TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        response_json TEXT,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tx_intents (
        intent_id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        operation TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        tx_hash TEXT,
        state TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tx_intents_state_idx ON tx_intents(state);
    `);
  }

  encode(value) { return this.privacy ? this.privacy.encrypt(value) : JSON.stringify(value); }
  decode(value) { return this.privacy ? this.privacy.decrypt(value) : JSON.parse(value); }
  decodeProtected(value) {
    if (this.privacy && String(value).startsWith("v1:")) return this.privacy.decrypt(value);
    try { return JSON.parse(value); } catch { return value; }
  }

  transaction(operation) {
    this.raw.exec("BEGIN IMMEDIATE");
    try { const result = operation(); this.raw.exec("COMMIT"); return result; }
    catch (error) { this.raw.exec("ROLLBACK"); throw error; }
  }

  resetDemoData({ records, welfare, audit }) {
    this.transaction(() => {
      this.raw.exec("DELETE FROM records; DELETE FROM beneficiaries; DELETE FROM audit; DELETE FROM auth_nonces; DELETE FROM sessions; DELETE FROM idempotency; DELETE FROM tx_intents;");
      const putRecord = this.raw.prepare("INSERT INTO records(id,key,created_at,data) VALUES(?,?,?,?)");
      for (const item of records) putRecord.run(item.id, item.key, item.date || new Date().toISOString(), this.encode(item));
      const putBeneficiary = this.raw.prepare("INSERT INTO beneficiaries(id,data) VALUES(?,?)");
      for (const item of welfare) putBeneficiary.run(item.id, this.encode(item));
    const putAudit = this.raw.prepare("INSERT OR IGNORE INTO audit(actor,role,action,subject_ref,tx_hash,created_at) VALUES(?,?,?,?,?,?)");
      for (const item of audit) putAudit.run(item.actor || "system:seed", item.role, item.action, this.encode(item.subjectRef || item.subject), item.transactionHash || null, item.timestamp || new Date().toISOString());
    });
  }

  listRecords(limit = 50, offset = 0) {
    return this.raw.prepare("SELECT data FROM records ORDER BY seq DESC LIMIT ? OFFSET ?").all(limit, offset).map((row) => this.decode(row.data));
  }
  countRecords() { return Number(this.raw.prepare("SELECT COUNT(*) AS count FROM records").get().count); }
  getRecord(id) {
    const row = this.raw.prepare("SELECT data FROM records WHERE id=?").get(id);
    return row ? this.decode(row.data) : null;
  }
  saveRecord(record) {
    this.raw.prepare(`INSERT INTO records(id,key,created_at,data) VALUES(?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET key=excluded.key, data=excluded.data`).run(record.id, record.key, record.date || new Date().toISOString(), this.encode(record));
  }
  listBeneficiaries() { return this.raw.prepare("SELECT data FROM beneficiaries ORDER BY seq").all().map((row) => this.decode(row.data)); }
  getBeneficiary(id) {
    const row = this.raw.prepare("SELECT data FROM beneficiaries WHERE id=?").get(id);
    return row ? this.decode(row.data) : null;
  }
  saveBeneficiary(item) {
    this.raw.prepare(`INSERT INTO beneficiaries(id,data) VALUES(?,?)
      ON CONFLICT(id) DO UPDATE SET data=excluded.data`).run(item.id, this.encode(item));
  }
  appendAudit({ actor, role, action, subjectRef, txHash, timestamp = new Date().toISOString() }) {
    this.raw.prepare("INSERT OR IGNORE INTO audit(actor,role,action,subject_ref,tx_hash,created_at) VALUES(?,?,?,?,?,?)")
      .run(actor, role, action, this.encode(subjectRef), txHash || null, timestamp);
    return this.listAudit(100);
  }
  listAudit(limit = 100, offset = 0) {
    return this.raw.prepare("SELECT actor,role,action,subject_ref AS subject,tx_hash AS transactionHash,created_at AS timestamp FROM audit ORDER BY seq DESC LIMIT ? OFFSET ?")
      .all(limit, offset).map((row) => ({ ...row, subject: this.decodeProtected(row.subject) }));
  }

  putNonce(address, nonce, message, expiresAt) {
    this.raw.prepare(`INSERT INTO auth_nonces(address,nonce,message,expires_at) VALUES(?,?,?,?)
      ON CONFLICT(address) DO UPDATE SET nonce=excluded.nonce,message=excluded.message,expires_at=excluded.expires_at`)
      .run(address.toLowerCase(), nonce, message, expiresAt);
  }
  getNonce(address) { return this.raw.prepare("SELECT * FROM auth_nonces WHERE address=?").get(address.toLowerCase()) || null; }
  consumeNonce(address) { this.raw.prepare("DELETE FROM auth_nonces WHERE address=?").run(address.toLowerCase()); }
  saveSession(tokenHash, address, csrfHash, expiresAt) {
    this.raw.prepare("INSERT INTO sessions(token_hash,address,csrf_hash,expires_at) VALUES(?,?,?,?)").run(tokenHash, address.toLowerCase(), csrfHash, expiresAt);
  }
  getSession(tokenHash) { return this.raw.prepare("SELECT * FROM sessions WHERE token_hash=? AND expires_at>? ").get(tokenHash, Date.now()) || null; }
  deleteSession(tokenHash) { this.raw.prepare("DELETE FROM sessions WHERE token_hash=?").run(tokenHash); }
  pruneSessions() { this.raw.prepare("DELETE FROM sessions WHERE expires_at<=?").run(Date.now()); }

  getIdempotency(scopeKey) {
    const row = this.raw.prepare("SELECT * FROM idempotency WHERE scope_key=? AND expires_at>? ").get(scopeKey, Date.now());
    return row ? { ...row, response: row.response_json ? this.decode(row.response_json) : null } : null;
  }
  beginIdempotency(scopeKey, requestHash, expiresAt) {
    this.raw.prepare("INSERT INTO idempotency(scope_key,request_hash,status,expires_at) VALUES(?,?,'pending',?)").run(scopeKey, requestHash, expiresAt);
  }
  finishIdempotency(scopeKey, status, response) {
    this.raw.prepare("UPDATE idempotency SET status=?,response_json=? WHERE scope_key=?").run(status, this.encode(response), scopeKey);
  }
  removeIdempotency(scopeKey) { this.raw.prepare("DELETE FROM idempotency WHERE scope_key=?").run(scopeKey); }
  pruneIdempotency() { this.raw.prepare("DELETE FROM idempotency WHERE expires_at<=?").run(Date.now()); }

  createIntent(intent) {
    const now = new Date().toISOString();
    this.raw.prepare(`INSERT INTO tx_intents(intent_id,actor,operation,subject_ref,payload_json,state,created_at,updated_at)
      VALUES(?,?,?,?,?,'prepared',?,?)`).run(intent.id, intent.actor, intent.operation, this.encode(intent.subjectRef), this.encode(intent.payload), now, now);
  }
  setIntentTx(intentId, txHash) {
    this.raw.prepare("UPDATE tx_intents SET tx_hash=?,state='submitted',updated_at=? WHERE intent_id=?")
      .run(txHash, new Date().toISOString(), intentId);
  }
  finishIntent(intentId, state) {
    this.raw.prepare("UPDATE tx_intents SET state=?,updated_at=? WHERE intent_id=?")
      .run(state, new Date().toISOString(), intentId);
  }
  listOpenIntents() { return this.raw.prepare("SELECT * FROM tx_intents WHERE state IN ('prepared','submitted') ORDER BY created_at").all().map((row) => ({ ...row, payload: this.decode(row.payload_json) })); }
  getIntent(id) {
    const row = this.raw.prepare("SELECT * FROM tx_intents WHERE intent_id=?").get(id);
    return row ? { ...row, payload: this.decode(row.payload_json) } : null;
  }
  quickCheck() { return this.raw.prepare("PRAGMA quick_check").get().quick_check === "ok"; }
  close() { this.raw.close(); }
}

module.exports = { Database };
