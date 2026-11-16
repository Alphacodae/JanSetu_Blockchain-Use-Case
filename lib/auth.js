const crypto = require("node:crypto");

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
function parseCookies(header = "") {
  const result = Object.create(null);
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (/^[A-Za-z0-9_-]{1,64}$/.test(key)) {
      try { result[key] = decodeURIComponent(value); } catch { result[key] = ""; }
    }
  }
  return result;
}

function createAuth(db, { cookieName = "jansetu_session", secureCookie = false, ttlMs = 8 * 60 * 60 * 1000 } = {}) {
  function read(req) {
    const token = parseCookies(req.headers.cookie)[cookieName];
    if (!token || token.length > 128) return null;
    const row = db.getSession(sha256(token));
    return row ? { address: row.address, csrfHash: row.csrf_hash, tokenHash: sha256(token), expiresAt: row.expires_at } : null;
  }
  function issue(res, address) {
    const token = crypto.randomBytes(32).toString("base64url");
    const csrf = crypto.randomBytes(24).toString("base64url");
    const expiresAt = Date.now() + ttlMs;
    const tokenHash = sha256(token);
    db.saveSession(tokenHash, address, sha256(csrf), expiresAt);
    const attributes = [`${cookieName}=${encodeURIComponent(token)}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${Math.floor(ttlMs / 1000)}`];
    if (secureCookie) attributes.push("Secure");
    res.append("Set-Cookie", attributes.join("; "));
    return { csrfToken: csrf, expiresAt };
  }
  function verifyCsrf(session, token) {
    if (!session || typeof token !== "string" || token.length > 128) return false;
    const expected = Buffer.from(session.csrfHash, "hex");
    const actual = Buffer.from(sha256(token), "hex");
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  }
  function clear(res, session) {
    if (session) db.deleteSession(session.tokenHash);
    const attributes = [`${cookieName}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
    if (secureCookie) attributes.push("Secure");
    res.append("Set-Cookie", attributes.join("; "));
  }
  return { read, issue, verifyCsrf, clear, sha256, ttlMs };
}

module.exports = { createAuth, sha256, parseCookies };
