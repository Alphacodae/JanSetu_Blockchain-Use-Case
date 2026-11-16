const crypto = require("node:crypto");

function requestId() { return crypto.randomUUID(); }

function securityHeaders(_req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'");
  next();
}

function fixedWindowLimit({ windowMs, max, name }) {
  const buckets = new Map();
  let lastPrune = Date.now();
  return (req, res, next) => {
    const now = Date.now();
    if (now - lastPrune > windowMs) {
      for (const [key, bucket] of buckets) if (bucket.endsAt <= now) buckets.delete(key);
      lastPrune = now;
    }
    if (buckets.size > 10000) return res.status(503).json({ error: "Rate limiter capacity reached." });
    const principal = req.user?.address?.toLowerCase() || req.socket.remoteAddress || "unknown";
    const key = `${name}:${principal}`;
    let bucket = buckets.get(key);
    if (!bucket || bucket.endsAt <= now) { bucket = { count: 0, endsAt: now + windowMs }; buckets.set(key, bucket); }
    bucket.count += 1;
    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, max - bucket.count)));
    res.setHeader("RateLimit-Reset", String(Math.ceil(bucket.endsAt / 1000)));
    if (bucket.count > max) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((bucket.endsAt - now) / 1000))));
      return res.status(429).json({ error: "Too many requests. Try again later.", requestId: req.requestId });
    }
    next();
  };
}

function sendError(error, _req, res, _next) {
  const known = Number.isInteger(error.status) && error.status >= 400 && error.status < 500;
  const status = known ? error.status : (error.code === "CALL_EXCEPTION" ? 409 : 500);
  const message = known ? error.message : (error.publicMessage || "The request could not be completed.");
  if (status >= 500) console.error(JSON.stringify({ level: "error", event: "request_failed", requestId: res.getHeader("X-Request-ID"), code: error.code || "INTERNAL" }));
  res.status(status).json({ error: message, requestId: res.getHeader("X-Request-ID") });
}

module.exports = { requestId, securityHeaders, fixedWindowLimit, sendError };
