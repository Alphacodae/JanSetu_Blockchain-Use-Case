const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function getHashKey(root) {
  const envValue = process.env.JANSETU_HASH_KEY;
  if (envValue) {
    const key = Buffer.from(envValue, "base64");
    if (key.length < 32) throw new Error("JANSETU_HASH_KEY must be a base64 encoded secret of at least 32 bytes.");
    return key;
  }
  if (process.env.NODE_ENV === "production") throw new Error("JANSETU_HASH_KEY must be provided by the production secret manager.");
  const directory = path.join(root, "data");
  const filename = path.join(directory, "demo-hash.key");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  try {
    const key = fs.readFileSync(filename);
    if (key.length < 32) throw new Error("Local demo hash key is invalid.");
    return key;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const key = crypto.randomBytes(32);
    const fd = fs.openSync(filename, "wx", 0o600);
    try { fs.writeFileSync(fd, key); } finally { fs.closeSync(fd); }
    return key;
  }
}

function createPrivacy(root) {
  const key = getHashKey(root);
  const dataKey = Buffer.from(crypto.hkdfSync("sha256", key, Buffer.from("jansetu-v1"), Buffer.from("offchain-data-encryption"), 32));
  return {
    digest(namespace, value) {
      if (!/^[A-Z][A-Z0-9_]{1,31}$/.test(namespace)) throw new Error("Invalid hash namespace.");
      const normalized = String(value).normalize("NFKC").trim().toUpperCase();
      return `0x${crypto.createHmac("sha256", key).update(`${namespace}\0${normalized}`, "utf8").digest("hex")}`;
    },
    encrypt(value) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, iv);
      const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
      return `v1:${iv.toString("base64url")}:${cipher.getAuthTag().toString("base64url")}:${ciphertext.toString("base64url")}`;
    },
    decrypt(value) {
      const [version, ivText, tagText, ciphertextText] = String(value).split(":");
      if (version !== "v1" || !ivText || !tagText || !ciphertextText) throw new Error("Encrypted datastore row is invalid.");
      const decipher = crypto.createDecipheriv("aes-256-gcm", dataKey, Buffer.from(ivText, "base64url"));
      decipher.setAuthTag(Buffer.from(tagText, "base64url"));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertextText, "base64url")), decipher.final()]);
      return JSON.parse(plaintext.toString("utf8"));
    }
  };
}

module.exports = { createPrivacy };
