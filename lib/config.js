const path = require("node:path");
const dotenv = require("dotenv");

function loadConfig(root) {
  dotenv.config({ path: path.join(root, ".env") });
  const nodeEnv = process.env.NODE_ENV || "development";
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 4173);
  const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
  const origin = process.env.APP_ORIGIN || `http://${host}:${port}`;
  const signerMode = process.env.SIGNER_MODE || "local-hardhat";
  if (nodeEnv === "production") throw new Error("Production startup is disabled until a managed signer, HTTPS origin, and deployment datastore are configured.");
  if (signerMode !== "local-hardhat") throw new Error("This build supports the local-hardhat signer only; managed signer support must be configured before deployment.");
  if (host !== "127.0.0.1" && host !== "localhost") throw new Error("The local-hardhat signer may only bind to loopback.");
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("PORT must be an integer between 1024 and 65535.");
  const originUrl = new URL(origin);
  if (originUrl.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(originUrl.hostname) || originUrl.username || originUrl.password || originUrl.pathname !== "/") throw new Error("APP_ORIGIN must be an HTTP loopback origin for local demo mode.");
  const rpc = new URL(rpcUrl);
  if (rpc.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(rpc.hostname) || rpc.username || rpc.password) throw new Error("RPC_URL must target a local HTTP RPC in local demo mode.");
  return {
    root, nodeEnv, host, port, rpcUrl, origin: originUrl.origin, signerMode,
    databaseFile: path.resolve(root, process.env.DATABASE_FILE || "data/jansetu.sqlite"),
    deploymentFile: path.resolve(root, process.env.DEPLOYMENT_FILE || "deployment.local.json"),
    sessionTtlMs: 8 * 60 * 60 * 1000,
    confirmationTimeoutMs: 30000,
    maxBodyBytes: "16kb"
  };
}

module.exports = { loadConfig };
