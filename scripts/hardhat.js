// Keep Hardhat's writable config and cache under this project workspace.
const path = require("node:path");
const root = path.resolve(__dirname, "..");
process.env.APPDATA = path.join(root, ".runtime");
process.env.LOCALAPPDATA = path.join(root, ".runtime-local");
process.env.XDG_CONFIG_HOME = path.join(root, ".runtime", "config");
process.env.XDG_DATA_HOME = path.join(root, ".runtime", "data");
process.env.XDG_CACHE_HOME = path.join(root, ".runtime-local", "cache");
require(require.resolve("hardhat/internal/cli/cli"));
