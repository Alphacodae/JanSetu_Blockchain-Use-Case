const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

async function main() {
  const root = path.resolve(__dirname, "..");
  const deployment = JSON.parse(fs.readFileSync(path.join(root, "deployment.local.json"), "utf8"));
  const origin = process.env.APP_ORIGIN || "http://127.0.0.1:4173";
  const rpc = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545", 31337, { staticNetwork: true });
  async function login(address) {
    const challengeResponse = await fetch(`${origin}/api/auth/challenge`, {
      method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ address })
    });
    if (!challengeResponse.ok) throw new Error(`Challenge failed: HTTP ${challengeResponse.status}`);
    const challenge = await challengeResponse.json();
    const signature = await rpc.send("personal_sign", [ethers.hexlify(ethers.toUtf8Bytes(challenge.message)), address]);
    const loginResponse = await fetch(`${origin}/api/auth/login`, {
      method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ address, message: challenge.message, signature })
    });
    if (!loginResponse.ok) throw new Error(`Wallet login failed: HTTP ${loginResponse.status} ${(await loginResponse.text()).slice(0, 240)}`);
    const session = await loginResponse.json();
    const cookie = loginResponse.headers.getSetCookie?.()[0]?.split(";")[0];
    if (!cookie) throw new Error("The API did not issue a session cookie.");
    return { session, cookie };
  }
  async function checkRole(name, address, recordsStatus, welfareStatus) {
    const { session, cookie } = await login(address);
    const records = await fetch(`${origin}/api/records?limit=4`, { headers: { Cookie: cookie } });
    const welfare = await fetch(`${origin}/api/welfare`, { headers: { Cookie: cookie } });
    if (records.status !== recordsStatus || welfare.status !== welfareStatus) throw new Error(`${name} access checks returned unexpected HTTP statuses (${records.status}, ${welfare.status}).`);
    if (name === "registrar") {
      const data = await records.json();
      if (data.records.length !== 4 || data.total !== 4 || !data.records.some((record) => record.status === "Pending")) throw new Error(`Seeded land data mismatch: total=${data.total}, page=${data.records.map((record) => `${record.id}:${record.status}`).join(",")}`);
    }
    if (name === "welfareOffice") {
      const data = await welfare.json();
      if (data.beneficiaries.length !== 4 || !data.beneficiaries.some((beneficiary) => !beneficiary.delivered)) throw new Error("Seeded welfare content did not load with the expected pending delivery.");
    }
    return { role: name, authenticatedAs: session.roles.join(","), landAccess: records.status, welfareAccess: welfare.status };
  }
  const checks = [];
  for (const [name, recordCode, welfareCode] of [["registrar",200,403],["landOffice",200,403],["surveyOffice",200,403],["identityIssuer",403,403],["welfareOffice",403,200]]) {
    checks.push(await checkRole(name, deployment.roles[name], recordCode, welfareCode));
  }
  const pageResponse = await fetch(origin);
  const page = await pageResponse.text();
  if (!pageResponse.ok || !page.includes("themeToggle") || !page.includes("authGate")) throw new Error("The static application did not load required theme/auth UI.");
  const csp = pageResponse.headers.get("content-security-policy");
  if (!csp || csp.includes("unsafe-inline")) throw new Error("The application response is missing the strict content security policy.");
  const styles = await fetch(`${origin}/styles.css`);
  const stylesheet = await styles.text();
  if (!styles.ok || !stylesheet.includes(":root[data-theme=dark]") || !stylesheet.includes("Segoe UI")) throw new Error("The theme stylesheet or system-font typography did not load.");
  console.log(JSON.stringify({ ok: true, deployment: deployment.address, chainId: deployment.chainId, roles: checks, ui: "loaded", csp: "strict" }, null, 2));
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
