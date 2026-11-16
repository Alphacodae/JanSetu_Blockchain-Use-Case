const hre = require("hardhat");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = hre;
const { createPrivacy } = require("../lib/privacy");
const { Database } = require("../lib/database");

async function main() {
  const [admin, landOffice, surveyOffice, identityIssuer, welfareOffice] = await ethers.getSigners();
  const root = path.resolve(__dirname, "..");
  const privacy = createPrivacy(root);
  const parcelId = (id) => privacy.digest("PARCEL_ID", id);
  const Factory = await ethers.getContractFactory("LandRegistry", admin);
  const registry = await Factory.deploy();
  await registry.waitForDeployment();
  const deploymentReceipt = await registry.deploymentTransaction().wait();
  const address = await registry.getAddress();

  await (await registry.grantRole(await registry.LAND_OFFICE_ROLE(), landOffice.address, ethers.id("DEMO:LAND-OFFICE"))).wait();
  await (await registry.grantRole(await registry.SURVEY_OFFICE_ROLE(), surveyOffice.address, ethers.id("DEMO:SURVEY-OFFICE"))).wait();
  await (await registry.grantRole(await registry.IDENTITY_ISSUER_ROLE(), identityIssuer.address, ethers.id("DEMO:IDENTITY-ISSUER"))).wait();
  await (await registry.grantRole(await registry.WELFARE_OPERATOR_ROLE(), welfareOffice.address, ethers.id("DEMO:WELFARE-OPERATOR"))).wait();

  const records = [
    { id: "LR-2026-00081", village: "Rampur, North District", owner: "Anita Sharma", area: 2.4, date: "Today", documentRef: "REG-DEMO-0081", verified: true },
    { id: "LR-2026-00082", village: "Kalyanpur, East District", owner: "Mohammed Iqbal", area: 1.85, date: "Today", documentRef: "REG-DEMO-0082", verified: false },
    { id: "LR-2026-00083", village: "Devgaon, South District", owner: "Priya Nair", area: 3.1, date: "Yesterday", documentRef: "REG-DEMO-0083", verified: true },
    { id: "LR-2026-00084", village: "Basantpur, West District", owner: "Ravi Patel", area: 0.95, date: "Yesterday", documentRef: "REG-DEMO-0084", verified: true }
  ];
  const audit = [];
  for (const record of records) {
    const idHash = parcelId(record.id);
    const submitted = await (await registry.submitRecord(
      idHash,
      privacy.digest("OWNER", record.owner),
      privacy.digest("DOCUMENT_PROOF", record.documentRef)
    )).wait();
    record.approvals = [];
    record.pendingTransfer = null;
    record.transactionHash = submitted.hash;
    if (record.verified) {
      const landReceipt = await (await registry.connect(landOffice).verifyRecord(idHash, await registry.LAND_OFFICE_ROLE())).wait();
      const surveyReceipt = await (await registry.connect(surveyOffice).verifyRecord(idHash, await registry.SURVEY_OFFICE_ROLE())).wait();
      record.approvals = ["Land office", "Survey office"];
      record.transactionHash = surveyReceipt.hash;
      audit.unshift({ action: "Record verified", subject: record.id, role: "Land office + Survey office", transactionHash: surveyReceipt.hash, timestamp: new Date().toISOString() });
      void landReceipt;
    } else {
      audit.unshift({ action: "Record submitted", subject: record.id, role: "District registrar", transactionHash: submitted.hash, timestamp: new Date().toISOString() });
    }
    record.key = idHash;
  }

  const welfare = [
    { id: "BEN-•••-0421", referenceId: "DEMO-BENEFICIARY-0421", household: "Household · 4 members", shop: "FPS-018 · Rampur", ration: "Rice 20 kg · Wheat 10 kg", cycle: "2026-11", delivered: true },
    { id: "BEN-•••-8173", referenceId: "DEMO-BENEFICIARY-8173", household: "Household · 3 members", shop: "FPS-022 · Kalyanpur", ration: "Rice 15 kg · Wheat 8 kg", cycle: "2026-11", delivered: false },
    { id: "BEN-•••-2095", referenceId: "DEMO-BENEFICIARY-2095", household: "Household · 5 members", shop: "FPS-018 · Rampur", ration: "Rice 25 kg · Wheat 12 kg", cycle: "2026-11", delivered: false },
    { id: "BEN-•••-6518", referenceId: "DEMO-BENEFICIARY-6518", household: "Household · 2 members", shop: "FPS-031 · Devgaon", ration: "Rice 10 kg · Wheat 6 kg", cycle: "2026-11", delivered: false }
  ];
  const claimType = await registry.PDS_ELIGIBILITY();
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);
  for (const beneficiary of welfare) {
    const referenceHash = privacy.digest("BENEFICIARY", beneficiary.referenceId);
    await (await registry.connect(identityIssuer).issueEligibilityClaim(referenceHash, claimType, expiry)).wait();
    if (beneficiary.delivered) {
      const cycleHash = privacy.digest("PDS_CYCLE", beneficiary.cycle);
      const itemsHash = privacy.digest("PDS_ITEMS", beneficiary.ration);
      const receipt = await (await registry.connect(welfareOffice).recordPdsDelivery(referenceHash, cycleHash, itemsHash)).wait();
      beneficiary.receiptHash = receipt.hash;
      audit.unshift({ action: "PDS delivery recorded", subject: beneficiary.id, role: "Fair price shop", transactionHash: receipt.hash, timestamp: new Date().toISOString() });
    }
  }

  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  fs.writeFileSync(path.join(root, "deployment.local.json"), JSON.stringify({
    address,
    chainId: 31337,
    deployedAt: new Date().toISOString(),
    deployedBlock: deploymentReceipt.blockNumber,
    deployer: admin.address,
    roles: { registrar: admin.address, landOffice: landOffice.address, surveyOffice: surveyOffice.address, identityIssuer: identityIssuer.address, welfareOffice: welfareOffice.address }
  }, null, 2));
  const db = new Database(path.join(root, "data", "jansetu.sqlite"), privacy);
  db.resetDemoData({ records, welfare, audit });
  db.close();

  console.log(`JanSetu registry: ${address}`);
  console.log(`Role accounts: registrar ${admin.address}; land ${landOffice.address}; survey ${surveyOffice.address}; identity ${identityIssuer.address}; welfare ${welfareOffice.address}`);
  console.log("Seeded 4 parcel records, 4 fake PDS claims and 1 delivery receipt.");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
