const assert = require("node:assert/strict");
const { ethers, network } = require("hardhat");

describe("LandRegistry governance and workflows", function () {
  let contract, admin, registrar, land, survey, issuer, welfare, outsider;
  const parcel = ethers.id("LR-TEST-1");
  const owner = ethers.id("OWNER-1");
  const proof = ethers.id("DOC-1");

  beforeEach(async function () {
    [admin, registrar, land, survey, issuer, welfare, outsider] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("LandRegistry", admin);
    contract = await Factory.deploy();
    await contract.waitForDeployment();
    await contract.grantRole(await contract.REGISTRAR_ROLE(), registrar.address, ethers.id("TEST:REGISTRAR"));
    await contract.grantRole(await contract.LAND_OFFICE_ROLE(), land.address, ethers.id("TEST:LAND"));
    await contract.grantRole(await contract.SURVEY_OFFICE_ROLE(), survey.address, ethers.id("TEST:SURVEY"));
    await contract.grantRole(await contract.IDENTITY_ISSUER_ROLE(), issuer.address, ethers.id("TEST:IDENTITY"));
    await contract.grantRole(await contract.WELFARE_OPERATOR_ROLE(), welfare.address, ethers.id("TEST:WELFARE"));
  });

  it("enforces role boundaries and prevents role collapse", async function () {
    await assert.rejects(contract.connect(outsider).submitRecord(parcel, owner, proof));
    await assert.rejects(contract.grantRole(await contract.SURVEY_OFFICE_ROLE(), land.address, ethers.id("TEST:BAD")));
    await assert.rejects(contract.connect(outsider).revokeRole(await contract.LAND_OFFICE_ROLE(), land.address, ethers.id("TEST:BAD")));
    await contract.grantRole(await contract.LAND_OFFICE_ROLE(), outsider.address, ethers.id("TEST:LAND-ROTATE"));
    await contract.revokeRole(await contract.LAND_OFFICE_ROLE(), land.address, ethers.id("TEST:ROTATE"));
    assert.equal(await contract.hasRole(await contract.LAND_OFFICE_ROLE(), land.address), false);
  });

  it("requires two distinct departments for record approval", async function () {
    await contract.connect(registrar).submitRecord(parcel, owner, proof);
    await contract.connect(land).verifyRecord(parcel, await contract.LAND_OFFICE_ROLE());
    await assert.rejects(contract.connect(land).verifyRecord(parcel, await contract.LAND_OFFICE_ROLE()));
    await assert.rejects(contract.connect(land).verifyRecord(parcel, await contract.SURVEY_OFFICE_ROLE()));
    assert.equal(Number((await contract.getParcel(parcel))[2]), 1);
    await contract.connect(survey).verifyRecord(parcel, await contract.SURVEY_OFFICE_ROLE());
    assert.equal(Number((await contract.getParcel(parcel))[2]), 2);
  });

  it("requires a verified parcel and two approvals for transfers", async function () {
    await contract.connect(registrar).submitRecord(parcel, owner, proof);
    await assert.rejects(contract.connect(registrar).requestTransfer(parcel, ethers.id("OWNER-2")));
    await contract.connect(land).verifyRecord(parcel, await contract.LAND_OFFICE_ROLE());
    await contract.connect(survey).verifyRecord(parcel, await contract.SURVEY_OFFICE_ROLE());
    const nextOwner = ethers.id("OWNER-2");
    await contract.connect(registrar).requestTransfer(parcel, nextOwner);
    await contract.connect(land).approveTransfer(parcel, await contract.LAND_OFFICE_ROLE());
    await assert.rejects(contract.connect(land).approveTransfer(parcel, await contract.SURVEY_OFFICE_ROLE()));
    await contract.connect(survey).approveTransfer(parcel, await contract.SURVEY_OFFICE_ROLE());
    assert.equal((await contract.getParcel(parcel))[0], nextOwner);
    assert.equal((await contract.getParcel(parcel))[5], ethers.ZeroHash);
  });

  it("rejects expired claims and duplicate monthly delivery receipts", async function () {
    const reference = ethers.id("BEN-TEST"), claim = await contract.PDS_ELIGIBILITY();
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    await contract.connect(issuer).issueEligibilityClaim(reference, claim, now + 3600);
    await contract.connect(welfare).recordPdsDelivery(reference, ethers.id("2026-11"), ethers.id("RICE-1"));
    await assert.rejects(contract.connect(welfare).recordPdsDelivery(reference, ethers.id("2026-11"), ethers.id("RICE-1")));
    await network.provider.send("evm_increaseTime", [3601]);
    await network.provider.send("evm_mine");
    await assert.rejects(contract.connect(welfare).recordPdsDelivery(reference, ethers.id("2026-12"), ethers.id("RICE-2")));
  });

  it("prevents accidental last-role loss and uses a two-step admin handoff", async function () {
    const registrarRole = await contract.REGISTRAR_ROLE();
    await assert.rejects(contract.revokeRole(registrarRole, admin.address, ethers.id("TEST:ADMIN")));
    await contract.proposeAdmin(outsider.address);
    assert.equal(await contract.admin(), admin.address);
    await contract.connect(outsider).acceptAdmin();
    assert.equal(await contract.admin(), outsider.address);
    assert.equal(await contract.hasRole(registrarRole, outsider.address), true);
    assert.equal(await contract.hasRole(registrarRole, admin.address), false);
  });
});
