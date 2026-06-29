import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

import { deploySystem, registerOrgAndGetId } from "./helpers/fixtures";

describe("Upgrade safety", () => {
  it("OZ upgrades plugin validates UUPS storage layout for OrganizationRegistry", async () => {
    const sys = await loadFixture(deploySystem);
    const Factory = await ethers.getContractFactory("OrganizationRegistry");
    // Upgrade to the same implementation as a smoke test of the upgrade path.
    await upgrades.upgradeProxy(await sys.orgRegistry.getAddress(), Factory, { kind: "uups" });
  });

  it("non-upgrader role cannot trigger upgradeToAndCall", async () => {
    const sys = await loadFixture(deploySystem);
    const Factory = await ethers.getContractFactory("OrganizationRegistry");
    const newImpl = await Factory.deploy();
    await newImpl.waitForDeployment();
    await expect(
      sys.orgRegistry.connect(sys.other).upgradeToAndCall(await newImpl.getAddress(), "0x")
    ).to.be.reverted;
  });

  it("UPGRADER_ROLE can call upgradeToAndCall", async () => {
    const sys = await loadFixture(deploySystem);
    const Factory = await ethers.getContractFactory("OrganizationRegistry");
    const newImpl = await Factory.deploy();
    await newImpl.waitForDeployment();
    await sys.orgRegistry
      .connect(sys.rootAdmin)
      .upgradeToAndCall(await newImpl.getAddress(), "0x");
  });

  it("DIDRegistry, SchemaRegistry, CredentialDefinitionRegistry, MerkleStateRegistry, Halo2VerifierRegistry all upgradable", async () => {
    const sys = await loadFixture(deploySystem);
    const pairs: [string, string][] = [
      ["DIDRegistry", await sys.didRegistry.getAddress()],
      ["SchemaRegistry", await sys.schemaRegistry.getAddress()],
      ["CredentialDefinitionRegistry", await sys.credDefRegistry.getAddress()],
      ["MerkleStateRegistry", await sys.merkleStateRegistry.getAddress()],
      ["Halo2VerifierRegistry", await sys.verifierRegistry.getAddress()],
    ];
    for (const [name, addr] of pairs) {
      const F = await ethers.getContractFactory(name);
      await upgrades.upgradeProxy(addr, F, { kind: "uups" });
    }
  });

  it("storage state is preserved across a same-impl upgrade", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const orgId = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Preserve Me Org", adminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgId);

    const Factory = await ethers.getContractFactory("OrganizationRegistry");
    await upgrades.upgradeProxy(await sys.orgRegistry.getAddress(), Factory, { kind: "uups" });

    // State must still be there post-upgrade
    const o = await sys.orgRegistry.getOrg(orgId);
    expect(o.did).to.equal("Preserve Me Org");
    expect(o.approved).to.equal(true);
  });

  it("implementation cannot be initialized directly (constructor disables initializers)", async () => {
    const Factory = await ethers.getContractFactory("OrganizationRegistry");
    const impl = await Factory.deploy();
    await impl.waitForDeployment();
    await expect(impl.initialize(await (await ethers.getSigners())[0].getAddress())).to.be.reverted;
  });
});
