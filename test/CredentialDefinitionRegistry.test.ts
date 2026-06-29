import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256 } from "ethers";

import { deploySystem, setupApprovedOrg, DeployedSystem } from "./helpers/fixtures";

describe("CredentialDefinitionRegistry", () => {
  const schemaId = keccak256(ethers.toUtf8Bytes("KYC-v1"));
  const credDefId = keccak256(ethers.toUtf8Bytes("KYC-v1-issuer-1"));
  const schemaHash = keccak256(ethers.toUtf8Bytes("schema-content"));
  const uri = "ipfs://Qm-schema-v1";
  const issuerPubKey = ethers.hexlify(ethers.randomBytes(96)); // BLS12-381 G2 compressed

  async function setupSchema(sys: DeployedSystem): Promise<string> {
    const orgId = await setupApprovedOrg(sys, [sys.member1]);
    await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri);
    return orgId;
  }

  describe("registerCredentialDefinition", () => {
    it("org member can register; emits event", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.member1)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n)
      )
        .to.emit(sys.credDefRegistry, "CredentialDefinitionRegistered")
        .withArgs(credDefId, schemaId, orgId, 1);
      const cd = await sys.credDefRegistry.getCredentialDefinition(credDefId);
      expect(cd.schemaId).to.equal(schemaId);
      expect(cd.issuerOrg).to.equal(orgId);
      expect(cd.policyMask).to.equal(1);
      expect(cd.deprecated).to.equal(false);
    });

    it("non-member is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.other)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "NotIssuerOrgMember");
    });

    it("requires schema to be active", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupSchema(sys);
      await sys.schemaRegistry.connect(sys.orgAdmin).deprecateSchema(schemaId);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "SchemaNotActive");
    });

    it("rejects empty issuer pubkey", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, "0x", 1, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "EmptyIssuerPubKey");
    });

    it("rejects invalid policy mask (zero or > TIER_ALL)", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 0, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidPolicyMask");
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 4, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidPolicyMask");
    });

    it("Mode A credDef with non-zero Tier 2 key is rejected (UnexpectedIssuerZkPubKey)", async () => {
      // Sanity check that the new gating does NOT relax Mode A — a Tier 1-only
      // credDef must not silently accept a stray ZK key.
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 1n, 2n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "UnexpectedIssuerZkPubKey");
    });

    it("Mode B credDef with (0, 0) Tier 2 key is rejected (InvalidIssuerZkPubKey)", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 2, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidIssuerZkPubKey");
    });

    it("Mode B credDef with the BabyJubjub identity (0, 1) is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 2, "", 0n, 1n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidIssuerZkPubKey");
    });

    it("Mode B credDef with coord >= BN254 scalar field is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 2, "", p, 2n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidIssuerZkPubKey");
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 2, "", 1n, p + 1n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "InvalidIssuerZkPubKey");
    });

    it("Mode B credDef stores + exposes the Tier 2 key via getIssuerZkPubKey", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 2, "", 42n, 99n);
      const k = await sys.credDefRegistry.getIssuerZkPubKey(credDefId);
      expect(k.ax).to.equal(42n);
      expect(k.ay).to.equal(99n);
      expect(k.set).to.equal(true);
    });

    it("Mode A credDef leaves the Tier 2 key slot unset", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);
      const k = await sys.credDefRegistry.getIssuerZkPubKey(credDefId);
      expect(k.ax).to.equal(0n);
      expect(k.ay).to.equal(0n);
      expect(k.set).to.equal(false);
    });

    it("rejects duplicate credDefId", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "CredDefAlreadyExists");
    });

    it("supportsTier returns correct flags", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      // Tier 1 only
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);
      expect(await sys.credDefRegistry.supportsTier(credDefId, 1)).to.equal(true);
      expect(await sys.credDefRegistry.supportsTier(credDefId, 2)).to.equal(false);
      expect(await sys.credDefRegistry.supportsTier(credDefId, 3)).to.equal(false);

      // Both tiers
      const otherCredDef = keccak256(ethers.toUtf8Bytes("KYC-v1-issuer-2"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(otherCredDef, schemaId, issuerPubKey, 3, "", 1n, 2n);
      expect(await sys.credDefRegistry.supportsTier(otherCredDef, 1)).to.equal(true);
      expect(await sys.credDefRegistry.supportsTier(otherCredDef, 2)).to.equal(true);
    });
  });

  describe("deprecateCredentialDefinition", () => {
    it("org member can deprecate; supportsTier flips to false", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 3, "", 1n, 2n);
      await sys.credDefRegistry.connect(sys.orgAdmin).deprecateCredentialDefinition(credDefId);
      expect(await sys.credDefRegistry.isActive(credDefId)).to.equal(false);
      expect(await sys.credDefRegistry.supportsTier(credDefId, 1)).to.equal(false);
    });

    it("non-member cannot deprecate", async () => {
      const sys = await loadFixture(deploySystem);
      await setupSchema(sys);
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);
      await expect(
        sys.credDefRegistry.connect(sys.other).deprecateCredentialDefinition(credDefId)
      ).to.be.revertedWithCustomError(sys.credDefRegistry, "NotIssuerOrgMember");
    });
  });
});
