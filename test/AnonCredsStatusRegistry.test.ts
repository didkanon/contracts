import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, toUtf8Bytes, hexlify, randomBytes } from "ethers";

import { deploySystem, setupApprovedOrg, DeployedSystem } from "./helpers/fixtures";

describe("AnonCredsStatusRegistry", () => {
  const schemaId = keccak256(toUtf8Bytes("DriverLicense-v1"));
  const credDefId = keccak256(toUtf8Bytes("DriverLicense-v1-issuer-A"));
  const schemaHash = keccak256(toUtf8Bytes("schema-content"));
  const issuerPubKey = hexlify(randomBytes(96));

  const credId1 = "cred-uuid-aaaaaaaa";
  const credIdHash1 = keccak256(toUtf8Bytes(credId1));
  const credId2 = "cred-uuid-bbbbbbbb";
  const credIdHash2 = keccak256(toUtf8Bytes(credId2));

  enum Status {
    Unknown = 0,
    Issued = 1,
    Revoked = 2,
  }

  async function setupCredDef(sys: DeployedSystem): Promise<{ orgId: string }> {
    const orgId = await setupApprovedOrg(sys, [sys.member1]);
    await sys.schemaRegistry
      .connect(sys.orgAdmin)
      .registerSchema(orgId, schemaId, schemaHash, "ipfs://Qm-driver-license");
    await sys.credDefRegistry
      .connect(sys.member1)
      .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);
    return { orgId };
  }

  describe("issueCredential", () => {
    it("org member can issue; emits event; flips to Issued", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);

      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1)
      )
        .to.emit(sys.anonCredsStatusRegistry, "CredentialIssued")
        .withArgs(credDefId, credIdHash1, await sys.member1.getAddress(), anyUint64());

      expect(await sys.anonCredsStatusRegistry.getStatus(credDefId, credIdHash1)).to.equal(
        Status.Issued
      );
      expect(await sys.anonCredsStatusRegistry.isActive(credDefId, credIdHash1)).to.equal(true);
      expect(await sys.anonCredsStatusRegistry.isRevoked(credDefId, credIdHash1)).to.equal(false);
    });

    it("non-org-member cannot issue", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.other).issueCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "NotIssuerOrgMember");
    });

    it("rejects unknown credDef", async () => {
      const sys = await loadFixture(deploySystem);
      const unknownCredDef = keccak256(toUtf8Bytes("nope"));
      await expect(
        sys.anonCredsStatusRegistry
          .connect(sys.member1)
          .issueCredential(unknownCredDef, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "CredDefNotFound");
    });

    it("rejects deprecated credDef", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.credDefRegistry.connect(sys.member1).deprecateCredentialDefinition(credDefId);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "CredDefNotActive");
    });

    it("rejects when issuer org is suspended", async () => {
      const sys = await loadFixture(deploySystem);
      const { orgId } = await setupCredDef(sys);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "IssuerOrgNotApprovedOrActive");
    });

    it("rejects double issuance of the same credIdHash", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "AlreadyIssued");
    });

    it("rejects zero credDefId / credIdHash", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await expect(
        sys.anonCredsStatusRegistry
          .connect(sys.member1)
          .issueCredential(ethers.ZeroHash, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "ZeroCredDefId");
      await expect(
        sys.anonCredsStatusRegistry
          .connect(sys.member1)
          .issueCredential(credDefId, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "ZeroCredIdHash");
    });

    it("rejects writes while paused", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.rootAdmin).pause();
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "EnforcedPause");
    });
  });

  describe("revokeCredential", () => {
    it("org member can revoke an issued credential; emits event; flips to Revoked", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);

      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1)
      )
        .to.emit(sys.anonCredsStatusRegistry, "CredentialRevoked")
        .withArgs(credDefId, credIdHash1, await sys.member1.getAddress(), anyUint64());

      expect(await sys.anonCredsStatusRegistry.getStatus(credDefId, credIdHash1)).to.equal(
        Status.Revoked
      );
      expect(await sys.anonCredsStatusRegistry.isRevoked(credDefId, credIdHash1)).to.equal(true);
      expect(await sys.anonCredsStatusRegistry.isActive(credDefId, credIdHash1)).to.equal(false);
    });

    it("non-org-member cannot revoke", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.other).revokeCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "NotIssuerOrgMember");
    });

    it("cannot revoke a never-issued credential", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "NotIssued");
    });

    it("cannot revoke an already-revoked credential", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);
      await sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "AlreadyRevoked");
    });

    it("rejects revoke when issuer org is suspended", async () => {
      const sys = await loadFixture(deploySystem);
      const { orgId } = await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1)
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "IssuerOrgNotApprovedOrActive");
    });
  });

  describe("getEntry / multi-credential", () => {
    it("tracks issuedAt and revokedAt timestamps", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      const issueTx = await sys.anonCredsStatusRegistry
        .connect(sys.member1)
        .issueCredential(credDefId, credIdHash1);
      const issueRcpt = await issueTx.wait();
      const issueBlock = await ethers.provider.getBlock(issueRcpt!.blockNumber);

      const revokeTx = await sys.anonCredsStatusRegistry
        .connect(sys.member1)
        .revokeCredential(credDefId, credIdHash1);
      const revokeRcpt = await revokeTx.wait();
      const revokeBlock = await ethers.provider.getBlock(revokeRcpt!.blockNumber);

      const entry = await sys.anonCredsStatusRegistry.getEntry(credDefId, credIdHash1);
      expect(entry.status).to.equal(Status.Revoked);
      expect(entry.issuedAt).to.equal(issueBlock!.timestamp);
      expect(entry.revokedAt).to.equal(revokeBlock!.timestamp);
    });

    it("independent credentials don't interfere", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash1);
      await sys.anonCredsStatusRegistry.connect(sys.member1).issueCredential(credDefId, credIdHash2);
      await sys.anonCredsStatusRegistry.connect(sys.member1).revokeCredential(credDefId, credIdHash1);

      expect(await sys.anonCredsStatusRegistry.isRevoked(credDefId, credIdHash1)).to.equal(true);
      expect(await sys.anonCredsStatusRegistry.isActive(credDefId, credIdHash2)).to.equal(true);
    });
  });

  describe("access control", () => {
    it("non-pauser cannot pause", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.other).pause()
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "AccessControlUnauthorizedAccount");
    });

    it("config role can update registry pointers", async () => {
      const sys = await loadFixture(deploySystem);
      // Just verify the role check; we don't change the actual pointer here.
      await expect(
        sys.anonCredsStatusRegistry.connect(sys.other).setOrgRegistry(await sys.orgRegistry.getAddress())
      ).to.be.revertedWithCustomError(sys.anonCredsStatusRegistry, "AccessControlUnauthorizedAccount");
      await sys.anonCredsStatusRegistry
        .connect(sys.rootAdmin)
        .setOrgRegistry(await sys.orgRegistry.getAddress());
    });
  });
});

// hardhat-chai-matchers withArgs helper for "any uint64"
function anyUint64() {
  return (value: bigint) => {
    expect(value).to.be.a("bigint");
    expect(value > 0n).to.equal(true);
    return true;
  };
}
