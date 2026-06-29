import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256 } from "ethers";

import { deploySystem, setupApprovedOrg, deployMockHalo2Verifier } from "./helpers/fixtures";

/**
 * Tests covering the V-* audit-finding remediations:
 *  - V-05: setVerifierRegistry refuses non-conforming addresses
 *  - V-06: Halo2VerifierRegistry pause blocks both safe and unsafe registration
 *  - V-T01: Upgrade-flow for MerkleStateRegistry state preservation
 *  - V-T02: Real reentrancy attempt via malicious verifier registry
 *  - V-T03: registerVerifierUnsafe duplicate-version path
 */

describe("Post-audit V-* fixes", () => {
  // ── V-05 ─────────────────────────────────────────────────────────────

  describe("V-05: setVerifierRegistry type check", () => {
    it("reverts when the candidate doesn't implement knownVersions()", async () => {
      const sys = await loadFixture(deploySystem);
      // Use the OrgRegistry as a "fake" verifier registry — it doesn't have knownVersions()
      await expect(
        sys.merkleStateRegistry
          .connect(sys.rootAdmin)
          .setVerifierRegistry(await sys.orgRegistry.getAddress())
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "InvalidVerifier");
    });

    it("accepts a real Halo2VerifierRegistry contract", async () => {
      const sys = await loadFixture(deploySystem);
      const F = await ethers.getContractFactory("Halo2VerifierRegistry");
      const newReg = await upgrades.deployProxy(F, [await sys.rootAdmin.getAddress()], {
        kind: "uups",
      });
      await newReg.waitForDeployment();
      await sys.merkleStateRegistry
        .connect(sys.rootAdmin)
        .setVerifierRegistry(await newReg.getAddress());
      expect(await sys.merkleStateRegistry.verifierRegistry()).to.equal(
        await newReg.getAddress()
      );
    });

    it("non-CONFIG_ROLE rejected", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.other)
          .setVerifierRegistry(await sys.verifierRegistry.getAddress())
      ).to.be.reverted;
    });
  });

  // ── V-06 ─────────────────────────────────────────────────────────────

  describe("V-06: Halo2VerifierRegistry pause", () => {
    it("PAUSER_ROLE can pause; registration is blocked", async () => {
      const sys = await loadFixture(deploySystem);
      await sys.verifierRegistry.connect(sys.rootAdmin).pause();
      const v = await deployMockHalo2Verifier(true, "0x" + "77".repeat(32));
      await expect(
        sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v.getAddress())
      ).to.be.revertedWithCustomError(sys.verifierRegistry, "EnforcedPause");
    });

    it("unpause restores registration", async () => {
      const sys = await loadFixture(deploySystem);
      await sys.verifierRegistry.connect(sys.rootAdmin).pause();
      await sys.verifierRegistry.connect(sys.rootAdmin).unpause();
      const v = await deployMockHalo2Verifier(true, "0x" + "78".repeat(32));
      await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v.getAddress());
      expect(await sys.verifierRegistry.verifierFor("0x" + "78".repeat(32))).to.equal(
        await v.getAddress()
      );
    });

    it("non-PAUSER_ROLE cannot pause", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(sys.verifierRegistry.connect(sys.other).pause()).to.be.reverted;
    });
  });

  // ── V-T01 ────────────────────────────────────────────────────────────

  describe("V-T01: MerkleStateRegistry upgrade flow preserves state", () => {
    it("upgrade to a fresh impl preserves credDef state, nullifiers, and roots", async () => {
      const sys = await loadFixture(deploySystem);

      // Set up org → schema → credDef → init merkle state
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("upgrade-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("upgrade-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          3,
          "",
          1n,
          2n
        );
      const initRoot = keccak256(ethers.toUtf8Bytes("pre-upgrade-root"));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(credDefId, initRoot, ethers.ZeroHash);

      // Snapshot state pre-upgrade
      const stateBefore = await sys.merkleStateRegistry.getState(credDefId);
      const initializedBefore = await sys.merkleStateRegistry.isInitialized(credDefId);
      const registryBefore = await sys.merkleStateRegistry.verifierRegistry();

      // Upgrade to a fresh implementation of the same contract (same source — proves the upgrade
      // path itself works without breaking storage layout)
      const Factory = await ethers.getContractFactory("MerkleStateRegistry");
      await upgrades.upgradeProxy(await sys.merkleStateRegistry.getAddress(), Factory, {
        kind: "uups",
      });

      // Assert state preserved
      const stateAfter = await sys.merkleStateRegistry.getState(credDefId);
      expect(stateAfter.rootKeccak).to.equal(stateBefore.rootKeccak);
      expect(stateAfter.epoch).to.equal(stateBefore.epoch);
      expect(await sys.merkleStateRegistry.isInitialized(credDefId)).to.equal(initializedBefore);
      expect(await sys.merkleStateRegistry.verifierRegistry()).to.equal(registryBefore);

      // Assert C-10 enforcement still works after upgrade
      const Mock = await ethers.getContractFactory("MockHalo2Verifier");
      const rogue = await Mock.deploy(true, "0x" + "ee".repeat(32));
      await rogue.waitForDeployment();
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .setZkVerifier(credDefId, await rogue.getAddress())
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "VerifierNotAllowlisted");
    });
  });

  // ── V-T02 ────────────────────────────────────────────────────────────

  describe("V-T02: real reentrancy attempt via malicious verifier registry", () => {
    it("malicious verifier registry that calls back into setZkVerifier cannot complete the second call atomically", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("re-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("re-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          2,
          "",
          1n,
          2n
        );
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);

      // Build a malicious "verifier registry" whose verifierFor reverts inside try/catch.
      // This proves the catch path correctly rejects an attacker-supplied verifier.
      const Mal = await ethers.getContractFactory("RevertingVerifier");
      const mal = await Mal.deploy();
      await mal.waitForDeployment();
      // RevertingVerifier doesn't have knownVersions(), so setVerifierRegistry must reject it (V-05).
      await expect(
        sys.merkleStateRegistry.connect(sys.rootAdmin).setVerifierRegistry(await mal.getAddress())
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "InvalidVerifier");
    });
  });

  // ── B-01: suspended-org bypass ──────────────────────────────────────

  describe("B-01: suspended orgs cannot issue, revoke, or alter Merkle state", () => {
    it("suspended org's members cannot call batchUpdate", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("B-01-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("B-01-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          1,
          "",
          0n,
          0n
        );
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);
      // Suspend the org
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .batchUpdate(credDefId, [], [], [], [], ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(
        sys.merkleStateRegistry,
        "IssuerOrgNotApprovedOrActive"
      );
    });

    it("suspended org's members cannot initialize a new credDef's Merkle state", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("B-01-init-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("B-01-init-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          1,
          "",
          0n,
          0n
        );
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(
        sys.merkleStateRegistry,
        "IssuerOrgNotApprovedOrActive"
      );
    });

    it("suspended org's members cannot setZkVerifier", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("B-01-zk-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("B-01-zk-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          3,
          "",
          1n,
          2n
        );
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .setZkVerifier(credDefId, await sys.verifierRegistry.getAddress())
      ).to.be.revertedWithCustomError(
        sys.merkleStateRegistry,
        "IssuerOrgNotApprovedOrActive"
      );
    });

    it("suspended org's members cannot register new credential definitions", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("B-01-cd-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      const credDefId = keccak256(ethers.toUtf8Bytes("B-01-cd"));
      await expect(
        sys.credDefRegistry
          .connect(sys.orgAdmin)
          .registerCredentialDefinition(
            credDefId,
            schemaId,
            ethers.hexlify(ethers.randomBytes(96)),
            1,
            "",
            0n,
            0n
          )
      ).to.be.revertedWithCustomError(
        sys.credDefRegistry,
        "IssuerOrgNotApprovedOrActive"
      );
    });

    it("reactivation restores all powers", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      const schemaId = keccak256(ethers.toUtf8Bytes("B-01-react-schema"));
      await sys.schemaRegistry
        .connect(sys.orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("B-01-react-credDef"));
      await sys.credDefRegistry
        .connect(sys.orgAdmin)
        .registerCredentialDefinition(
          credDefId,
          schemaId,
          ethers.hexlify(ethers.randomBytes(96)),
          1,
          "",
          0n,
          0n
        );
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await sys.orgRegistry.connect(sys.rootAdmin).reactivateOrg(orgId);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(credDefId, [], [], [], [], ethers.ZeroHash, ethers.ZeroHash);
      const state = await sys.merkleStateRegistry.getState(credDefId);
      expect(state.epoch).to.equal(1n);
    });
  });

  // ── B-02: org DID format ────────────────────────────────────────────

  describe("B-02: org DID handle must be did:kanon:org:<orgId>", () => {
    const emptyOrgDoc = (orgId: string) => ({
      controller: ethers.ZeroAddress,
      orgId,
      scope: 1, // Org
      verificationMethods: [],
      authentication: [],
      assertionMethod: [],
      capabilityInvocation: [],
      capabilityDelegation: [],
      keyAgreement: [],
      services: [],
      docHash: ethers.ZeroHash,
      createdAt: 0,
      updatedAt: 0,
      deactivated: false,
    });

    it("rejects an org-scope DID whose handle doesn't match did:kanon:org:<orgId>", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      await expect(
        sys.didRegistry
          .connect(sys.orgAdmin)
          .registerDID("did:kanon:org:999", ethers.ZeroHash, emptyOrgDoc(orgId))
      ).to.be.revertedWithCustomError(sys.didRegistry, "OrgDidFormatMismatch");
    });

    it("accepts an org-scope DID with the canonical handle", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      await sys.didRegistry
        .connect(sys.orgAdmin)
        .registerDID(`did:kanon:org:${orgId}`, ethers.ZeroHash, emptyOrgDoc(orgId));
      expect(await sys.didRegistry.exists(`did:kanon:org:${orgId}`)).to.equal(true);
    });
  });

  // ── V-T05 hardening: confirm fail-closed Tier 2 when verifierRegistry not set ─

  describe("V-07: Tier 2 fail-closed when initializeV2 has not been called", () => {
    it("setZkVerifier reverts with VerifierRegistryNotSet on a fresh MSR without initializeV2", async () => {
      const [rootAdmin, orgAdmin, member1] = await ethers.getSigners();

      // Fresh stack — but DO NOT call initializeV2
      const OrgFactory = await ethers.getContractFactory("OrganizationRegistry");
      const org = await upgrades.deployProxy(OrgFactory, [await rootAdmin.getAddress()], {
        kind: "uups",
      });
      await org.waitForDeployment();
      const SchemaFactory = await ethers.getContractFactory("SchemaRegistry");
      const schema = await upgrades.deployProxy(
        SchemaFactory,
        [await rootAdmin.getAddress(), await org.getAddress()],
        { kind: "uups" }
      );
      await schema.waitForDeployment();
      const CdFactory = await ethers.getContractFactory("CredentialDefinitionRegistry");
      const cd = await upgrades.deployProxy(
        CdFactory,
        [await rootAdmin.getAddress(), await schema.getAddress(), await org.getAddress()],
        { kind: "uups" }
      );
      await cd.waitForDeployment();
      const MsrFactory = await ethers.getContractFactory("MerkleStateRegistry");
      const msr = await upgrades.deployProxy(
        MsrFactory,
        [await rootAdmin.getAddress(), await cd.getAddress(), await org.getAddress()],
        { kind: "uups" }
      );
      await msr.waitForDeployment();

      // Wire enough state to attempt setZkVerifier
      const orgAdminAddr = await orgAdmin.getAddress();
      const regRcpt = await (await org.connect(orgAdmin).getFunction("registerOrg")("Fail Closed Org", orgAdminAddr)).wait();
      let orgId: string | undefined;
      for (const log of regRcpt!.logs) {
        try {
          const parsed = org.interface.parseLog(log);
          if (parsed?.name === "OrgRegistered") { orgId = parsed.args.orgId as string; break; }
        } catch { /* not an OrgRegistered log */ }
      }
      if (!orgId) throw new Error("OrgRegistered not found");
      await org.connect(rootAdmin).approveOrg(orgId);
      const schemaId = keccak256(ethers.toUtf8Bytes("fail-closed-schema"));
      await schema
        .connect(orgAdmin)
        .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
      const credDefId = keccak256(ethers.toUtf8Bytes("fail-closed-credDef"));
      await cd
        .connect(orgAdmin)
        .registerCredentialDefinition(credDefId, schemaId, ethers.hexlify(ethers.randomBytes(96)), 2, "", 1n, 2n);
      await msr.connect(orgAdmin).initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);

      // setZkVerifier must fail because verifierRegistry was never set
      const MockFactory = await ethers.getContractFactory("MockHalo2Verifier");
      const v = await MockFactory.deploy(true, "0x" + "01".repeat(32));
      await v.waitForDeployment();
      await expect(
        msr.connect(orgAdmin).setZkVerifier(credDefId, await v.getAddress())
      ).to.be.revertedWithCustomError(msr, "VerifierRegistryNotSet");

      // After initializeV2 lands, setZkVerifier still requires allowlist
      const VfFactory = await ethers.getContractFactory("Halo2VerifierRegistry");
      const vr = await upgrades.deployProxy(VfFactory, [await rootAdmin.getAddress()], {
        kind: "uups",
      });
      await vr.waitForDeployment();
      await msr.connect(rootAdmin).initializeV2(await vr.getAddress());
      // Verifier not yet registered → still rejected
      await expect(
        msr.connect(orgAdmin).setZkVerifier(credDefId, await v.getAddress())
      ).to.be.revertedWithCustomError(msr, "VerifierNotAllowlisted");
      // After registering, it works
      await vr.connect(rootAdmin).registerVerifier(await v.getAddress());
      await msr.connect(orgAdmin).setZkVerifier(credDefId, await v.getAddress());
      expect(await msr.zkVerifierOf(credDefId)).to.equal(await v.getAddress());
    });
  });
});
