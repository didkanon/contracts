import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { Signer, keccak256, solidityPacked } from "ethers";

import { deploySystem, setupApprovedOrg, registerOrgAndGetId, DeployedSystem } from "./helpers/fixtures";

enum DIDScope {
  User = 0,
  Org = 1,
}

const ZERO32 = "0x" + "00".repeat(32);

function makeEmptyDoc(scope: DIDScope, orgId: string = ZERO32) {
  return {
    controller: ethers.ZeroAddress, // overwritten by contract on register
    orgId,
    scope,
    verificationMethods: [],
    authentication: [],
    assertionMethod: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    services: [],
    docHash: ethers.ZeroHash,
    createdAt: 0n,
    updatedAt: 0n,
    deactivated: false,
  };
}

function makeDocWithKey(scope: DIDScope, orgId: string = ZERO32) {
  const keyId = keccak256(ethers.toUtf8Bytes("key-1"));
  return {
    ...makeEmptyDoc(scope, orgId),
    verificationMethods: [
      {
        id: keyId,
        vmType: 0, // Ed25519
        publicKey: ethers.hexlify(ethers.randomBytes(32)),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}

async function computeUserDid(holder: Signer, salt: string): Promise<string> {
  const addr = await holder.getAddress();
  const expected = keccak256(solidityPacked(["string", "address", "bytes32"], ["did:kanon:user:", addr, salt]));
  return `did:kanon:user:${expected}`;
}

describe("DIDRegistry", () => {
  describe("registerDID — User scope (sender-binding)", () => {
    it("accepts a properly bound user DID", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, salt, makeDocWithKey(DIDScope.User))
      ).to.emit(sys.didRegistry, "DIDRegistered");
      expect(await sys.didRegistry.exists(did)).to.equal(true);
      expect(await sys.didRegistry.controllerOf(did)).to.equal(await sys.holder.getAddress());
    });

    it("rejects a DID with a different salt (handle does not commit to caller)", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const otherSalt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, otherSalt, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "HandleNotBoundToCaller");
    });

    it("rejects a DID where someone else tries to register for caller's binding", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await expect(
        sys.didRegistry.connect(sys.other).registerDID(did, salt, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "HandleNotBoundToCaller");
    });

    it("rejects empty DID", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID("", ethers.ZeroHash, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "EmptyDid");
    });

    it("rejects re-registration of an existing DID", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await sys.didRegistry.connect(sys.holder).registerDID(did, salt, makeDocWithKey(DIDScope.User));
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, salt, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "DIDAlreadyExists");
    });
  });

  describe("registerDID — Org scope", () => {
    it("requires the caller to be an approved-org member", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      const did = `did:kanon:org:${orgId}`;
      // Non-member should be rejected
      await expect(
        sys.didRegistry.connect(sys.other).registerDID(did, ethers.ZeroHash, makeDocWithKey(DIDScope.Org, orgId))
      ).to.be.revertedWithCustomError(sys.didRegistry, "OrgScopeRequiresOrgAdmin");
      // Org admin succeeds
      await expect(
        sys.didRegistry.connect(sys.orgAdmin).registerDID(did, ethers.ZeroHash, makeDocWithKey(DIDScope.Org, orgId))
      ).to.emit(sys.didRegistry, "DIDRegistered");
    });

    it("requires the org to be approved and active", async () => {
      const sys = await loadFixture(deploySystem);
      // Register but don't approve
      const adminAddr = await sys.orgAdmin.getAddress();
      const orgId = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
      const did = `did:kanon:org:${orgId}`;
      await expect(
        sys.didRegistry
          .connect(sys.orgAdmin)
          .registerDID(did, ethers.ZeroHash, makeDocWithKey(DIDScope.Org, orgId))
      ).to.be.revertedWithCustomError(sys.didRegistry, "OrgNotApprovedOrActive");
    });
  });

  describe("validation", () => {
    it("rejects too many verification methods", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      const doc = makeDocWithKey(DIDScope.User);
      // Push 17 verification methods (limit is 16)
      doc.verificationMethods = [];
      for (let i = 0; i < 17; i++) {
        doc.verificationMethods.push({
          id: keccak256(ethers.toUtf8Bytes(`k${i}`)),
          vmType: 0,
          publicKey: ethers.hexlify(ethers.randomBytes(32)),
        });
      }
      doc.authentication = [];
      doc.assertionMethod = [];
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, salt, doc)
      ).to.be.revertedWithCustomError(sys.didRegistry, "TooManyVerificationMethods");
    });

    it("rejects relationship references that point to a missing verification method", async () => {
      const sys = await loadFixture(deploySystem);
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      const doc = makeDocWithKey(DIDScope.User);
      doc.authentication = [keccak256(ethers.toUtf8Bytes("not-declared"))];
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, salt, doc)
      ).to.be.revertedWithCustomError(sys.didRegistry, "InvalidVerificationMethodReference");
    });
  });

  describe("updateDID / rotateController / deactivateDID", () => {
    async function setupUserDid(sys: DeployedSystem) {
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await sys.didRegistry.connect(sys.holder).registerDID(did, salt, makeDocWithKey(DIDScope.User));
      return { did, salt };
    }

    it("only controller can update", async () => {
      const sys = await loadFixture(deploySystem);
      const { did } = await setupUserDid(sys);
      await expect(
        sys.didRegistry.connect(sys.other).updateDID(did, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "NotController");
      await sys.didRegistry.connect(sys.holder).updateDID(did, makeDocWithKey(DIDScope.User));
    });

    it("rotateController moves authority atomically", async () => {
      const sys = await loadFixture(deploySystem);
      const { did } = await setupUserDid(sys);
      const newCtrl = await sys.member1.getAddress();
      await expect(sys.didRegistry.connect(sys.holder).rotateController(did, newCtrl))
        .to.emit(sys.didRegistry, "ControllerRotated")
        .withArgs(did, await sys.holder.getAddress(), newCtrl);
      // Old controller can no longer write
      await expect(
        sys.didRegistry.connect(sys.holder).updateDID(did, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "NotController");
      // New controller can
      await sys.didRegistry.connect(sys.member1).updateDID(did, makeDocWithKey(DIDScope.User));
    });

    it("rotating to same controller reverts", async () => {
      const sys = await loadFixture(deploySystem);
      const { did } = await setupUserDid(sys);
      const me = await sys.holder.getAddress();
      await expect(sys.didRegistry.connect(sys.holder).rotateController(did, me)).to.be.revertedWithCustomError(
        sys.didRegistry,
        "SameController"
      );
    });

    it("deactivate is one-way; further writes revert", async () => {
      const sys = await loadFixture(deploySystem);
      const { did } = await setupUserDid(sys);
      await sys.didRegistry.connect(sys.holder).deactivateDID(did);
      expect(await sys.didRegistry.isDeactivated(did)).to.equal(true);
      await expect(
        sys.didRegistry.connect(sys.holder).updateDID(did, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "DIDDeactivated_");
    });
  });

  describe("pause + config", () => {
    it("pause blocks writes", async () => {
      const sys = await loadFixture(deploySystem);
      await sys.didRegistry.connect(sys.rootAdmin).pause();
      const salt = ethers.hexlify(ethers.randomBytes(32));
      const did = await computeUserDid(sys.holder, salt);
      await expect(
        sys.didRegistry.connect(sys.holder).registerDID(did, salt, makeDocWithKey(DIDScope.User))
      ).to.be.revertedWithCustomError(sys.didRegistry, "EnforcedPause");
    });

    it("setOrgRegistry can be updated by CONFIG_ROLE", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(sys.didRegistry.connect(sys.other).setOrgRegistry(await sys.orgRegistry.getAddress())).to.be
        .reverted;
      await sys.didRegistry.connect(sys.rootAdmin).setOrgRegistry(await sys.orgRegistry.getAddress());
    });
  });
});
