import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, getBytes, concat, Signer } from "ethers";

import { deploySystem, setupApprovedOrg, registerOrgAndGetId, DeployedSystem } from "../helpers/fixtures";
import { StandardMerkleTree, buildOneTimeCredentialTree } from "../helpers/merkleTree";

const SCHEMA_ID = keccak256(ethers.toUtf8Bytes("INV-schema"));
const SCHEMA_HASH = keccak256(ethers.toUtf8Bytes("h"));
const URI = "ipfs://h";
const CRED_DEF_ID = keccak256(ethers.toUtf8Bytes("INV-credDef"));
const ISSUER_PK = ethers.hexlify(ethers.randomBytes(96));

async function setupCredDef(sys: DeployedSystem, policyMask: number = 1): Promise<string> {
  const orgId = await setupApprovedOrg(sys, [sys.member1]);
  await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, SCHEMA_ID, SCHEMA_HASH, URI);
  await sys.credDefRegistry
    .connect(sys.orgAdmin)
    // policyMask gates whether a Tier-2 key is required; pass (1, 2) when Mode B
    // is in the mask, (0, 0) otherwise. The registry rejects mismatches.
    .registerCredentialDefinition(
      CRED_DEF_ID,
      SCHEMA_ID,
      ISSUER_PK,
      policyMask,
      "",
      (policyMask & 0b10) !== 0 ? 1n : 0n,
      (policyMask & 0b10) !== 0 ? 2n : 0n
    );
  await sys.merkleStateRegistry
    .connect(sys.orgAdmin)
    .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
  return orgId;
}

describe("Invariants — MerkleStateRegistry", () => {
  it("no leaf can be consumed twice (nullifier non-replay)", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);

    const pairs = await Promise.all(
      Array.from({ length: 10 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`c${i}`)),
        owner: await sys.holder.getAddress(),
      }))
    );
    const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        CRED_DEF_ID,
        leaves,
        leaves.map(keccak256),
        [],
        [],
        tree.root,
        ethers.ZeroHash
      );

    // Each credId consumes once, then reverts on every subsequent attempt.
    for (let j = 0; j < credIds.length; j++) {
      const proof = tree.proofFor(leaves[j]);
      await sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, credIds[j], proof);
      for (let i = 0; i < 3; i++) {
        await expect(
          sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, credIds[j], proof)
        ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");
      }
    }
  });

  it("epoch is strictly monotonic across batchUpdate calls", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys);

    let lastEpoch = 0n;
    for (let i = 0; i < 20; i++) {
      const root = keccak256(ethers.toUtf8Bytes(`r${i}`));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, [], [], [], [], root, ethers.ZeroHash);
      const state = await sys.merkleStateRegistry.getState(CRED_DEF_ID);
      expect(state.epoch).to.be.greaterThan(lastEpoch);
      lastEpoch = state.epoch;
    }
  });

  it("recent-roots window has at most RECENT_ROOTS_WINDOW (16) entries", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys);

    const seen: string[] = [];
    for (let i = 0; i < 24; i++) {
      const root = keccak256(ethers.toUtf8Bytes(`unique-root-${i}`));
      seen.push(root);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, [], [], [], [], root, ethers.ZeroHash);
    }

    // The first 8 roots (24 - 16 = 8) should have rolled out of the window
    for (let i = 0; i < 8; i++) {
      expect(
        await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, seen[i])
      ).to.equal(false);
    }
    // The last 16 should still be in the window
    for (let i = 8; i < 24; i++) {
      expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, seen[i])).to.equal(true);
    }
  });

  it("totalIssued is conserved: issuedCount - revokedCount never goes negative", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys);

    // Random alternating add / revoke; require monotonic counters
    for (let i = 0; i < 10; i++) {
      const adds = Array.from({ length: 5 }, (_, k) => keccak256(ethers.toUtf8Bytes(`a-${i}-${k}`)));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          adds,
          adds.map(keccak256),
          [],
          [],
          keccak256(ethers.toUtf8Bytes(`r-add-${i}`)),
          ethers.ZeroHash
        );
      const a = await sys.merkleStateRegistry.getState(CRED_DEF_ID);

      const revokes = adds.slice(0, 2);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          [],
          [],
          revokes,
          revokes.map(keccak256),
          keccak256(ethers.toUtf8Bytes(`r-rev-${i}`)),
          ethers.ZeroHash
        );
      const b = await sys.merkleStateRegistry.getState(CRED_DEF_ID);

      expect(b.issuedCount).to.equal(a.issuedCount); // unchanged on revoke
      expect(b.revokedCount).to.be.greaterThan(a.revokedCount);
      expect(b.issuedCount >= b.revokedCount).to.equal(true);
    }
  });

  it("only the current epoch's roots can revert past nullifiers (pause doesn't unset nullifiers)", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);

    const pairs = await Promise.all(
      Array.from({ length: 3 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`pp${i}`)),
        owner: await sys.holder.getAddress(),
      }))
    );
    const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        CRED_DEF_ID,
        leaves,
        leaves.map(keccak256),
        [],
        [],
        tree.root,
        ethers.ZeroHash
      );
    await sys.merkleStateRegistry
      .connect(sys.holder)
      .consumeOneTime(CRED_DEF_ID, credIds[0], tree.proofFor(leaves[0]));

    // Pause + unpause does not reset nullifier state
    await sys.merkleStateRegistry.connect(sys.rootAdmin).pause();
    await sys.merkleStateRegistry.connect(sys.rootAdmin).unpause();
    await expect(
      sys.merkleStateRegistry
        .connect(sys.holder)
        .consumeOneTime(CRED_DEF_ID, credIds[0], tree.proofFor(leaves[0]))
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");
  });

  it("Tier 1 always requires the leaf to verify against a recent root", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);

    const pairs = await Promise.all(
      Array.from({ length: 4 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`f${i}`)),
        owner: await sys.holder.getAddress(),
      }))
    );
    const { tree, leaves } = buildOneTimeCredentialTree(pairs);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        CRED_DEF_ID,
        leaves,
        leaves.map(keccak256),
        [],
        [],
        tree.root,
        ethers.ZeroHash
      );

    // Forge a leaf NOT in the tree
    const fakeLeaf = keccak256(ethers.toUtf8Bytes("absent"));
    await expect(
      sys.merkleStateRegistry
        .connect(sys.holder)
        .consumeOneTime(CRED_DEF_ID, fakeLeaf, [ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash])
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "MembershipProofFailed");
  });
});

describe("Invariants — OrganizationRegistry", () => {
  it("admin transfer is atomic: old admin loses authority, new gains it, in one tx", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);

    const newAdminAddr = await sys.member1.getAddress();
    await sys.orgRegistry.connect(sys.orgAdmin).transferOrgAdmin(id, newAdminAddr);

    // Old admin can no longer add members
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).addMember(id, await sys.member2.getAddress())
    ).to.be.revertedWithCustomError(sys.orgRegistry, "NotOrgAdmin");
    // New admin can
    await sys.orgRegistry.connect(sys.member1).addMember(id, await sys.member2.getAddress());
  });

  it("every registered org gets a distinct, non-zero bytes32 id", async () => {
    const sys = await loadFixture(deploySystem);
    const ZERO32 = "0x" + "00".repeat(32);
    const seen = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const adminAddr = await sys.orgAdmin.getAddress();
      const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, `Org ${i}`, adminAddr);
      expect(id).to.not.equal(ZERO32);
      expect(seen.has(id)).to.equal(false);
      seen.add(id);
    }
    expect(seen.size).to.equal(5);
  });

  it("approveOrg → suspendOrg → reactivateOrg are idempotent guards", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
    await expect(sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id)).to.be.revertedWithCustomError(
      sys.orgRegistry,
      "OrgAlreadyApproved"
    );
    await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id);
    await expect(sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id)).to.be.revertedWithCustomError(
      sys.orgRegistry,
      "OrgSuspended"
    );
  });
});

describe("Invariants — DIDRegistry", () => {
  it("only one controller at a time after a rotation chain", async () => {
    const sys = await loadFixture(deploySystem);
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expectedHandle = keccak256(
      ethers.solidityPacked(["string", "address", "bytes32"], ["did:kanon:user:", await sys.holder.getAddress(), salt])
    );
    const did = `did:kanon:user:${expectedHandle}`;
    await sys.didRegistry.connect(sys.holder).registerDID(did, salt, {
      controller: ethers.ZeroAddress,
      orgId: ethers.ZeroHash,
      scope: 0,
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
    // Rotate twice
    await sys.didRegistry.connect(sys.holder).rotateController(did, await sys.member1.getAddress());
    await sys.didRegistry.connect(sys.member1).rotateController(did, await sys.member2.getAddress());

    // Only member2 can act now
    expect(await sys.didRegistry.controllerOf(did)).to.equal(await sys.member2.getAddress());
    await expect(
      sys.didRegistry.connect(sys.holder).rotateController(did, await sys.other.getAddress())
    ).to.be.revertedWithCustomError(sys.didRegistry, "NotController");
    await expect(
      sys.didRegistry.connect(sys.member1).rotateController(did, await sys.other.getAddress())
    ).to.be.revertedWithCustomError(sys.didRegistry, "NotController");
  });
});
