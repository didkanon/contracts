import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, concat, getBytes, Signer } from "ethers";

import {
  deploySystem,
  setupApprovedOrg,
  deployMockHalo2Verifier,
  deployAndRegisterMockHalo2Verifier,
  deployMockGatedContract,
  DeployedSystem,
} from "./helpers/fixtures";
import { StandardMerkleTree, buildOneTimeCredentialTree } from "./helpers/merkleTree";

const SCHEMA_ID = keccak256(ethers.toUtf8Bytes("KYC-v1"));
const SCHEMA_HASH = keccak256(ethers.toUtf8Bytes("schema-content"));
const SCHEMA_URI = "ipfs://Qm-schema";
const CRED_DEF_ID = keccak256(ethers.toUtf8Bytes("KYC-v1-issuer-1"));
// AnonCreds CL key slot is opaque to the registry — any non-empty value works.
const CL_PUBKEY_STUB = ethers.toUtf8Bytes("anoncreds-cl-key-stub");
// BabyJubjub Tier-2 issuer key — published separately via setIssuerZkPubKey when the
// credDef opts into TIER_ZK_SNARK. Values just need to be valid felts (< BN254 prime)
// and not the identity (0, 1); they are matched against publicSignals[3]/[4].
const ISSUER_AX = 1n;
const ISSUER_AY = 2n;
const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// publicSignals[1] in the circuit is `uint256(credDefId) % BN254_SCALAR_FIELD`;
// the registry binds against that reduction.
const CRED_DEF_FELT = BigInt(CRED_DEF_ID) % BN254_SCALAR_FIELD;
const TIER_ZK_SNARK = 0b10;

// Build a 7-length public-signal vector with the matching credDefId-as-felt at [1]
// and issuer key at [3],[4] so the registry's binding checks pass.
function zkSignals(root: string): string[] {
  const z = ethers.ZeroHash;
  const b32 = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");
  return [root, b32(CRED_DEF_FELT), z, b32(ISSUER_AX), b32(ISSUER_AY), z, z];
}

async function setupCredDef(sys: DeployedSystem, policyMask: number = 1): Promise<string> {
  const orgId = await setupApprovedOrg(sys, [sys.member1]);
  await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, SCHEMA_ID, SCHEMA_HASH, SCHEMA_URI);
  // For Tier-2 credDefs the BabyJubjub key is registered atomically. Mode A
  // credDefs MUST pass (0, 0) — the registry rejects stray ZK keys.
  const wantsZk = (policyMask & TIER_ZK_SNARK) !== 0;
  await sys.credDefRegistry
    .connect(sys.orgAdmin)
    .registerCredentialDefinition(
      CRED_DEF_ID,
      SCHEMA_ID,
      CL_PUBKEY_STUB,
      policyMask,
      "",
      wantsZk ? ISSUER_AX : 0n,
      wantsZk ? ISSUER_AY : 0n
    );
  return orgId;
}

function leafFor(credId: string, owner: string): string {
  return keccak256(concat([getBytes(credId), getBytes(owner)]));
}

async function generateCredIds(holder: Signer, n: number): Promise<{ credId: string; owner: string }[]> {
  const owner = await holder.getAddress();
  return Array.from({ length: n }, (_, i) => ({
    credId: keccak256(ethers.toUtf8Bytes(`cred-${owner}-${i}`)),
    owner,
  }));
}

describe("MerkleStateRegistry", () => {
  describe("initializeCredDefState", () => {
    it("issuer org member can initialize; emits event; populates recent roots", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      const initK = keccak256(ethers.toUtf8Bytes("init-keccak"));
      const initP = keccak256(ethers.toUtf8Bytes("init-poseidon"));
      await expect(
        sys.merkleStateRegistry.connect(sys.orgAdmin).initializeCredDefState(CRED_DEF_ID, initK, initP)
      )
        .to.emit(sys.merkleStateRegistry, "MerkleStateInitialized")
        .withArgs(CRED_DEF_ID, initK, initP);
      expect(await sys.merkleStateRegistry.isInitialized(CRED_DEF_ID)).to.equal(true);
      expect(await sys.merkleStateRegistry.isCurrentKeccakRoot(CRED_DEF_ID, initK)).to.equal(true);
      expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, initK)).to.equal(true);
      expect(await sys.merkleStateRegistry.isRecentPoseidonRoot(CRED_DEF_ID, initP)).to.equal(true);
    });

    it("non-member cannot initialize", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.other)
          .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NotIssuerOrgMember");
    });

    it("cannot initialize twice", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "AlreadyInitialized");
    });

    it("requires credDef to be active", async () => {
      const sys = await loadFixture(deploySystem);
      // No credDef registered
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "CredDefNotActive");
    });
  });

  describe("batchUpdate", () => {
    it("issuer updates roots; emits RootsUpdated + per-leaf events; bumps epoch", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs = await generateCredIds(sys.holder, 4);
      const { tree, leaves } = buildOneTimeCredentialTree(pairs);
      const newRootK = tree.root;
      const newRootP = keccak256(ethers.toUtf8Bytes("poseidon-root-stub"));
      // mirror leaves as Poseidon leaves (stub — in production they're a Poseidon hash)
      const poseidonLeaves = leaves.map((l) => keccak256(l));

      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .batchUpdate(CRED_DEF_ID, leaves, poseidonLeaves, [], [], newRootK, newRootP)
      )
        .to.emit(sys.merkleStateRegistry, "RootsUpdated")
        .withArgs(CRED_DEF_ID, 1n, newRootK, newRootP, leaves.length, 0);
      const state = await sys.merkleStateRegistry.getState(CRED_DEF_ID);
      expect(state.epoch).to.equal(1n);
      expect(state.issuedCount).to.equal(leaves.length);
      expect(state.revokedCount).to.equal(0);
    });

    it("non-member cannot batchUpdate", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.other)
          .batchUpdate(CRED_DEF_ID, [], [], [], [], ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NotIssuerOrgMember");
    });

    it("array length mismatch reverts", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .batchUpdate(
            CRED_DEF_ID,
            [ethers.ZeroHash],
            [],
            [],
            [],
            ethers.ZeroHash,
            ethers.ZeroHash
          )
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "BatchSizeMismatch");
    });
  });

  describe("Tier 1: verifyKeccakMembership and consumeOneTime", () => {
    it("happy path: valid leaf + proof verifies; consumption marks nullifier", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);

      const pairs = await generateCredIds(sys.holder, 4);
      const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
      const poseidonLeaves = leaves.map((l) => keccak256(l));
      const newRootK = tree.root;
      const newRootP = keccak256(ethers.toUtf8Bytes("poseidon-root-stub"));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, leaves, poseidonLeaves, [], [], newRootK, newRootP);

      const proof = tree.proofFor(leaves[0]);
      expect(await sys.merkleStateRegistry.verifyKeccakMembership(CRED_DEF_ID, credIds[0], proof)).to.equal(true);

      await expect(
        sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, credIds[0], proof)
      )
        .to.emit(sys.merkleStateRegistry, "OneTimeConsumed")
        .withArgs(CRED_DEF_ID, leaves[0]);
      expect(await sys.merkleStateRegistry.isNullifierUsed(CRED_DEF_ID, credIds[0])).to.equal(true);
    });

    it("double-spend is prevented", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs = await generateCredIds(sys.holder, 2);
      const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
      const poseidonLeaves = leaves.map((l) => keccak256(l));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, leaves, poseidonLeaves, [], [], tree.root, ethers.ZeroHash);
      const proof = tree.proofFor(leaves[0]);
      await sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, credIds[0], proof);
      await expect(
        sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, credIds[0], proof)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");
    });

    it("bogus proof reverts with MembershipProofFailed", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs = await generateCredIds(sys.holder, 2);
      const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
      const poseidonLeaves = leaves.map((l) => keccak256(l));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, leaves, poseidonLeaves, [], [], tree.root, ethers.ZeroHash);
      await expect(
        sys.merkleStateRegistry
          .connect(sys.holder)
          .consumeOneTime(CRED_DEF_ID, credIds[0], [ethers.ZeroHash, ethers.ZeroHash])
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "MembershipProofFailed");
    });

    it("recent-roots window: after an update, the previous root remains accepted", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs1 = await generateCredIds(sys.holder, 2);
      const { tree: tree1, leaves: leaves1, credIds: credIds1 } = buildOneTimeCredentialTree(pairs1);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          leaves1,
          leaves1.map((l) => keccak256(l)),
          [],
          [],
          tree1.root,
          ethers.ZeroHash
        );
      // New batch shifts the current root but tree1.root stays in the recent window
      const pairs2 = await generateCredIds(sys.member1, 2);
      const { tree: tree2, leaves: leaves2 } = buildOneTimeCredentialTree(pairs2);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          leaves2,
          leaves2.map((l) => keccak256(l)),
          [],
          [],
          tree2.root,
          ethers.ZeroHash
        );
      // Membership against the OLD root must still verify
      expect(
        await sys.merkleStateRegistry.verifyKeccakMembership(CRED_DEF_ID, credIds1[0], tree1.proofFor(leaves1[0]))
      ).to.equal(true);
    });

    it("Tier 2 not supported when policyMask excludes it", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 1); // Tier 1 only
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      expect(
        await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0x", [ethers.ZeroHash])
      ).to.equal(false);
    });
  });

  describe("Tier 2: SNARK verifier injection", () => {
    it("setZkVerifier rejects non-conforming addresses", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 2);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      // Use a contract that exists but isn't an IHalo2Verifier — e.g. the OrgRegistry proxy.
      // Its circuitVersion() will revert / decode-fail, which is caught and re-thrown as InvalidVerifier.
      await expect(
        sys.merkleStateRegistry
          .connect(sys.orgAdmin)
          .setZkVerifier(CRED_DEF_ID, await sys.orgRegistry.getAddress())
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "InvalidVerifier");
    });

    it("setZkVerifier(0) clears the verifier", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 2);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const v = await deployAndRegisterMockHalo2Verifier(sys, true);
      await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await v.getAddress());
      expect(await sys.merkleStateRegistry.zkVerifierOf(CRED_DEF_ID)).to.equal(await v.getAddress());
      await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, ethers.ZeroAddress);
      expect(await sys.merkleStateRegistry.zkVerifierOf(CRED_DEF_ID)).to.equal(ethers.ZeroAddress);
    });

    it("with a mock verifier wired, verifyZKMembership returns the configured result if root is recent", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 2);
      const initP = keccak256(ethers.toUtf8Bytes("pose-init"));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, initP);
      const verifier = await deployAndRegisterMockHalo2Verifier(sys, true);
      await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await verifier.getAddress());
      // recent root + matching issuer key -> delegates to the (accepting) verifier
      expect(
        await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0xdeadbeef", zkSignals(initP))
      ).to.equal(true);
      // Stale root rejected before delegation
      expect(
        await sys.merkleStateRegistry.verifyZKMembership(
          CRED_DEF_ID,
          "0xdeadbeef",
          zkSignals(keccak256(ethers.toUtf8Bytes("never-was-a-root")))
        )
      ).to.equal(false);
    });

    it("issuer-key mismatch in public signals is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 2);
      const initP = keccak256(ethers.toUtf8Bytes("pose-init"));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, initP);
      const verifier = await deployAndRegisterMockHalo2Verifier(sys, true);
      await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await verifier.getAddress());
      // Signals carry a different issuer key than the credDef's registered (Ax,Ay).
      const wrong = zkSignals(initP);
      wrong[3] = "0x" + (999n).toString(16).padStart(64, "0");
      expect(
        await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0xdeadbeef", wrong)
      ).to.equal(false);
    });

    it("verifier returning false yields verifyZKMembership=false", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 2);
      const initP = keccak256(ethers.toUtf8Bytes("pose-init"));
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, initP);
      const verifier = await deployAndRegisterMockHalo2Verifier(sys, false, "0x" + "cd".repeat(32));
      await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await verifier.getAddress());
      expect(
        await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0x", zkSignals(initP))
      ).to.equal(false);
    });
  });

  describe("Gated contract integration", () => {
    it("gates an action via consumeOneTime; double-spend reverts second call", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 1);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs = await generateCredIds(sys.holder, 3);
      const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          leaves,
          leaves.map((l) => keccak256(l)),
          [],
          [],
          tree.root,
          ethers.ZeroHash
        );
      const gated = await deployMockGatedContract(sys.merkleStateRegistry, CRED_DEF_ID);
      const proof0 = tree.proofFor(leaves[0]);
      await expect(gated.connect(sys.holder).performAction(credIds[0], proof0))
        .to.emit(gated, "GatedActionPerformed")
        .withArgs(await sys.holder.getAddress(), credIds[0], 1n);
      await expect(
        gated.connect(sys.holder).performAction(credIds[0], proof0)
      ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");
    });

    it("multiple distinct credIds let the holder act multiple times", async () => {
      const sys = await loadFixture(deploySystem);
      await setupCredDef(sys, 1);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
      const pairs = await generateCredIds(sys.holder, 5);
      const { tree, leaves, credIds } = buildOneTimeCredentialTree(pairs);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(
          CRED_DEF_ID,
          leaves,
          leaves.map((l) => keccak256(l)),
          [],
          [],
          tree.root,
          ethers.ZeroHash
        );
      const gated = await deployMockGatedContract(sys.merkleStateRegistry, CRED_DEF_ID);
      for (let i = 0; i < 5; i++) {
        await gated.connect(sys.holder).performAction(credIds[i], tree.proofFor(leaves[i]));
      }
      expect(await gated.actionsByCaller(await sys.holder.getAddress())).to.equal(5n);
    });
  });
});
