import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, concat, getBytes, solidityPacked } from "ethers";

import {
  deploySystem,
  registerOrgAndGetId,
  deployMockGatedContract,
  deployMockHalo2Verifier,
  deployAndRegisterMockHalo2Verifier,
  DeployedSystem,
} from "../helpers/fixtures";
import { buildOneTimeCredentialTree, StandardMerkleTree } from "../helpers/merkleTree";

describe("End-to-end SSI lifecycle", () => {
  it("org → schema → credDef → issue → present (Tier 1) → revoke → re-present fails", async () => {
    const sys = await loadFixture(deploySystem);

    // 1. Org registers and gets approved
    const orgAdminAddr = await sys.orgAdmin.getAddress();
    const orgId = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Acme Issuer", orgAdminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgId);
    await sys.orgRegistry.connect(sys.orgAdmin).addMember(orgId, await sys.member1.getAddress());

    // 2. Org publishes a schema
    const schemaId = keccak256(ethers.toUtf8Bytes("DriverLicense-v1"));
    const schemaHash = keccak256(ethers.toUtf8Bytes("{type:object,properties:...}"));
    await sys.schemaRegistry
      .connect(sys.member1)
      .registerSchema(orgId, schemaId, schemaHash, "ipfs://Qm-driver-license");

    // 3. Org publishes a credDef with Tier-1-only policy
    const credDefId = keccak256(ethers.toUtf8Bytes("DriverLicense-v1-issuer-A"));
    const issuerPubKey = ethers.hexlify(ethers.randomBytes(96));
    await sys.credDefRegistry
      .connect(sys.member1)
      .registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 1, "", 0n, 0n);

    // 4. Initialize Merkle state
    await sys.merkleStateRegistry
      .connect(sys.member1)
      .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);

    // 5. Issuer mints 5 one-time-use credentials to the holder
    const holderAddr = await sys.holder.getAddress();
    const issued = Array.from({ length: 5 }, (_, i) => ({
      credId: keccak256(ethers.toUtf8Bytes(`license-${holderAddr}-${i}`)),
      owner: holderAddr,
    }));
    const { tree, leaves, credIds } = buildOneTimeCredentialTree(issued);
    await sys.merkleStateRegistry
      .connect(sys.member1)
      .batchUpdate(credDefId, leaves, leaves.map((l) => keccak256(l)), [], [], tree.root, ethers.ZeroHash);

    // 6. Deploy a credential-gated contract
    const gated = await deployMockGatedContract(sys.merkleStateRegistry, credDefId);

    // 7. Holder uses credential #0 to perform a gated action
    await gated.connect(sys.holder).performAction(credIds[0], tree.proofFor(leaves[0]));
    expect(await gated.actionsByCaller(holderAddr)).to.equal(1n);

    // 8. Holder cannot reuse the same credential
    await expect(
      gated.connect(sys.holder).performAction(credIds[0], tree.proofFor(leaves[0]))
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");

    // 9. Holder uses credential #1 successfully
    await gated.connect(sys.holder).performAction(credIds[1], tree.proofFor(leaves[1]));
    expect(await gated.actionsByCaller(holderAddr)).to.equal(2n);

    // 10. Issuer revokes the remaining credentials (rebuilds tree with only used ones removed = empty tree)
    // We rebuild the tree as if all five remained but revoke the unused ones.
    // For test simplicity: shrink tree to just the used leaves.
    const remainingTree = new StandardMerkleTree([leaves[0], leaves[1]]);
    await sys.merkleStateRegistry
      .connect(sys.member1)
      .batchUpdate(
        credDefId,
        [],
        [],
        [leaves[2], leaves[3], leaves[4]],
        [keccak256(leaves[2]), keccak256(leaves[3]), keccak256(leaves[4])],
        remainingTree.root,
        ethers.ZeroHash
      );

    // 11. Holder presenting credential #2 against the OLD root still works (root is in recent window)
    // but the nullifier ALSO has to be unused — credential #2 hasn't been used, so it works once.
    await gated.connect(sys.holder).performAction(credIds[2], tree.proofFor(leaves[2]));

    // 12. After enough updates, the old root falls out of the window. Simulate by performing 16 noop updates.
    for (let i = 0; i < 16; i++) {
      const noopRoot = keccak256(ethers.toUtf8Bytes(`noop-${i}`));
      await sys.merkleStateRegistry
        .connect(sys.member1)
        .batchUpdate(credDefId, [], [], [], [], noopRoot, ethers.ZeroHash);
    }
    // Credential #3 (revoked AND root stale) — should fail
    await expect(
      gated.connect(sys.holder).performAction(credIds[3], tree.proofFor(leaves[3]))
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "MembershipProofFailed");
  });

  it("Tier 2: SNARK presentation flow with mock verifier", async () => {
    const sys = await loadFixture(deploySystem);
    const orgAdminAddr = await sys.orgAdmin.getAddress();
    const orgId = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Age Issuer", orgAdminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgId);
    const schemaId = keccak256(ethers.toUtf8Bytes("AgeProof-v1"));
    const credDefId = keccak256(ethers.toUtf8Bytes("AgeProof-v1-issuer"));
    await sys.schemaRegistry
      .connect(sys.orgAdmin)
      .registerSchema(orgId, schemaId, keccak256(ethers.toUtf8Bytes("age-schema")), "ipfs://Qm-age");
    // The AnonCreds CL key slot is opaque to the registry — a non-empty stub
    // satisfies it. The BabyJubjub Tier-2 issuer key is published separately
    // via setIssuerZkPubKey so verifyZKMembership's binding lookup works.
    const issuerAx = 1n;
    const issuerAy = 2n;
    const clKeyStub = ethers.toUtf8Bytes("anoncreds-cl-key-stub");
    // Tier 2 — BabyJubjub key registered atomically in the same call.
    await sys.credDefRegistry
      .connect(sys.orgAdmin)
      .registerCredentialDefinition(
        credDefId,
        schemaId,
        clKeyStub,
        2,
        "",
        issuerAx,
        issuerAy
      );

    const initialPoseidonRoot = keccak256(ethers.toUtf8Bytes("init-pose"));
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(credDefId, ethers.ZeroHash, initialPoseidonRoot);

    const verifier = await deployAndRegisterMockHalo2Verifier(sys, true);
    await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(credDefId, await verifier.getAddress());

    // Verifier (e.g. an age-gated dapp) checks a presentation on-chain. Public-signal layout:
    // [root, credDefId, challenge, issuerAx, issuerAy, idx, val]. The on-chain
    // registry binds publicSignals[1] to `uint256(credDefId) % BN254_SCALAR_FIELD`,
    // so the test mirrors that reduction.
    const BN254_SCALAR_FIELD =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const credDefFelt = BigInt(credDefId) % BN254_SCALAR_FIELD;
    const z = ethers.ZeroHash;
    const b32 = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");
    const publicSignals = [initialPoseidonRoot, b32(credDefFelt), z, b32(issuerAx), b32(issuerAy), z, z];
    expect(
      await sys.merkleStateRegistry.verifyZKMembership(credDefId, "0xdeadbeef", publicSignals)
    ).to.equal(true);

    // Tier 1 is NOT supported on this credDef
    await expect(
      sys.merkleStateRegistry.consumeOneTime(credDefId, ethers.ZeroHash, [])
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "TierNotSupported");
  });
});
