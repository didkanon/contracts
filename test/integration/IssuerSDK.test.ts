import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, hexlify, randomBytes } from "ethers";

import { deploySystem, registerOrgAndGetId } from "../helpers/fixtures";
import {
  IssuerService,
  KanonClient,
  TIER_ONE_TIME,
  TIER_ZK_SNARK,
  TIER_ALL,
  deriveLeaf,
  issuer as sdkIssuer,
} from "../../sdk/dist/index.cjs";

const { generateIssuerKeyPair } = sdkIssuer;

/**
 * Exercises the SDK IssuerService methods introduced in 0.1.7:
 *
 *  - reconstructFromChain     restart-survivable rebuild from CredentialAdded /
 *                             CredentialRevoked events on MerkleStateRegistry
 *  - revoke (by leaf)         now consumes the companion poseidon stored at
 *                             issuance time / chain replay rather than
 *                             recomputing the placeholder mapping per call
 *  - revokeByCredId           credId-shape entry point used by plugins
 *  - getCheckpoint /          { lastSyncedBlock, active leaves } round-trip
 *    loadCheckpoint
 *  - KanonClient tier helpers getCredDefPolicy / credDefSupportsZk /
 *                             credDefSupportsOneTime read the on-chain mask
 */
describe("SDK IssuerService — restart-survivable Mode B helpers", () => {
  async function freshSystemWithCredDef(policyMask: number) {
    const sys = await loadFixture(deploySystem);

    const orgAdminAddr = await sys.orgAdmin.getAddress();
    const orgId = await registerOrgAndGetId(
      sys.orgRegistry,
      sys.orgAdmin,
      "Acme Issuer",
      orgAdminAddr
    );
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgId);
    await sys.orgRegistry
      .connect(sys.orgAdmin)
      .addMember(orgId, await sys.member1.getAddress());

    const schemaId = keccak256(ethers.toUtf8Bytes("IssuerSDK-schema"));
    await sys.schemaRegistry
      .connect(sys.member1)
      .registerSchema(
        orgId,
        schemaId,
        keccak256(ethers.toUtf8Bytes("schema-content")),
        "ipfs://Qm-test"
      );

    const credDefId = keccak256(ethers.toUtf8Bytes(`cred-def-${policyMask}`));
    const issuerPubKey = hexlify(randomBytes(96));
    await sys.credDefRegistry
      .connect(sys.member1)
      .registerCredentialDefinition(
        credDefId,
        schemaId,
        issuerPubKey,
        policyMask,
        "",
        (policyMask & 0b10) !== 0 ? 1n : 0n,
        (policyMask & 0b10) !== 0 ? 2n : 0n
      );

    await sys.merkleStateRegistry
      .connect(sys.member1)
      .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);

    const contracts = {
      orgRegistry: sys.orgRegistry,
      didRegistry: sys.didRegistry,
      schemaRegistry: sys.schemaRegistry,
      credDefRegistry: sys.credDefRegistry,
      merkleStateRegistry: sys.merkleStateRegistry,
      halo2VerifierRegistry: sys.verifierRegistry,
      anonCredsStatusRegistry: sys.anonCredsStatusRegistry,
    };

    return { sys, contracts, credDefId };
  }

  it("reconstructFromChain rebuilds active leaves after restart", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();

    // Issuer A issues two pools, then a third — total 9 active leaves.
    const issuerA = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    const holderAddr = await sys.holder.getAddress();
    const pool1 = await issuerA.issueOneTimePool(holderAddr, { name: "Alice" }, 3);
    const pool2 = await issuerA.issueOneTimePool(holderAddr, { name: "Alice" }, 4);
    const pool3 = await issuerA.issueOneTimePool(holderAddr, { name: "Alice" }, 2);
    const issuedLeaves = [...pool1.credentials, ...pool2.credentials, ...pool3.credentials]
      .map((c) => c.leafKeccak.toLowerCase());
    expect(issuedLeaves.length).to.eq(9);

    // Simulate a restart: fresh IssuerService instance with empty in-memory state.
    const issuerB = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    const tip = await issuerB.reconstructFromChain();
    expect(tip).to.be.greaterThan(0);

    const cp = issuerB.getCheckpoint();
    expect(cp.lastSyncedBlock).to.eq(tip);
    expect(cp.active.keccak.sort()).to.deep.eq(issuedLeaves.sort());
    expect(cp.active.poseidon.length).to.eq(cp.active.keccak.length);
  });

  it("reconstructFromChain folds revocations into the active set", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();
    const issuerA = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);

    const pool = await issuerA.issueOneTimePool(
      await sys.holder.getAddress(),
      { name: "Alice" },
      5
    );
    const leaves = pool.credentials.map((c) => c.leafKeccak.toLowerCase());

    // Revoke two of the five.
    await issuerA.revoke([leaves[1]!, leaves[3]!]);

    const issuerB = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    await issuerB.reconstructFromChain();
    const cp = issuerB.getCheckpoint();

    const expected = [leaves[0]!, leaves[2]!, leaves[4]!].sort();
    expect(cp.active.keccak.sort()).to.deep.eq(expected);
  });

  it("getCheckpoint / loadCheckpoint round-trip preserves keccak↔poseidon companion map", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();
    const issuerA = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);

    await issuerA.issueOneTimePool(await sys.holder.getAddress(), { v: "x" }, 4);
    const snapshot = issuerA.getCheckpoint();

    const issuerB = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    issuerB.loadCheckpoint(snapshot);
    const restored = issuerB.getCheckpoint();

    expect(restored.lastSyncedBlock).to.eq(snapshot.lastSyncedBlock);
    expect(restored.active.keccak).to.deep.eq(snapshot.active.keccak);
    expect(restored.active.poseidon).to.deep.eq(snapshot.active.poseidon);

    // After loading the checkpoint, issuerB can revoke without recomputing
    // poseidon — the companion map is already populated.
    await expect(issuerB.revoke([snapshot.active.keccak[0]!])).to.not.be.reverted;
  });

  it("revokeByCredId derives the keccak leaf and removes the credential", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();
    const issuerA = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);

    const pool = await issuerA.issueOneTimePool(
      await sys.holder.getAddress(),
      { v: "x" },
      3
    );
    const credId = pool.credentials[0]!.credentialId;
    const leafKeccak = deriveLeaf(credId);

    await issuerA.revokeByCredId([credId]);

    const issuerB = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    await issuerB.reconstructFromChain();
    const cp = issuerB.getCheckpoint();
    expect(cp.active.keccak.map((s) => s.toLowerCase())).to.not.include(leafKeccak.toLowerCase());
  });

  it("revokeByCredId([]) is a no-op (no transaction)", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();
    const issuer = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    await expect(issuer.revokeByCredId([])).to.not.be.reverted;
    await expect(issuer.revoke([])).to.not.be.reverted;
  });

  it("revoke of a leaf not in the active set throws without touching chain", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ALL);
    const issuerKeys = generateIssuerKeyPair();
    const issuer = new IssuerService(contracts as never, sys.member1, credDefId, issuerKeys);
    const fakeLeaf = "0x" + "11".repeat(32);
    await expect(issuer.revoke([fakeLeaf])).to.be.rejectedWith(/not in active set/);
  });

  it("KanonClient surfaces the credDef's policy mask", async () => {
    const { sys, contracts, credDefId } = await freshSystemWithCredDef(TIER_ZK_SNARK);
    // KanonClient constructor takes a deployment + signer. Build a thin
    // deployment from the live registries so the contract handles match.
    const deployment = {
      chainId: (await ethers.provider.getNetwork()).chainId,
      network: "hardhat",
      deployedAt: new Date().toISOString(),
      deployer: await sys.rootAdmin.getAddress(),
      rootAdmin: await sys.rootAdmin.getAddress(),
      addresses: {
        OrganizationRegistry: await sys.orgRegistry.getAddress(),
        DIDRegistry: await sys.didRegistry.getAddress(),
        SchemaRegistry: await sys.schemaRegistry.getAddress(),
        CredentialDefinitionRegistry: await sys.credDefRegistry.getAddress(),
        MerkleStateRegistry: await sys.merkleStateRegistry.getAddress(),
        Halo2VerifierRegistry: await sys.verifierRegistry.getAddress(),
      },
    };
    const client = new KanonClient(deployment as never, sys.member1);
    expect(await client.getCredDefPolicy(credDefId)).to.eq(TIER_ZK_SNARK);
    expect(await client.credDefSupportsZk(credDefId)).to.eq(true);
    expect(await client.credDefSupportsOneTime(credDefId)).to.eq(false);

    // Tier-1-only credDef from a parallel deployment.
    const tier1 = await freshSystemWithCredDef(TIER_ONE_TIME);
    const dep1 = { ...deployment, addresses: { ...deployment.addresses, OrganizationRegistry: await tier1.sys.orgRegistry.getAddress(), CredentialDefinitionRegistry: await tier1.sys.credDefRegistry.getAddress(), MerkleStateRegistry: await tier1.sys.merkleStateRegistry.getAddress() } };
    const client1 = new KanonClient(dep1 as never, tier1.sys.member1);
    expect(await client1.getCredDefPolicy(tier1.credDefId)).to.eq(TIER_ONE_TIME);
    expect(await client1.credDefSupportsZk(tier1.credDefId)).to.eq(false);
    expect(await client1.credDefSupportsOneTime(tier1.credDefId)).to.eq(true);
  });
});
