import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256 } from "ethers";

import { deploySystem, setupApprovedOrg, DeployedSystem } from "./helpers/fixtures";
import {
  zkInit,
  newIssuer,
  issueCredential,
  proveNonRevocation,
  PoseidonTree,
  toBytes32,
  DEPTH,
  BN254_SCALAR_FIELD,
} from "./helpers/zk";

const SCHEMA_ID = keccak256(ethers.toUtf8Bytes("ZK-schema"));
const CRED_DEF_ID_BYTES = keccak256(ethers.toUtf8Bytes("ZK-credDef"));

// The on-chain `MerkleStateRegistry.verifyZKMembership` binds the circuit's
// `publicSignals[1]` (a BN254 felt) to `uint256(CRED_DEF_ID_BYTES) mod p`. The
// circuit, the off-chain leaf, the EdDSA signature, and the Poseidon tree all
// use this same reduced value — derive it once and pass it everywhere so all
// four agree.
const CIRCUIT_CRED_DEF_ID =
  BigInt(CRED_DEF_ID_BYTES) % BN254_SCALAR_FIELD;

/** Register a Tier-2 credDef and publish the issuer's BabyJubjub ZK key. */
async function setupZkCredDef(
  sys: DeployedSystem,
  issuer: { Ax: bigint; Ay: bigint }
) {
  const orgId = await setupApprovedOrg(sys, [sys.member1]);
  await sys.schemaRegistry
    .connect(sys.orgAdmin)
    .registerSchema(orgId, SCHEMA_ID, keccak256(ethers.toUtf8Bytes("h")), "ipfs://x");
  // The AnonCreds CL key slot — opaque bytes, not used by Mode B. Any non-empty
  // value satisfies `EmptyIssuerPubKey`. policyMask = 2 (TIER_ZK_SNARK only).
  const clKeyStub = ethers.toUtf8Bytes("kanon-anoncreds-cl-key-stub");
  // Mode B credDef — the BabyJubjub Tier-2 key is registered atomically in
  // the same call. No separate setIssuerZkPubKey hop.
  await sys.credDefRegistry
    .connect(sys.orgAdmin)
    .registerCredentialDefinition(
      CRED_DEF_ID_BYTES,
      SCHEMA_ID,
      clKeyStub,
      2,
      "",
      issuer.Ax,
      issuer.Ay
    );
}

async function deployVerifierStack(sys: DeployedSystem) {
  const G16 = await ethers.getContractFactory("Groth16Verifier");
  const g16 = await G16.deploy();
  await g16.waitForDeployment();
  const Adapter = await ethers.getContractFactory("Groth16NonRevocationVerifier");
  const adapter = await Adapter.deploy(await g16.getAddress());
  await adapter.waitForDeployment();
  // allowlist it, then attach to the credDef
  await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await adapter.getAddress());
  return adapter;
}

describe("Tier 2 ZK — real Groth16 proof verified on-chain", function () {
  this.timeout(120000);

  it("end-to-end: issue -> prove -> verifyZKMembership returns true", async () => {
    await zkInit();
    const sys = await loadFixture(deploySystem);

    const issuer = newIssuer(7);

    await setupZkCredDef(sys, issuer);
    const adapter = await deployVerifierStack(sys);

    // Issue a credential and build the Poseidon tree.
    const credId = 123456789n;
    const attributes = [11n, 22n, 33n, 44n, 55n, 66n, 77n, 88n, 99n, 100n, 110n, 120n, 130n, 140n, 150n, 160n];
    const cred = issueCredential(issuer, CIRCUIT_CRED_DEF_ID, credId, attributes);
    const leafIndex = 3;
    const leaves = [1n, 2n, 3n, cred.leaf]; // credential at index 3
    const tree = new PoseidonTree(DEPTH, leaves);

    // Initialize Merkle state with the real Poseidon root and wire the verifier.
    const poseidonRoot = toBytes32(tree.root);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID_BYTES, ethers.ZeroHash, poseidonRoot);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .setZkVerifier(CRED_DEF_ID_BYTES, await adapter.getAddress());

    // Holder generates a real proof disclosing attribute[2] (= 33).
    const p = await proveNonRevocation({
      issuer,
      cred,
      tree,
      leafIndex,
      credDefId: CIRCUIT_CRED_DEF_ID,
      challenge: 999n,
      disclosedIndex: 2,
    });

    // publicSignals[0] must be the Poseidon root the registry knows.
    expect(p.publicSignals[0]).to.equal(poseidonRoot);

    const ok = await sys.merkleStateRegistry.verifyZKMembership(
      CRED_DEF_ID_BYTES,
      p.proofBytes,
      p.publicSignals
    );
    expect(ok).to.equal(true);
  });

  it("tampered public signal (wrong disclosed value) fails verification", async () => {
    await zkInit();
    const sys = await loadFixture(deploySystem);
    const issuer = newIssuer(8);

    await setupZkCredDef(sys, issuer);
    const adapter = await deployVerifierStack(sys);

    const cred = issueCredential(
      issuer,
      CIRCUIT_CRED_DEF_ID,
      777n,
      [5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n, 19n, 20n]
    );
    const tree = new PoseidonTree(DEPTH, [cred.leaf]);
    const poseidonRoot = toBytes32(tree.root);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID_BYTES, ethers.ZeroHash, poseidonRoot);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .setZkVerifier(CRED_DEF_ID_BYTES, await adapter.getAddress());

    const p = await proveNonRevocation({
      issuer,
      cred,
      tree,
      leafIndex: 0,
      credDefId: CIRCUIT_CRED_DEF_ID,
      challenge: 1n,
      disclosedIndex: 0,
    });

    // Flip the disclosed value (publicSignals[6]) — proof no longer matches.
    const tampered = [...p.publicSignals];
    tampered[6] = toBytes32(BigInt(tampered[6]) + 1n);
    // Root unchanged so the registry still delegates; the SNARK check must fail.
    const ok = await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID_BYTES, p.proofBytes, tampered);
    expect(ok).to.equal(false);
  });

  it("stale / unknown Poseidon root is rejected before the SNARK even runs", async () => {
    await zkInit();
    const sys = await loadFixture(deploySystem);
    const issuer = newIssuer(9);

    await setupZkCredDef(sys, issuer);
    const adapter = await deployVerifierStack(sys);

    const cred = issueCredential(
      issuer,
      CIRCUIT_CRED_DEF_ID,
      555n,
      [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]
    );
    const tree = new PoseidonTree(DEPTH, [cred.leaf]);
    // Initialize with a DIFFERENT root than the proof uses.
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID_BYTES, ethers.ZeroHash, keccak256(ethers.toUtf8Bytes("other-root")));
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .setZkVerifier(CRED_DEF_ID_BYTES, await adapter.getAddress());

    const p = await proveNonRevocation({
      issuer,
      cred,
      tree,
      leafIndex: 0,
      credDefId: CIRCUIT_CRED_DEF_ID,
      challenge: 1n,
      disclosedIndex: 0,
    });
    // The proof's root is not in the recent-roots window -> verifyZKMembership returns false.
    const ok = await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID_BYTES, p.proofBytes, p.publicSignals);
    expect(ok).to.equal(false);
  });
});
