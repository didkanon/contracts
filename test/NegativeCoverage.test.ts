import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256, solidityPacked, concat, getBytes, Signer } from "ethers";

import { deploySystem, setupApprovedOrg, registerOrgAndGetId, DeployedSystem } from "./helpers/fixtures";
import { StandardMerkleTree, buildOneTimeCredentialTree } from "./helpers/merkleTree";

const SCHEMA_ID = keccak256(ethers.toUtf8Bytes("NEG-schema"));
const SCHEMA_HASH = keccak256(ethers.toUtf8Bytes("hash"));
const URI = "ipfs://qm";
const CRED_DEF_ID = keccak256(ethers.toUtf8Bytes("NEG-credDef"));
// AnonCreds CL key slot is opaque — any non-empty value works.
const CL_PK_STUB = ethers.toUtf8Bytes("anoncreds-cl-key-stub");
// BabyJubjub Tier-2 issuer key — set via setIssuerZkPubKey after registration
// for any credDef whose policyMask opts into TIER_ZK_SNARK.
const ISSUER_AX = 1n;
const ISSUER_AY = 2n;
const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CRED_DEF_FELT = BigInt(CRED_DEF_ID) % BN254_SCALAR_FIELD;
const TIER_ZK_SNARK = 0b10;

function zkSignals(root: string): string[] {
  const z = ethers.ZeroHash;
  const b32 = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");
  return [root, b32(CRED_DEF_FELT), z, b32(ISSUER_AX), b32(ISSUER_AY), z, z];
}

async function setupCredDef(sys: DeployedSystem, policyMask = 1): Promise<string> {
  const orgId = await setupApprovedOrg(sys, [sys.member1]);
  await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, SCHEMA_ID, SCHEMA_HASH, URI);
  const wantsZk = (policyMask & TIER_ZK_SNARK) !== 0;
  await sys.credDefRegistry
    .connect(sys.orgAdmin)
    .registerCredentialDefinition(
      CRED_DEF_ID,
      SCHEMA_ID,
      CL_PK_STUB,
      policyMask,
      "",
      wantsZk ? ISSUER_AX : 0n,
      wantsZk ? ISSUER_AY : 0n
    );
  return orgId;
}

describe("Negative coverage — OrganizationRegistry", () => {
  it("approveOrg / suspendOrg / reactivateOrg / transferOrgAdmin / addMember / removeMember all revert with OrgNotFound for unknown orgId", async () => {
    const sys = await loadFixture(deploySystem);
    const unknown = "0x" + "ff".repeat(32);
    await expect(sys.orgRegistry.connect(sys.rootAdmin).approveOrg(unknown))
      .to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(unknown))
      .to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.connect(sys.rootAdmin).reactivateOrg(unknown))
      .to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).transferOrgAdmin(unknown, await sys.member1.getAddress())
    ).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).addMember(unknown, await sys.member1.getAddress())
    ).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).removeMember(unknown, await sys.member1.getAddress())
    ).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
  });

  it("transferOrgAdmin / addMember reject zero address", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).transferOrgAdmin(id, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAdmin");
    await expect(
      sys.orgRegistry.connect(sys.orgAdmin).addMember(id, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAdmin");
  });

  it("removeMember by non-admin reverts NotOrgAdmin", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
    await sys.orgRegistry.connect(sys.orgAdmin).addMember(id, await sys.member1.getAddress());
    await expect(
      sys.orgRegistry.connect(sys.other).removeMember(id, await sys.member1.getAddress())
    ).to.be.revertedWithCustomError(sys.orgRegistry, "NotOrgAdmin");
  });

  it("suspending an already-suspended org reverts OrgSuspended", async () => {
    const sys = await loadFixture(deploySystem);
    const adminAddr = await sys.orgAdmin.getAddress();
    const id = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
    await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id);
    await expect(sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id)).to.be.revertedWithCustomError(
      sys.orgRegistry,
      "OrgSuspended"
    );
  });
});

describe("Negative coverage — DIDRegistry", () => {
  async function userDid(sys: DeployedSystem) {
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const handle = keccak256(
      solidityPacked(["string", "address", "bytes32"], ["did:kanon:user:", await sys.holder.getAddress(), salt])
    );
    return { did: `did:kanon:user:${handle}`, salt };
  }

  const emptyDoc = (scope = 0, orgId: string = "0x" + "00".repeat(32)) => ({
    controller: ethers.ZeroAddress,
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
    createdAt: 0,
    updatedAt: 0,
    deactivated: false,
  });

  it("updateDID on unknown DID reverts DIDNotFound", async () => {
    const sys = await loadFixture(deploySystem);
    await expect(
      sys.didRegistry.connect(sys.holder).updateDID("did:kanon:user:nope", emptyDoc())
    ).to.be.revertedWithCustomError(sys.didRegistry, "DIDNotFound");
  });

  it("rotateController on unknown DID reverts DIDNotFound", async () => {
    const sys = await loadFixture(deploySystem);
    await expect(
      sys.didRegistry.connect(sys.holder).rotateController("did:kanon:user:nope", await sys.holder.getAddress())
    ).to.be.revertedWithCustomError(sys.didRegistry, "DIDNotFound");
  });

  it("rotateController to address(0) reverts InvalidController", async () => {
    const sys = await loadFixture(deploySystem);
    const { did, salt } = await userDid(sys);
    await sys.didRegistry.connect(sys.holder).registerDID(did, salt, emptyDoc());
    await expect(
      sys.didRegistry.connect(sys.holder).rotateController(did, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(sys.didRegistry, "InvalidController");
  });

  it("deactivateDID on unknown DID reverts DIDNotFound", async () => {
    const sys = await loadFixture(deploySystem);
    await expect(
      sys.didRegistry.connect(sys.holder).deactivateDID("did:kanon:user:nope")
    ).to.be.revertedWithCustomError(sys.didRegistry, "DIDNotFound");
  });

  it("deactivateDID by non-controller reverts NotController", async () => {
    const sys = await loadFixture(deploySystem);
    const { did, salt } = await userDid(sys);
    await sys.didRegistry.connect(sys.holder).registerDID(did, salt, emptyDoc());
    await expect(
      sys.didRegistry.connect(sys.other).deactivateDID(did)
    ).to.be.revertedWithCustomError(sys.didRegistry, "NotController");
  });

  it("updateDID with reference to a verification method NOT in the new doc reverts", async () => {
    // C-CRITICAL test: removing a VM still referenced in authentication must fail.
    const sys = await loadFixture(deploySystem);
    const { did, salt } = await userDid(sys);
    const keyA = keccak256(ethers.toUtf8Bytes("key-A"));
    const docWithA = {
      ...emptyDoc(),
      verificationMethods: [{ id: keyA, vmType: 0, publicKey: ethers.hexlify(ethers.randomBytes(32)) }],
      authentication: [keyA],
    };
    await sys.didRegistry.connect(sys.holder).registerDID(did, salt, docWithA);

    // Attempt to update with no verificationMethods but still reference keyA in authentication.
    // This must revert because the reference no longer resolves.
    const docMissingVm = {
      ...emptyDoc(),
      verificationMethods: [],
      authentication: [keyA],
    };
    await expect(
      sys.didRegistry.connect(sys.holder).updateDID(did, docMissingVm)
    ).to.be.revertedWithCustomError(sys.didRegistry, "InvalidVerificationMethodReference");
  });

  it("registering org DID via non-member reverts even if did string is plausible", async () => {
    const sys = await loadFixture(deploySystem);
    const orgId = await setupApprovedOrg(sys);
    await expect(
      sys.didRegistry.connect(sys.other).registerDID(
        `did:kanon:org:${orgId}`,
        ethers.ZeroHash,
        { ...emptyDoc(1, orgId) }
      )
    ).to.be.revertedWithCustomError(sys.didRegistry, "OrgScopeRequiresOrgAdmin");
  });
});

describe("Negative coverage — SchemaRegistry", () => {
  it("deprecate on unknown schema reverts SchemaNotFound", async () => {
    const sys = await loadFixture(deploySystem);
    await expect(
      sys.schemaRegistry.connect(sys.orgAdmin).deprecateSchema(SCHEMA_ID)
    ).to.be.revertedWithCustomError(sys.schemaRegistry, "SchemaNotFound");
  });

  it("a different org's member cannot deprecate", async () => {
    const sys = await loadFixture(deploySystem);
    const orgA = await setupApprovedOrg(sys);
    await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgA, SCHEMA_ID, SCHEMA_HASH, URI);

    // Set up a second org with member2; member2 is NOT in orgA
    const m2 = await sys.member2.getAddress();
    const orgB = await registerOrgAndGetId(sys.orgRegistry, sys.member2, "Org B", m2);
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgB);
    await expect(
      sys.schemaRegistry.connect(sys.member2).deprecateSchema(SCHEMA_ID)
    ).to.be.revertedWithCustomError(sys.schemaRegistry, "NotOrgMember");
  });
});

describe("Negative coverage — CredentialDefinitionRegistry", () => {
  it("registerCredentialDefinition rejects zero credDefId", async () => {
    const sys = await loadFixture(deploySystem);
    const orgId = await setupApprovedOrg(sys);
    await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, SCHEMA_ID, SCHEMA_HASH, URI);
    await expect(
      sys.credDefRegistry.connect(sys.orgAdmin).registerCredentialDefinition(
        ethers.ZeroHash,
        SCHEMA_ID,
        CL_PK_STUB,
        1,
        "",
        0n,
        0n
      )
    ).to.be.revertedWithCustomError(sys.credDefRegistry, "ZeroCredDefId");
  });

  it("rejects oversized issuer pubkey (>256 bytes)", async () => {
    const sys = await loadFixture(deploySystem);
    const orgId = await setupApprovedOrg(sys);
    await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, SCHEMA_ID, SCHEMA_HASH, URI);
    const tooLong = ethers.hexlify(ethers.randomBytes(257));
    await expect(
      sys.credDefRegistry.connect(sys.orgAdmin).registerCredentialDefinition(
        CRED_DEF_ID,
        SCHEMA_ID,
        tooLong,
        1,
        "",
        0n,
        0n
      )
    ).to.be.revertedWithCustomError(sys.credDefRegistry, "EmptyIssuerPubKey");
  });

  it("deprecate on unknown credDef reverts CredDefNotFound", async () => {
    const sys = await loadFixture(deploySystem);
    await expect(
      sys.credDefRegistry.connect(sys.orgAdmin).deprecateCredentialDefinition(CRED_DEF_ID)
    ).to.be.revertedWithCustomError(sys.credDefRegistry, "CredDefNotFound");
  });

  it("cannot deprecate twice — CredDefDeprecated_", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);
    await sys.credDefRegistry.connect(sys.orgAdmin).deprecateCredentialDefinition(CRED_DEF_ID);
    await expect(
      sys.credDefRegistry.connect(sys.orgAdmin).deprecateCredentialDefinition(CRED_DEF_ID)
    ).to.be.revertedWithCustomError(sys.credDefRegistry, "CredDefDeprecated_");
  });
});

describe("Negative coverage — MerkleStateRegistry", () => {
  it("batchUpdate / setZkVerifier / consumeOneTime revert NotInitialized for uninitialized credDef", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);
    await expect(
      sys.merkleStateRegistry.connect(sys.orgAdmin).batchUpdate(
        CRED_DEF_ID, [], [], [], [], ethers.ZeroHash, ethers.ZeroHash
      )
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NotInitialized");
    await expect(
      sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await sys.orgRegistry.getAddress())
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NotInitialized");
    await expect(
      sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, ethers.ZeroHash, [])
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NotInitialized");
  });

  it("consumeOneTime reverts TierNotSupported when policyMask excludes Tier 1", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 2); // Tier 2 only
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
    await expect(
      sys.merkleStateRegistry.connect(sys.holder).consumeOneTime(CRED_DEF_ID, ethers.ZeroHash, [])
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "TierNotSupported");
  });

  it("supportsTier returns false for tier=0", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 3); // all tiers
    expect(await sys.credDefRegistry.supportsTier(CRED_DEF_ID, 0)).to.equal(false);
  });

  it("re-entrancy: a malicious gated contract attempting re-entry via fallback is blocked", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);

    const pairs = await Promise.all(
      Array.from({ length: 3 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`re${i}`)),
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

    const Reentrant = await ethers.getContractFactory("ReentrantConsumer");
    const r = await Reentrant.deploy(await sys.merkleStateRegistry.getAddress(), CRED_DEF_ID);
    await r.waitForDeployment();

    // First call succeeds normally
    await r.connect(sys.holder).performAction(credIds[0], tree.proofFor(leaves[0]));

    // Re-presenting the same credId reverts via the nullifier check.
    await r.connect(sys.holder).arm(credIds[0], tree.proofFor(leaves[0]));
    await expect(
      r.connect(sys.holder).performAction(credIds[0], tree.proofFor(leaves[0]))
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "NullifierAlreadyUsed");
  });

  it("cross-credDef leakage: a leaf from credDefA's tree cannot be consumed against credDefB", async () => {
    const sys = await loadFixture(deploySystem);
    // Set up credDefA
    await setupCredDef(sys, 1);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);
    const pairsA = await Promise.all(
      Array.from({ length: 2 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`A-${i}`)),
        owner: await sys.holder.getAddress(),
      }))
    );
    const { tree: treeA, leaves: leavesA, credIds: credIdsA } = buildOneTimeCredentialTree(pairsA);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        CRED_DEF_ID,
        leavesA,
        leavesA.map(keccak256),
        [],
        [],
        treeA.root,
        ethers.ZeroHash
      );

    // Set up credDefB with a totally different tree
    const credDefB = keccak256(ethers.toUtf8Bytes("cred-def-B"));
    await sys.credDefRegistry
      .connect(sys.orgAdmin)
      .registerCredentialDefinition(credDefB, SCHEMA_ID, CL_PK_STUB, 1, "", 0n, 0n);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(credDefB, ethers.ZeroHash, ethers.ZeroHash);
    const pairsB = await Promise.all(
      Array.from({ length: 2 }, async (_, i) => ({
        credId: keccak256(ethers.toUtf8Bytes(`B-${i}`)),
        owner: await sys.holder.getAddress(),
      }))
    );
    const { tree: treeB, leaves: leavesB } = buildOneTimeCredentialTree(pairsB);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        credDefB,
        leavesB,
        leavesB.map(keccak256),
        [],
        [],
        treeB.root,
        ethers.ZeroHash
      );

    // Consuming credDefA's credential against credDefB must fail: its proof recovers treeA.root,
    // which is not in credDefB's recent-roots window.
    await expect(
      sys.merkleStateRegistry
        .connect(sys.holder)
        .consumeOneTime(credDefB, credIdsA[0], treeA.proofFor(leavesA[0]))
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "MembershipProofFailed");
  });

  it("recent-roots window wraparound at slot 0: 16th batchUpdate overwrites initRoot", async () => {
    // Slot math: initialize sets initRoot at slot 0 (epoch=0). batchUpdate increments epoch first,
    // so the 1st batchUpdate uses slot 1, the 16th uses slot 0 (epoch=16 % 16 = 0). At that point
    // initRoot is overwritten. The 17th uses slot 1, overwriting batch #1's root.
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 1);
    const initRoot = keccak256(ethers.toUtf8Bytes("init-cycle"));
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, initRoot, ethers.ZeroHash);
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, initRoot)).to.equal(true);

    const batchRoots: string[] = [];
    // First 15 updates fill slots 1..15. initRoot still safe at slot 0.
    for (let i = 1; i <= 15; i++) {
      const r = keccak256(ethers.toUtf8Bytes(`cycle-${i}`));
      batchRoots.push(r);
      await sys.merkleStateRegistry
        .connect(sys.orgAdmin)
        .batchUpdate(CRED_DEF_ID, [], [], [], [], r, ethers.ZeroHash);
    }
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, initRoot)).to.equal(true);

    // 16th update: epoch=16, slot=0 → overwrites initRoot.
    const root16 = keccak256(ethers.toUtf8Bytes("cycle-16"));
    batchRoots.push(root16);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(CRED_DEF_ID, [], [], [], [], root16, ethers.ZeroHash);
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, initRoot)).to.equal(false);
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, root16)).to.equal(true);

    // 17th update: epoch=17, slot=1 → overwrites batchRoots[0] (epoch=1, slot=1).
    const root17 = keccak256(ethers.toUtf8Bytes("cycle-17"));
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(CRED_DEF_ID, [], [], [], [], root17, ethers.ZeroHash);
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, batchRoots[0])).to.equal(false);
    expect(await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, root17)).to.equal(true);
    // batchRoots[1..15] (epochs 2..16) still in the window
    for (let i = 1; i < batchRoots.length; i++) {
      expect(
        await sys.merkleStateRegistry.isRecentKeccakRoot(CRED_DEF_ID, batchRoots[i])
      ).to.equal(true);
    }
  });

  it("setZkVerifier(0) clears the verifier; further verifyZKMembership returns false", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 2);
    const initPose = keccak256(ethers.toUtf8Bytes("p-init"));
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, initPose);

    // Wire a valid mock verifier (must be allowlisted in Halo2VerifierRegistry first per C-10)
    const Mock = await ethers.getContractFactory("MockHalo2Verifier");
    const m = await Mock.deploy(true, "0x" + "44".repeat(32));
    await m.waitForDeployment();
    await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await m.getAddress());
    await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await m.getAddress());
    expect(
      await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0xabcd", zkSignals(initPose))
    ).to.equal(true);

    // Clear it
    await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, ethers.ZeroAddress);
    expect(await sys.merkleStateRegistry.zkVerifierOf(CRED_DEF_ID)).to.equal(ethers.ZeroAddress);

    // verifyZKMembership now returns false
    expect(
      await sys.merkleStateRegistry.verifyZKMembership(CRED_DEF_ID, "0xabcd", zkSignals(initPose))
    ).to.equal(false);
  });
});

describe("Negative coverage — C-10 verifier allowlist enforcement", () => {
  it("setZkVerifier rejects an address not in Halo2VerifierRegistry", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 2);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);

    // Deploy a mock that conforms to IHalo2Verifier but is NOT registered in the allowlist
    const Mock = await ethers.getContractFactory("MockHalo2Verifier");
    const rogue = await Mock.deploy(true, "0x" + "55".repeat(32));
    await rogue.waitForDeployment();

    await expect(
      sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await rogue.getAddress())
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "VerifierNotAllowlisted");
  });

  it("setZkVerifier rejects when a different address is registered under the same version", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 2);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);

    const version = "0x" + "66".repeat(32);
    const Mock = await ethers.getContractFactory("MockHalo2Verifier");
    const real = await Mock.deploy(true, version);
    await real.waitForDeployment();
    await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await real.getAddress());

    // Different address but same version
    const fake = await Mock.deploy(true, version);
    await fake.waitForDeployment();
    await expect(
      sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, await fake.getAddress())
    ).to.be.revertedWithCustomError(sys.merkleStateRegistry, "VerifierNotAllowlisted");

    // Real address succeeds
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .setZkVerifier(CRED_DEF_ID, await real.getAddress());
    expect(await sys.merkleStateRegistry.zkVerifierOf(CRED_DEF_ID)).to.equal(await real.getAddress());
  });

  it("setZkVerifier(0) is always allowed (clears the slot)", async () => {
    const sys = await loadFixture(deploySystem);
    await setupCredDef(sys, 2);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(CRED_DEF_ID, ethers.ZeroHash, ethers.ZeroHash);

    // No registry-wired verifier; setting to zero must still succeed
    await sys.merkleStateRegistry.connect(sys.orgAdmin).setZkVerifier(CRED_DEF_ID, ethers.ZeroAddress);
    expect(await sys.merkleStateRegistry.zkVerifierOf(CRED_DEF_ID)).to.equal(ethers.ZeroAddress);
  });

  it("verifierRegistry pointer is exposed via getter and rotatable by CONFIG_ROLE", async () => {
    const sys = await loadFixture(deploySystem);
    const current = await sys.merkleStateRegistry.verifierRegistry();
    expect(current).to.equal(await sys.verifierRegistry.getAddress());

    // Deploy a second verifier registry (fresh impl)
    const F = await ethers.getContractFactory("Halo2VerifierRegistry");
    const newReg = await F.deploy();
    await newReg.waitForDeployment();
    await sys.merkleStateRegistry
      .connect(sys.rootAdmin)
      .setVerifierRegistry(await newReg.getAddress());
    expect(await sys.merkleStateRegistry.verifierRegistry()).to.equal(await newReg.getAddress());

    // Non-CONFIG_ROLE caller rejected
    await expect(
      sys.merkleStateRegistry.connect(sys.other).setVerifierRegistry(await sys.verifierRegistry.getAddress())
    ).to.be.reverted;
  });
});

describe("Negative coverage — KanonTimelock", () => {
  it("re-executing the same scheduled proposal reverts", async () => {
    const [deployer, safe] = await ethers.getSigners();
    const MIN_DELAY = 60;
    const TF = await ethers.getContractFactory("KanonTimelock");
    const tl = await TF.deploy(MIN_DELAY, [await safe.getAddress()], [await safe.getAddress()], ethers.ZeroAddress);
    await tl.waitForDeployment();

    // Use a trivial calldata that the timelock will execute — call into itself's updateDelay()
    const calldata = tl.interface.encodeFunctionData("updateDelay", [MIN_DELAY * 2]);
    const target = await tl.getAddress();
    const salt = ethers.hexlify(ethers.randomBytes(32));
    await tl.connect(safe).schedule(target, 0, calldata, ethers.ZeroHash, salt, MIN_DELAY);
    await ethers.provider.send("evm_increaseTime", [MIN_DELAY + 1]);
    await ethers.provider.send("evm_mine", []);
    await tl.connect(safe).execute(target, 0, calldata, ethers.ZeroHash, salt);

    // Re-execute the same op → reverts (operation no longer Ready)
    await expect(tl.connect(safe).execute(target, 0, calldata, ethers.ZeroHash, salt)).to.be.reverted;
  });
});
