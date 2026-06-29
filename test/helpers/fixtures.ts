import { ethers, upgrades } from "hardhat";
import { Signer } from "ethers";

import {
  OrganizationRegistry,
  DIDRegistry,
  SchemaRegistry,
  CredentialDefinitionRegistry,
  MerkleStateRegistry,
  Halo2VerifierRegistry,
  AnonCredsStatusRegistry,
  MockHalo2Verifier,
  MockGatedContract,
} from "../../typechain-types";

export interface DeployedSystem {
  rootAdmin: Signer;
  orgAdmin: Signer;
  member1: Signer;
  member2: Signer;
  holder: Signer;
  other: Signer;
  orgRegistry: OrganizationRegistry;
  didRegistry: DIDRegistry;
  schemaRegistry: SchemaRegistry;
  credDefRegistry: CredentialDefinitionRegistry;
  merkleStateRegistry: MerkleStateRegistry;
  verifierRegistry: Halo2VerifierRegistry;
  anonCredsStatusRegistry: AnonCredsStatusRegistry;
}

export async function deploySystem(): Promise<DeployedSystem> {
  const [rootAdmin, orgAdmin, member1, member2, holder, other] = await ethers.getSigners();

  const OrgFactory = await ethers.getContractFactory("OrganizationRegistry");
  const orgRegistry = (await upgrades.deployProxy(OrgFactory, [await rootAdmin.getAddress()], {
    kind: "uups",
  })) as unknown as OrganizationRegistry;
  await orgRegistry.waitForDeployment();

  const DIDFactory = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = (await upgrades.deployProxy(
    DIDFactory,
    [await rootAdmin.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  )) as unknown as DIDRegistry;
  await didRegistry.waitForDeployment();

  const SchemaFactory = await ethers.getContractFactory("SchemaRegistry");
  const schemaRegistry = (await upgrades.deployProxy(
    SchemaFactory,
    [await rootAdmin.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  )) as unknown as SchemaRegistry;
  await schemaRegistry.waitForDeployment();

  const CredDefFactory = await ethers.getContractFactory("CredentialDefinitionRegistry");
  const credDefRegistry = (await upgrades.deployProxy(
    CredDefFactory,
    [await rootAdmin.getAddress(), await schemaRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  )) as unknown as CredentialDefinitionRegistry;
  await credDefRegistry.waitForDeployment();

  const MsrFactory = await ethers.getContractFactory("MerkleStateRegistry");
  const merkleStateRegistry = (await upgrades.deployProxy(
    MsrFactory,
    [await rootAdmin.getAddress(), await credDefRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  )) as unknown as MerkleStateRegistry;
  await merkleStateRegistry.waitForDeployment();

  const VerifierFactory = await ethers.getContractFactory("Halo2VerifierRegistry");
  const verifierRegistry = (await upgrades.deployProxy(VerifierFactory, [await rootAdmin.getAddress()], {
    kind: "uups",
  })) as unknown as Halo2VerifierRegistry;
  await verifierRegistry.waitForDeployment();

  // C-10 remediation: wire the verifier allowlist into MerkleStateRegistry
  await merkleStateRegistry
    .connect(rootAdmin)
    .initializeV2(await verifierRegistry.getAddress());

  const StatusFactory = await ethers.getContractFactory("AnonCredsStatusRegistry");
  const anonCredsStatusRegistry = (await upgrades.deployProxy(
    StatusFactory,
    [
      await rootAdmin.getAddress(),
      await credDefRegistry.getAddress(),
      await orgRegistry.getAddress(),
    ],
    { kind: "uups" }
  )) as unknown as AnonCredsStatusRegistry;
  await anonCredsStatusRegistry.waitForDeployment();

  return {
    rootAdmin,
    orgAdmin,
    member1,
    member2,
    holder,
    other,
    orgRegistry,
    didRegistry,
    schemaRegistry,
    credDefRegistry,
    merkleStateRegistry,
    verifierRegistry,
    anonCredsStatusRegistry,
  };
}

/** Register an approved + active org. Returns the bytes32 orgId (hex string). */
export async function setupApprovedOrg(
  sys: DeployedSystem,
  members: Signer[] = []
): Promise<string> {
  const orgName = "Kanon Test Org";
  const tx = await sys.orgRegistry
    .connect(sys.orgAdmin)
    .registerOrg(orgName, await sys.orgAdmin.getAddress());
  const receipt = await tx.wait();
  // Parse OrgRegistered event for the random bytes32 orgId.
  const orgId = parseOrgId(sys.orgRegistry, receipt!.logs);
  await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(orgId);
  for (const m of members) {
    await sys.orgRegistry.connect(sys.orgAdmin).addMember(orgId, await m.getAddress());
  }
  return orgId;
}

/** Extract the bytes32 orgId (hex string) from the OrgRegistered event in a tx's logs. */
export function parseOrgId(
  orgRegistry: OrganizationRegistry,
  logs: readonly { topics: readonly string[]; data: string }[]
): string {
  for (const log of logs) {
    try {
      const parsed = orgRegistry.interface.parseLog({
        topics: [...log.topics],
        data: log.data,
      });
      if (parsed?.name === "OrgRegistered") return parsed.args.orgId as string;
    } catch {
      /* not an OrgRegistered log */
    }
  }
  throw new Error("OrgRegistered event not found in logs");
}

/**
 * Register an org and return its random bytes32 id, read from the emitted
 * OrgRegistered event. Do NOT derive the id from a staticCall: the id depends on
 * block.timestamp/prevrandao/nonce, which differ between an eth_call and the mined tx.
 */
export async function registerOrgAndGetId(
  orgRegistry: OrganizationRegistry,
  signer: Signer,
  name: string,
  admin: string
): Promise<string> {
  const tx = await orgRegistry.connect(signer).registerOrg(name, admin);
  const receipt = await tx.wait();
  return parseOrgId(orgRegistry, receipt!.logs);
}

/** The canonical org DID for a bytes32 orgId: "did:kanon:org:0x<64-hex>". */
export function orgDidFor(orgId: string): string {
  return "did:kanon:org:" + orgId;
}

/** Deploy a mock Halo2 verifier (always-accept or always-reject). */
export async function deployMockHalo2Verifier(accept: boolean, version: string = "0x" + "ab".repeat(32)) {
  const Factory = await ethers.getContractFactory("MockHalo2Verifier");
  const v = (await Factory.deploy(accept, version)) as unknown as MockHalo2Verifier;
  await v.waitForDeployment();
  return v;
}

/** Deploy a mock verifier AND register it in Halo2VerifierRegistry so setZkVerifier accepts it. */
export async function deployAndRegisterMockHalo2Verifier(
  sys: DeployedSystem,
  accept: boolean,
  version: string = "0x" + "ab".repeat(32)
) {
  const v = await deployMockHalo2Verifier(accept, version);
  await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v.getAddress());
  return v;
}

/** Deploy a MockGatedContract bound to the given credDefId. */
export async function deployMockGatedContract(
  merkleStateRegistry: MerkleStateRegistry,
  credDefId: string
): Promise<MockGatedContract> {
  const Factory = await ethers.getContractFactory("MockGatedContract");
  const g = (await Factory.deploy(await merkleStateRegistry.getAddress(), credDefId)) as unknown as MockGatedContract;
  await g.waitForDeployment();
  return g;
}
