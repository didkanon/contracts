import { ethers } from "hardhat";
import { keccak256, concat, getBytes } from "ethers";
import * as fs from "fs";
import * as path from "path";

/**
 * Seed an example org → schema → credDef → batch of Tier-1 credentials onto a fresh deployment.
 *
 * Reads deployment addresses from `deployments/<chainId>.json`.
 * Reads holder address from HOLDER env var; defaults to signer[1].
 */
async function main() {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const deploymentPath = path.join(__dirname, "..", "deployments", `${chainId}.json`);
  if (!fs.existsSync(deploymentPath)) {
    throw new Error(`No deployment record at ${deploymentPath}. Run scripts/deploy.ts first.`);
  }
  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));

  const [deployer, holderSigner] = await ethers.getSigners();
  const holder = process.env.HOLDER ?? (await holderSigner.getAddress());

  const org = await ethers.getContractAt("OrganizationRegistry", deployment.addresses.OrganizationRegistry);
  const schema = await ethers.getContractAt("SchemaRegistry", deployment.addresses.SchemaRegistry);
  const credDef = await ethers.getContractAt(
    "CredentialDefinitionRegistry",
    deployment.addresses.CredentialDefinitionRegistry
  );
  const msr = await ethers.getContractAt("MerkleStateRegistry", deployment.addresses.MerkleStateRegistry);

  console.log("Seeding dev data on", deployment.network, "chainId", chainId);
  console.log("Deployer / org admin:", await deployer.getAddress());
  console.log("Holder:", holder);

  // 1. Register and approve an org. orgId is now a random bytes32.
  console.log("\n[1] Registering org…");
  const orgId: string = await org.registerOrg.staticCall("Kanon Dev Org", await deployer.getAddress());
  await (await org.registerOrg("Kanon Dev Org", await deployer.getAddress())).wait();
  await (await org.approveOrg(orgId)).wait();
  console.log("    orgId=" + orgId + " approved (DID did:kanon:org:" + orgId + ")");

  // 2. Register a schema
  const schemaId = keccak256(ethers.toUtf8Bytes("DevSchema-v1"));
  const schemaHash = keccak256(ethers.toUtf8Bytes("dev-schema-content"));
  console.log("\n[2] Registering schema…");
  await (await schema.registerSchema(orgId, schemaId, schemaHash, "ipfs://Qm-dev-schema")).wait();

  // 3. Register a credDef supporting both tiers
  const credDefId = keccak256(ethers.toUtf8Bytes("DevSchema-v1-issuer-dev"));
  const issuerPubKey = ethers.hexlify(ethers.randomBytes(96));
  console.log("\n[3] Registering credDef…");
  await (
    await credDef.registerCredentialDefinition(credDefId, schemaId, issuerPubKey, 3, "")
  ).wait();

  console.log("\n[4] Initializing Merkle state…");
  await (await msr.initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash)).wait();

  // Emit credIds only; use sdk/src/issuer/IssuerService to publish the corresponding Merkle root.
  console.log("\n[5] Sample credential IDs:");
  for (let i = 0; i < 5; i++) {
    const credId = keccak256(ethers.toUtf8Bytes(`dev-cred-${holder}-${i}`));
    const leaf = keccak256(concat([getBytes(credId), getBytes(holder)]));
    console.log(`    credId[${i}] = ${credId}`);
    console.log(`      leaf     = ${leaf}`);
  }

  console.log("\nDev seed complete.");
  console.log("Next: use sdk/src/issuer to compute the canonical Merkle root and call batchUpdate.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
