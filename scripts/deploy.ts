import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Deploy the kanonv2 Phase-1 system as UUPS proxies and wire roles.
 *
 * Resolution order for the root admin address:
 *  1. ROOT_ADMIN env var (recommended for prod: pass a Safe multisig address)
 *  2. deployer signer
 *
 * Writes the deployment record to `deployments/<chainId>.json`.
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const rootAdmin = process.env.ROOT_ADMIN ?? (await deployer.getAddress());

  console.log("Deploying kanonv2 to network:", network.name, "chainId:", chainId);
  console.log("Deployer:", await deployer.getAddress());
  console.log("Root admin:", rootAdmin);

  // 1. OrganizationRegistry — no dependencies
  console.log("\n[1/6] Deploying OrganizationRegistry…");
  const OrgFactory = await ethers.getContractFactory("OrganizationRegistry");
  const orgRegistry = await upgrades.deployProxy(OrgFactory, [rootAdmin], { kind: "uups" });
  await orgRegistry.waitForDeployment();
  console.log("    proxy =", await orgRegistry.getAddress());

  // 2. DIDRegistry — depends on OrgRegistry
  console.log("\n[2/6] Deploying DIDRegistry…");
  const DIDFactory = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await upgrades.deployProxy(
    DIDFactory,
    [rootAdmin, await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await didRegistry.waitForDeployment();
  console.log("    proxy =", await didRegistry.getAddress());

  // 3. SchemaRegistry — depends on OrgRegistry
  console.log("\n[3/6] Deploying SchemaRegistry…");
  const SchemaFactory = await ethers.getContractFactory("SchemaRegistry");
  const schemaRegistry = await upgrades.deployProxy(
    SchemaFactory,
    [rootAdmin, await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await schemaRegistry.waitForDeployment();
  console.log("    proxy =", await schemaRegistry.getAddress());

  // 4. CredentialDefinitionRegistry — depends on SchemaRegistry + OrgRegistry
  console.log("\n[4/6] Deploying CredentialDefinitionRegistry…");
  const CredDefFactory = await ethers.getContractFactory("CredentialDefinitionRegistry");
  const credDefRegistry = await upgrades.deployProxy(
    CredDefFactory,
    [rootAdmin, await schemaRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await credDefRegistry.waitForDeployment();
  console.log("    proxy =", await credDefRegistry.getAddress());

  // 5. MerkleStateRegistry — depends on CredDef + OrgRegistry
  console.log("\n[5/6] Deploying MerkleStateRegistry…");
  const MsrFactory = await ethers.getContractFactory("MerkleStateRegistry");
  const msr = await upgrades.deployProxy(
    MsrFactory,
    [rootAdmin, await credDefRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await msr.waitForDeployment();
  console.log("    proxy =", await msr.getAddress());

  // 6. Halo2VerifierRegistry — independent
  console.log("\n[6/7] Deploying Halo2VerifierRegistry…");
  const VerifierFactory = await ethers.getContractFactory("Halo2VerifierRegistry");
  const verifierRegistry = await upgrades.deployProxy(VerifierFactory, [rootAdmin], {
    kind: "uups",
  });
  await verifierRegistry.waitForDeployment();
  console.log("    proxy =", await verifierRegistry.getAddress());

  // 7. AnonCredsStatusRegistry — AnonCreds VDR mode (per-credential status)
  console.log("\n[7/7] Deploying AnonCredsStatusRegistry…");
  const StatusFactory = await ethers.getContractFactory("AnonCredsStatusRegistry");
  const anonCredsStatusRegistry = await upgrades.deployProxy(
    StatusFactory,
    [rootAdmin, await credDefRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await anonCredsStatusRegistry.waitForDeployment();
  console.log("    proxy =", await anonCredsStatusRegistry.getAddress());

  // Without initializeV2 every Tier-2 setZkVerifier reverts with VerifierRegistryNotSet.
  console.log("\n[wire] MerkleStateRegistry.initializeV2 → verifierRegistry…");
  if (rootAdmin.toLowerCase() === (await deployer.getAddress()).toLowerCase()) {
    const initTx = await (msr as unknown as { initializeV2: (a: string) => Promise<{ wait: () => Promise<unknown> }> })
      .initializeV2(await verifierRegistry.getAddress());
    await initTx.wait();
    console.log("    ok");
  } else {
    console.log("    deferred: rootAdmin (" + rootAdmin + ") must call initializeV2(" + (await verifierRegistry.getAddress()) + ") manually");
  }

  // 8. KanonAddressBook — single directory of the seven registries (one address
  //    for consumers to wire, instead of seven).
  console.log("\n[8] Deploying KanonAddressBook…");
  const AddressBookFactory = await ethers.getContractFactory("KanonAddressBook");
  const addressBook = await upgrades.deployProxy(AddressBookFactory, [rootAdmin], { kind: "uups" });
  await addressBook.waitForDeployment();
  console.log("    proxy =", await addressBook.getAddress());

  /* eslint-disable @typescript-eslint/no-explicit-any */
  let seededOrgId: string | null = null;
  if (rootAdmin.toLowerCase() === (await deployer.getAddress()).toLowerCase()) {
    console.log("[wire] KanonAddressBook.setRegistries…");
    const setTx = await (addressBook as any).setRegistries({
      organizationRegistry: await orgRegistry.getAddress(),
      didRegistry: await didRegistry.getAddress(),
      schemaRegistry: await schemaRegistry.getAddress(),
      credentialDefinitionRegistry: await credDefRegistry.getAddress(),
      merkleStateRegistry: await msr.getAddress(),
      anonCredsStatusRegistry: await anonCredsStatusRegistry.getAddress(),
      halo2VerifierRegistry: await verifierRegistry.getAddress(),
    });
    await setTx.wait();
    console.log("    ok");

    // Seed an approved issuer org so the issuer agent can register schemas/cred-defs.
    console.log("[seed] registerOrg + approveOrg…");
    const orgName = process.env.KANON_SEED_ORG_NAME ?? "Kanon Issuer Org";
    const regRcpt = await (await (orgRegistry as any).registerOrg(orgName, await deployer.getAddress())).wait();
    for (const log of regRcpt.logs) {
      try {
        const parsed = (orgRegistry as any).interface.parseLog(log);
        // orgId is a random bytes32 — capture it as a 0x-prefixed hex string.
        if (parsed?.name === "OrgRegistered") { seededOrgId = parsed.args.orgId as string; break; }
      } catch { /* not from orgRegistry */ }
    }
    if (seededOrgId !== null) {
      await (await (orgRegistry as any).approveOrg(seededOrgId)).wait();
      console.log("    org", seededOrgId, "registered + approved");
      console.log("    org DID:", "did:kanon:org:" + seededOrgId);
    } else {
      console.log("    WARN: OrgRegistered event not found; org not seeded");
    }
  } else {
    console.log("[wire] deferred: rootAdmin must setRegistries(...) + seed an org manually");
  }
  /* eslint-enable @typescript-eslint/no-explicit-any */

  const deployment = {
    chainId,
    network: network.name,
    deployedAt: new Date().toISOString(),
    deployer: await deployer.getAddress(),
    rootAdmin,
    issuerOrgId: seededOrgId,
    addresses: {
      KanonAddressBook: await addressBook.getAddress(),
      OrganizationRegistry: await orgRegistry.getAddress(),
      DIDRegistry: await didRegistry.getAddress(),
      SchemaRegistry: await schemaRegistry.getAddress(),
      CredentialDefinitionRegistry: await credDefRegistry.getAddress(),
      MerkleStateRegistry: await msr.getAddress(),
      Halo2VerifierRegistry: await verifierRegistry.getAddress(),
      AnonCredsStatusRegistry: await anonCredsStatusRegistry.getAddress(),
    },
    implementations: {
      KanonAddressBook: await upgrades.erc1967.getImplementationAddress(
        await addressBook.getAddress()
      ),
      OrganizationRegistry: await upgrades.erc1967.getImplementationAddress(
        await orgRegistry.getAddress()
      ),
      DIDRegistry: await upgrades.erc1967.getImplementationAddress(await didRegistry.getAddress()),
      SchemaRegistry: await upgrades.erc1967.getImplementationAddress(
        await schemaRegistry.getAddress()
      ),
      CredentialDefinitionRegistry: await upgrades.erc1967.getImplementationAddress(
        await credDefRegistry.getAddress()
      ),
      MerkleStateRegistry: await upgrades.erc1967.getImplementationAddress(await msr.getAddress()),
      Halo2VerifierRegistry: await upgrades.erc1967.getImplementationAddress(
        await verifierRegistry.getAddress()
      ),
      AnonCredsStatusRegistry: await upgrades.erc1967.getImplementationAddress(
        await anonCredsStatusRegistry.getAddress()
      ),
    },
  };

  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `${chainId}.json`);
  fs.writeFileSync(outFile, JSON.stringify(deployment, null, 2));

  console.log("\n=================================================");
  console.log("kanon deployment written to", outFile);
  console.log("=================================================");
  console.log(JSON.stringify(deployment, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
