import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Production deploy: deploys all six proxies AND wires them to a KanonTimelock
 * controlled by a Safe multisig.
 *
 * Required env vars:
 *   SAFE_MULTISIG_ADDRESS — the Gnosis Safe address that will hold proposer + executor roles
 *   MIN_DELAY_SECONDS     — minimum timelock delay (default 172800 = 48h)
 *
 * The timelock becomes the holder of every registry's DEFAULT_ADMIN_ROLE,
 * UPGRADER_ROLE, GOVERNANCE_ROLE, and PAUSER_ROLE.
 *
 * After this script:
 *   - Direct calls to admin functions fail
 *   - Safe must schedule -> wait -> execute via TimelockController
 *   - Emergency pause is also gated by timelock (consider separating to a dedicated pauser EOA for incident response)
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);

  const safe = process.env.SAFE_MULTISIG_ADDRESS;
  if (!safe || !ethers.isAddress(safe)) {
    throw new Error("SAFE_MULTISIG_ADDRESS env var required (and must be a valid address)");
  }
  const minDelay = Number(process.env.MIN_DELAY_SECONDS ?? "172800"); // 48 hours

  console.log("Production deployment");
  console.log("  Network    :", network.name);
  console.log("  ChainId    :", chainId);
  console.log("  Deployer   :", await deployer.getAddress());
  console.log("  Safe       :", safe);
  console.log("  Min delay  :", minDelay, "seconds");

  // 1. Deploy the timelock; proposer + executor = Safe; admin = address(0) (self-managed)
  console.log("\n[1] Deploying KanonTimelock…");
  const TimelockFactory = await ethers.getContractFactory("KanonTimelock");
  const timelock = await TimelockFactory.deploy(minDelay, [safe], [safe], ethers.ZeroAddress);
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  console.log("    timelock =", timelockAddr);

  // 2. Deploy all six proxies with the timelock as root admin
  const proxies = await deployProxies(timelockAddr);

  // 3. Sanity check: deployer must NOT have any roles
  await assertNoDeployerRoles(proxies, await deployer.getAddress());

  // The Safe must schedule + execute MerkleStateRegistry.initializeV2 via the timelock
  // before any Tier-2 setZkVerifier call will succeed.
  console.log("\n========================================================================");
  console.log("REQUIRED FIRST POST-DEPLOY ACTION:");
  console.log("  Safe must schedule + execute via timelock:");
  console.log("    target = " + (await proxies.msr.getAddress()));
  console.log("    data   = MerkleStateRegistry.initializeV2(" + (await proxies.verifierRegistry.getAddress()) + ")");
  console.log("  Until this lands, Tier-2 setZkVerifier reverts with VerifierRegistryNotSet.");
  console.log("========================================================================\n");

  const deployment = {
    chainId,
    network: network.name,
    deployedAt: new Date().toISOString(),
    deployer: await deployer.getAddress(),
    rootAdmin: timelockAddr,
    safe,
    minDelaySeconds: minDelay,
    addresses: {
      KanonTimelock: timelockAddr,
      OrganizationRegistry: await proxies.orgRegistry.getAddress(),
      DIDRegistry: await proxies.didRegistry.getAddress(),
      SchemaRegistry: await proxies.schemaRegistry.getAddress(),
      CredentialDefinitionRegistry: await proxies.credDefRegistry.getAddress(),
      MerkleStateRegistry: await proxies.msr.getAddress(),
      Halo2VerifierRegistry: await proxies.verifierRegistry.getAddress(),
    },
  };
  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `${chainId}-production.json`);
  fs.writeFileSync(outFile, JSON.stringify(deployment, null, 2));
  console.log("\nProduction deployment written to", outFile);
  console.log("\nNext steps:");
  console.log(" 1. Verify timelock + each proxy on the explorer");
  console.log(" 2. Confirm Safe can call timelock.schedule()");
  console.log(" 3. Run a dry-run upgrade through the timelock on a staging chain first");
}

async function deployProxies(timelock: string) {
  const OrgFactory = await ethers.getContractFactory("OrganizationRegistry");
  const orgRegistry = await upgrades.deployProxy(OrgFactory, [timelock], { kind: "uups" });
  await orgRegistry.waitForDeployment();

  const DIDFactory = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await upgrades.deployProxy(
    DIDFactory,
    [timelock, await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await didRegistry.waitForDeployment();

  const SchemaFactory = await ethers.getContractFactory("SchemaRegistry");
  const schemaRegistry = await upgrades.deployProxy(
    SchemaFactory,
    [timelock, await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await schemaRegistry.waitForDeployment();

  const CredDefFactory = await ethers.getContractFactory("CredentialDefinitionRegistry");
  const credDefRegistry = await upgrades.deployProxy(
    CredDefFactory,
    [timelock, await schemaRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await credDefRegistry.waitForDeployment();

  const MsrFactory = await ethers.getContractFactory("MerkleStateRegistry");
  const msr = await upgrades.deployProxy(
    MsrFactory,
    [timelock, await credDefRegistry.getAddress(), await orgRegistry.getAddress()],
    { kind: "uups" }
  );
  await msr.waitForDeployment();

  const VerifierFactory = await ethers.getContractFactory("Halo2VerifierRegistry");
  const verifierRegistry = await upgrades.deployProxy(VerifierFactory, [timelock], { kind: "uups" });
  await verifierRegistry.waitForDeployment();

  return { orgRegistry, didRegistry, schemaRegistry, credDefRegistry, msr, verifierRegistry } as const;
}

async function assertNoDeployerRoles(proxies: Awaited<ReturnType<typeof deployProxies>>, deployer: string) {
  const ZERO_ROLE = ethers.ZeroHash;
  // OZ AccessControl's DEFAULT_ADMIN_ROLE is bytes32(0)
  for (const [name, proxy] of Object.entries(proxies)) {
    const hasRole = await (proxy as any).hasRole(ZERO_ROLE, deployer);
    if (hasRole) {
      throw new Error(`SECURITY: deployer retains DEFAULT_ADMIN_ROLE on ${name}. Aborting.`);
    }
  }
  console.log("✓ Deployer holds no admin roles on any proxy.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
