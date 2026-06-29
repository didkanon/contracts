import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Upgrade the live CredentialDefinitionRegistry UUPS proxy in place.
 *
 * Adds the new `string uri` field to the CredentialDefinition struct without
 * a fresh deploy, preserving all org/DID/schema/cred-def state. The struct is a
 * mapping value, so appending a field is storage-layout-safe.
 *
 * Run:
 *   set -a; . ./.env; set +a; npx hardhat run scripts/upgrade-creddef.ts --network besu-ajna
 */
async function main() {
  const deploymentsPath = path.join(__dirname, "..", "deployments", `${network.config.chainId}.json`);
  const deployment = JSON.parse(fs.readFileSync(deploymentsPath, "utf8"));
  const proxyAddr: string = deployment.addresses.CredentialDefinitionRegistry;
  if (!proxyAddr) throw new Error("CredentialDefinitionRegistry proxy address not found in deployments file");

  const oldImpl = await upgrades.erc1967.getImplementationAddress(proxyAddr);
  console.log("Network:        ", network.name, "(chainId", network.config.chainId, ")");
  console.log("Proxy:          ", proxyAddr);
  console.log("Old implementation:", oldImpl);

  // Pick an existing cred-def to verify state preservation, if any are recorded.
  const Factory = await ethers.getContractFactory("CredentialDefinitionRegistry");
  const upgraded = await upgrades.upgradeProxy(proxyAddr, Factory, {
    kind: "uups",
    redeployImplementation: "always",
  });
  await upgraded.waitForDeployment();

  const newImpl = await upgrades.erc1967.getImplementationAddress(proxyAddr);
  console.log("New implementation:", newImpl);
  console.log("Implementation changed:", oldImpl.toLowerCase() !== newImpl.toLowerCase());

  // Persist the new implementation address.
  deployment.implementations.CredentialDefinitionRegistry = newImpl;
  deployment.upgradedAt = new Date().toISOString();
  fs.writeFileSync(deploymentsPath, JSON.stringify(deployment, null, 2) + "\n");
  console.log("Updated", deploymentsPath);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
