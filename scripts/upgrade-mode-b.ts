import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Upgrade BOTH live UUPS proxies for the Mode B v0.6.4 / SDK 0.1.9 work:
 *
 *   - `CredentialDefinitionRegistry`
 *       storage layout extended (added `mapping(bytes32 => IssuerZkPubKey)`,
 *       reduced `__gap` 47 → 46) and `registerCredentialDefinition` ABI
 *       changed (new `ax`, `ay` positional args).
 *
 *   - `MerkleStateRegistry`
 *       no storage changes; `verifyZKMembership` now reads from
 *       `getIssuerZkPubKey`, binds `publicSignals[1]` to
 *       `uint256(credDefId) mod BN254_SCALAR_FIELD`.
 *
 * Both are upgradeable via OpenZeppelin UUPS. The deployer in
 * `deployments/<chainId>.json` must hold `UPGRADER_ROLE` on each proxy (set
 * by the initial deploy script, persisted on chain).
 *
 * Run (source .env first so BESU_AJNA_DEPLOYER_KEY is loaded; the operator
 * key MUST NEVER be echoed):
 *
 *   set -a; . ./.env; set +a
 *   npx hardhat run scripts/upgrade-mode-b.ts --network besu-ajna
 *
 * The script writes the new implementation addresses back to the
 * deployments JSON and prints a summary suitable for the upgrade transcript.
 */
async function main() {
  const deploymentsPath = path.join(
    __dirname,
    "..",
    "deployments",
    `${network.config.chainId}.json`
  );
  if (!fs.existsSync(deploymentsPath)) {
    throw new Error(`No deployments file at ${deploymentsPath}`);
  }
  const deployment = JSON.parse(fs.readFileSync(deploymentsPath, "utf8"));

  console.log("Network: %s (chainId %s)", network.name, network.config.chainId);
  console.log("Deployer: %s", deployment.deployer);

  const targets = [
    {
      name: "CredentialDefinitionRegistry",
      contractName: "CredentialDefinitionRegistry",
    },
    { name: "MerkleStateRegistry", contractName: "MerkleStateRegistry" },
  ] as const;

  const results: Array<{
    name: string;
    proxy: string;
    oldImpl: string;
    newImpl: string;
    changed: boolean;
  }> = [];

  for (const target of targets) {
    const proxy: string = deployment.addresses[target.name];
    if (!proxy) {
      throw new Error(`Missing proxy address for ${target.name} in deployments JSON`);
    }
    const oldImpl = await upgrades.erc1967.getImplementationAddress(proxy);
    console.log(`\n[${target.name}]`);
    console.log("  proxy:         ", proxy);
    console.log("  old impl:      ", oldImpl);

    const Factory = await ethers.getContractFactory(target.contractName);

    // `redeployImplementation: "always"` forces a fresh implementation deploy
    // even if the bytecode hasn't changed since the last upgrade — useful for
    // re-uploading after source-level patches that don't affect bytecode
    // (e.g. comment changes), but in our case the bytecode IS different.
    const upgraded = await upgrades.upgradeProxy(proxy, Factory, {
      kind: "uups",
      redeployImplementation: "always",
    });
    await upgraded.waitForDeployment();

    const newImpl = await upgrades.erc1967.getImplementationAddress(proxy);
    console.log("  new impl:      ", newImpl);
    console.log("  changed:       ", oldImpl.toLowerCase() !== newImpl.toLowerCase());

    results.push({
      name: target.name,
      proxy,
      oldImpl,
      newImpl,
      changed: oldImpl.toLowerCase() !== newImpl.toLowerCase(),
    });

    // Update in-memory deployment record.
    deployment.implementations[target.name] = newImpl;
  }

  deployment.upgradedAt = new Date().toISOString();
  fs.writeFileSync(deploymentsPath, JSON.stringify(deployment, null, 2) + "\n");
  console.log("\nUpdated", deploymentsPath);

  // Post-upgrade sanity reads — verifies the new ABI is callable on chain.
  console.log("\n--- post-upgrade sanity ---");
  const credDef = await ethers.getContractAt(
    "CredentialDefinitionRegistry",
    deployment.addresses.CredentialDefinitionRegistry
  );
  // The view will return `{ax: 0, ay: 0, set: false}` for any unknown id;
  // success here means the new selector is wired.
  const sentinelId =
    "0x0000000000000000000000000000000000000000000000000000000000000001";
  const zkKey = await credDef.getIssuerZkPubKey(sentinelId);
  console.log("getIssuerZkPubKey(sentinel) ->", {
    ax: zkKey.ax.toString(),
    ay: zkKey.ay.toString(),
    set: zkKey.set,
  });

  console.log("\n--- upgrade transcript ---");
  for (const r of results) {
    console.log(
      `${r.name.padEnd(32)}  ${r.proxy}  ${r.oldImpl} -> ${r.newImpl}  (changed: ${r.changed})`
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
