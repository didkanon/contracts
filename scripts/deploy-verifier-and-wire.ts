import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Mode B (ZK) post-deploy wiring.
 *
 * Run this AFTER `deploy.ts` has placed the seven core registries on chain,
 * and AFTER the trusted-setup ceremony has produced:
 *   contracts/verifiers/Groth16Verifier.sol   (snarkjs-exported)
 *   contracts/verifiers/non_revocation_vk.json
 *
 * This script:
 *   1. Deploys the snarkjs-generated `Groth16Verifier`.
 *   2. Deploys `Groth16NonRevocationVerifier(addrOfGroth16Verifier)` — the
 *      `IHalo2Verifier`-shaped adapter the registry expects.
 *   3. Calls `Halo2VerifierRegistry.registerVerifier(adapter)`.
 *   4. Updates the deployments JSON with both addresses.
 *
 * To bind a credential definition to this verifier:
 *   await merkleStateRegistry.setZkVerifier(credDefId, adapterAddress)
 * That call is per-credDef and is left to the operator/SDK.
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);

  const deployPath = path.join(__dirname, "..", "deployments", `${chainId}.json`);
  if (!fs.existsSync(deployPath)) {
    throw new Error(
      `No deployment record at ${deployPath}. Run scripts/deploy.ts first.`
    );
  }
  const record = JSON.parse(fs.readFileSync(deployPath, "utf-8")) as {
    addresses: Record<string, string>;
    implementations?: Record<string, string>;
  };

  const verifierRegistryAddress = record.addresses.Halo2VerifierRegistry;
  if (!verifierRegistryAddress) {
    throw new Error("Deployment record missing Halo2VerifierRegistry address.");
  }

  console.log("Network:", network.name, "chainId:", chainId);
  console.log("Deployer:", await deployer.getAddress());

  // 1. snarkjs-exported Groth16Verifier
  console.log("\n[1/3] Deploying Groth16Verifier (raw snarkjs verifier)…");
  const Groth16Factory = await ethers.getContractFactory("Groth16Verifier");
  const groth16 = await Groth16Factory.deploy();
  await groth16.waitForDeployment();
  const groth16Address = await groth16.getAddress();
  console.log("    address =", groth16Address);

  // 2. Adapter that implements IHalo2Verifier on top of the snarkjs verifier
  console.log("\n[2/3] Deploying Groth16NonRevocationVerifier (adapter)…");
  const AdapterFactory = await ethers.getContractFactory(
    "Groth16NonRevocationVerifier"
  );
  const adapter = await AdapterFactory.deploy(groth16Address);
  await adapter.waitForDeployment();
  const adapterAddress = await adapter.getAddress();
  console.log("    address =", adapterAddress);

  // 3. Register in the verifier registry so MerkleStateRegistry.setZkVerifier
  //    accepts it for per-credDef wiring.
  console.log("\n[3/3] Registering adapter in Halo2VerifierRegistry…");
  const registry = await ethers.getContractAt(
    "Halo2VerifierRegistry",
    verifierRegistryAddress
  );
  const tx = await registry.registerVerifier(adapterAddress);
  await tx.wait();
  console.log("    registerVerifier tx:", tx.hash);

  // 4. Persist
  record.addresses.Groth16Verifier = groth16Address;
  record.addresses.Groth16NonRevocationVerifier = adapterAddress;
  record.implementations = record.implementations || {};
  fs.writeFileSync(deployPath, JSON.stringify(record, null, 2));
  console.log("\nUpdated deployment record at", deployPath);
  console.log("=================================================");
  console.log("Mode B (ZK) verifier wired. Each credDef opts in via:");
  console.log("  merkleStateRegistry.setZkVerifier(credDefId, adapterAddress)");
  console.log("=================================================");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
