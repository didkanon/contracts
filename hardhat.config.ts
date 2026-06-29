import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-contract-sizer";
import "hardhat-gas-reporter";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      // besu-ajna (besu-dev) genesis is at the London fork — no PUSH0/transient storage.
      evmVersion: "london",
    },
  },
  networks: {
    hardhat: {
      blockGasLimit: 50_000_000,
      allowUnlimitedContractSize: false,
    },
    "besu-local": {
      url: process.env.BESU_LOCAL_RPC_URL || "http://localhost:8545",
      chainId: 1947,
      accounts: process.env.BESU_DEPLOYER_KEY ? [process.env.BESU_DEPLOYER_KEY] : [],
      timeout: 60_000,
      gasPrice: 0,
    },
    // ── Ajna Inc Besu network — public-facing RPC at besu.ajna.inc.
    //    QBFT consensus, chainId 1947, gasPrice 0 (consortium chain).
    //    Operator-only: requires BESU_AJNA_DEPLOYER_KEY in env at deploy time.
    //    Override BESU_AJNA_RPC_URL if you need to hit an internal RPC pod
    //    (e.g. via port-forward) instead of the public endpoint.
    "besu-ajna": {
      url: process.env.BESU_AJNA_RPC_URL || "https://besu.ajna.inc",
      chainId: Number(process.env.BESU_AJNA_CHAIN_ID || 1947),
      accounts: process.env.BESU_AJNA_DEPLOYER_KEY
        ? [process.env.BESU_AJNA_DEPLOYER_KEY]
        : [],
      timeout: 120_000,
      gasPrice: 0,
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
    outputFile: process.env.REPORT_GAS === "true" ? "gas-report.txt" : undefined,
    noColors: process.env.REPORT_GAS === "true",
  },
  contractSizer: {
    runOnCompile: false,
    strict: false,
  },
  mocha: {
    timeout: 120_000,
  },
};

export default config;
