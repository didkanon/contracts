import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

import { deploySystem, deployMockHalo2Verifier } from "./helpers/fixtures";

describe("Halo2VerifierRegistry", () => {
  describe("registerVerifier", () => {
    it("CIRCUIT_REGISTRAR_ROLE can register a conforming verifier", async () => {
      const sys = await loadFixture(deploySystem);
      const v = await deployMockHalo2Verifier(true, "0x" + "11".repeat(32));
      await expect(sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v.getAddress()))
        .to.emit(sys.verifierRegistry, "VerifierRegistered")
        .withArgs("0x" + "11".repeat(32), await v.getAddress());
      expect(await sys.verifierRegistry.verifierFor("0x" + "11".repeat(32))).to.equal(await v.getAddress());
      const versions = await sys.verifierRegistry.knownVersions();
      expect(versions.length).to.equal(1);
      expect(versions[0]).to.equal("0x" + "11".repeat(32));
    });

    it("rejects zero verifier address", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(sys.verifierRegistry, "ZeroVerifier");
    });

    it("rejects non-CIRCUIT_REGISTRAR_ROLE caller", async () => {
      const sys = await loadFixture(deploySystem);
      const v = await deployMockHalo2Verifier(true);
      await expect(sys.verifierRegistry.connect(sys.other).registerVerifier(await v.getAddress())).to.be
        .reverted;
    });

    it("rejects duplicate version registration", async () => {
      const sys = await loadFixture(deploySystem);
      const version = "0x" + "22".repeat(32);
      const v1 = await deployMockHalo2Verifier(true, version);
      const v2 = await deployMockHalo2Verifier(true, version);
      await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v1.getAddress());
      await expect(
        sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v2.getAddress())
      ).to.be.revertedWithCustomError(sys.verifierRegistry, "VerifierAlreadyRegistered");
    });

    it("rejects a verifier whose circuitVersion() reverts", async () => {
      const sys = await loadFixture(deploySystem);
      const Reverting = await ethers.getContractFactory("RevertingVerifier");
      const r = await Reverting.deploy();
      await r.waitForDeployment();
      await expect(sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await r.getAddress())).to.be
        .reverted;
    });
  });

  describe("verifierFor", () => {
    it("reverts on unknown circuit version", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.verifierRegistry.verifierFor("0x" + "ff".repeat(32))
      ).to.be.revertedWithCustomError(sys.verifierRegistry, "UnknownCircuitVersion");
    });
  });

  describe("knownVersions", () => {
    it("returns versions in registration order", async () => {
      const sys = await loadFixture(deploySystem);
      const v1 = await deployMockHalo2Verifier(true, "0x" + "01".repeat(32));
      const v2 = await deployMockHalo2Verifier(true, "0x" + "02".repeat(32));
      const v3 = await deployMockHalo2Verifier(true, "0x" + "03".repeat(32));
      for (const v of [v1, v2, v3]) {
        await sys.verifierRegistry.connect(sys.rootAdmin).registerVerifier(await v.getAddress());
      }
      const versions = await sys.verifierRegistry.knownVersions();
      expect(versions).to.deep.equal(["0x" + "01".repeat(32), "0x" + "02".repeat(32), "0x" + "03".repeat(32)]);
    });
  });
});
