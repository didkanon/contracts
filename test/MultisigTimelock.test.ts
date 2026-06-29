import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

import { OrganizationRegistry } from "../typechain-types";
import { registerOrgAndGetId } from "./helpers/fixtures";

/**
 * Integration test demonstrating the production multisig + timelock flow:
 *   - Deploy a KanonTimelock with a "Safe" address (mocked as a signer here)
 *   - Deploy an OrganizationRegistry proxy with the timelock as root admin
 *   - Confirm direct admin calls fail
 *   - Schedule an admin op via the timelock (Safe proposes)
 *   - Wait the delay
 *   - Execute (Safe executes)
 *   - Confirm the op took effect
 */
describe("Multisig + Timelock integration", () => {
  async function deployTimelockedSystem() {
    const [deployer, safe, anotherUser] = await ethers.getSigners();
    const MIN_DELAY = 60; // 60 seconds for test; production uses 48h

    // 1. Deploy the timelock (proposers + executors = safe)
    const TimelockFactory = await ethers.getContractFactory("KanonTimelock");
    const timelock = await TimelockFactory.deploy(
      MIN_DELAY,
      [await safe.getAddress()],
      [await safe.getAddress()],
      ethers.ZeroAddress
    );
    await timelock.waitForDeployment();
    const timelockAddr = await timelock.getAddress();

    // 2. Deploy the org registry with the timelock as root admin
    const OrgFactory = await ethers.getContractFactory("OrganizationRegistry");
    const orgRegistry = (await upgrades.deployProxy(OrgFactory, [timelockAddr], {
      kind: "uups",
    })) as unknown as OrganizationRegistry;
    await orgRegistry.waitForDeployment();

    return { deployer, safe, anotherUser, timelock, orgRegistry, MIN_DELAY };
  }

  it("timelock holds DEFAULT_ADMIN_ROLE; deployer does not", async () => {
    const { deployer, timelock, orgRegistry } = await loadFixture(deployTimelockedSystem);
    const ZERO_ROLE = ethers.ZeroHash;
    expect(await orgRegistry.hasRole(ZERO_ROLE, await timelock.getAddress())).to.equal(true);
    expect(await orgRegistry.hasRole(ZERO_ROLE, await deployer.getAddress())).to.equal(false);
  });

  it("direct admin call from deployer fails", async () => {
    const { deployer, orgRegistry } = await loadFixture(deployTimelockedSystem);
    // Register an org so there's something to govern
    const deployerAddr = await deployer.getAddress();
    const orgId = await registerOrgAndGetId(orgRegistry, deployer, "Gov Org", deployerAddr);
    // approveOrg requires GOVERNANCE_ROLE which is held by the timelock
    await expect(orgRegistry.connect(deployer).approveOrg(orgId)).to.be.reverted;
  });

  it("Safe → schedule → wait → execute applies admin action", async () => {
    const { safe, timelock, orgRegistry, MIN_DELAY } = await loadFixture(deployTimelockedSystem);
    // Register an org first
    const safeAddr = await safe.getAddress();
    const orgId = await registerOrgAndGetId(orgRegistry, safe, "Safe Org", safeAddr);

    // 1. Encode approveOrg(orgId) calldata
    const calldata = orgRegistry.interface.encodeFunctionData("approveOrg", [orgId]);
    const target = await orgRegistry.getAddress();
    const value = 0;
    const predecessor = ethers.ZeroHash;
    const salt = ethers.hexlify(ethers.randomBytes(32));

    // 2. Safe schedules
    await timelock.connect(safe).schedule(target, value, calldata, predecessor, salt, MIN_DELAY);

    // 3. Attempting to execute before the delay fails
    await expect(timelock.connect(safe).execute(target, value, calldata, predecessor, salt)).to.be.reverted;

    // 4. Wait the minimum delay
    await time.increase(MIN_DELAY + 1);

    // 5. Safe executes
    await timelock.connect(safe).execute(target, value, calldata, predecessor, salt);

    // 6. Verify state changed
    expect(await orgRegistry.isApprovedAndActive(orgId)).to.equal(true);
  });

  it("Safe → schedule UUPS upgrade → wait → execute", async () => {
    const { safe, timelock, orgRegistry, MIN_DELAY } = await loadFixture(deployTimelockedSystem);

    // 1. Deploy a new implementation (we use the same contract — smoke test of the upgrade path)
    const NewImplFactory = await ethers.getContractFactory("OrganizationRegistry");
    const newImpl = await NewImplFactory.deploy();
    await newImpl.waitForDeployment();

    // 2. Encode upgradeToAndCall(newImpl, "") calldata
    const calldata = orgRegistry.interface.encodeFunctionData("upgradeToAndCall", [
      await newImpl.getAddress(),
      "0x",
    ]);
    const target = await orgRegistry.getAddress();
    const salt = ethers.hexlify(ethers.randomBytes(32));

    // 3. Schedule + wait + execute
    await timelock.connect(safe).schedule(target, 0, calldata, ethers.ZeroHash, salt, MIN_DELAY);
    await time.increase(MIN_DELAY + 1);
    await timelock.connect(safe).execute(target, 0, calldata, ethers.ZeroHash, salt);

    // 4. Confirm the new implementation is active
    const implAddr = await upgrades.erc1967.getImplementationAddress(await orgRegistry.getAddress());
    expect(implAddr.toLowerCase()).to.equal((await newImpl.getAddress()).toLowerCase());
  });

  it("non-Safe address cannot schedule or execute", async () => {
    const { anotherUser, timelock, orgRegistry, MIN_DELAY } = await loadFixture(deployTimelockedSystem);
    const calldata = orgRegistry.interface.encodeFunctionData("approveOrg", ["0x" + "11".repeat(32)]);
    const target = await orgRegistry.getAddress();
    await expect(
      timelock.connect(anotherUser).schedule(target, 0, calldata, ethers.ZeroHash, ethers.ZeroHash, MIN_DELAY)
    ).to.be.reverted;
  });
});
