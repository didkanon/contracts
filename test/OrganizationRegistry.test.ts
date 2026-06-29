import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

import { deploySystem, registerOrgAndGetId } from "./helpers/fixtures";

const ZERO32 = "0x" + "00".repeat(32);

/** Register an org (as orgAdmin) and return its random bytes32 id from the event. */
async function register(
  sys: Awaited<ReturnType<typeof deploySystem>>,
  did: string,
  admin: string
): Promise<string> {
  return registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, did, admin);
}

describe("OrganizationRegistry", () => {
  describe("initialize", () => {
    it("grants all roles to the root admin", async () => {
      const sys = await loadFixture(deploySystem);
      const adminAddr = await sys.rootAdmin.getAddress();
      const DEFAULT_ADMIN_ROLE = "0x" + "00".repeat(32);
      expect(await sys.orgRegistry.hasRole(DEFAULT_ADMIN_ROLE, adminAddr)).to.equal(true);
      expect(await sys.orgRegistry.hasRole(await sys.orgRegistry.GOVERNANCE_ROLE(), adminAddr)).to.equal(true);
      expect(await sys.orgRegistry.hasRole(await sys.orgRegistry.PAUSER_ROLE(), adminAddr)).to.equal(true);
      expect(await sys.orgRegistry.hasRole(await sys.orgRegistry.UPGRADER_ROLE(), adminAddr)).to.equal(true);
    });

    it("cannot be initialized twice", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(sys.orgRegistry.initialize(await sys.rootAdmin.getAddress())).to.be.reverted;
    });

    it("rejects zero root admin", async () => {
      const Factory = await ethers.getContractFactory("OrganizationRegistry");
      await expect(
        upgrades.deployProxy(Factory, [ethers.ZeroAddress], { kind: "uups" })
      ).to.be.revertedWithCustomError(Factory, "ZeroAdmin");
    });
  });

  describe("registerOrg", () => {
    it("emits OrgRegistered with a random, non-zero, unique bytes32 id", async () => {
      const sys = await loadFixture(deploySystem);
      const adminAddr = await sys.orgAdmin.getAddress();
      const id1 = await register(sys, "Org One", adminAddr);
      const id2 = await register(sys, "Org Two", adminAddr);
      expect(id1).to.not.equal(ZERO32);
      expect(id2).to.not.equal(ZERO32);
      expect(id1).to.not.equal(id2);
      expect(id1).to.match(/^0x[0-9a-f]{64}$/);
      // Stored org reflects the supplied did.
      expect((await sys.orgRegistry.getOrg(id1)).did).to.equal("Org One");
    });

    it("rejects empty did", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.orgRegistry.connect(sys.orgAdmin).registerOrg("", await sys.orgAdmin.getAddress())
      ).to.be.revertedWithCustomError(sys.orgRegistry, "EmptyDid");
    });

    it("rejects zero admin", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(
        sys.orgRegistry.connect(sys.orgAdmin).registerOrg("Org", ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAdmin");
    });
  });

  describe("approveOrg / suspendOrg / reactivateOrg", () => {
    it("only GOVERNANCE_ROLE can approve", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      await expect(sys.orgRegistry.connect(sys.orgAdmin).approveOrg(id)).to.be.reverted;
      await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
      expect(await sys.orgRegistry.isApprovedAndActive(id)).to.equal(true);
    });

    it("approval is idempotent-safe: already-approved-and-active reverts", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
      await expect(sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id)).to.be.revertedWithCustomError(
        sys.orgRegistry,
        "OrgAlreadyApproved"
      );
    });

    it("can suspend then reactivate", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id);
      expect(await sys.orgRegistry.isApprovedAndActive(id)).to.equal(false);
      await sys.orgRegistry.connect(sys.rootAdmin).reactivateOrg(id);
      expect(await sys.orgRegistry.isApprovedAndActive(id)).to.equal(true);
    });

    it("cannot suspend a never-approved org", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      await expect(sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(id)).to.be.revertedWithCustomError(
        sys.orgRegistry,
        "OrgNotApproved"
      );
    });
  });

  describe("admin transfer", () => {
    it("only current admin can transfer; emits OrgAdminTransferred", async () => {
      const sys = await loadFixture(deploySystem);
      const oldAdmin = await sys.orgAdmin.getAddress();
      const newAdmin = await sys.member1.getAddress();
      const id = await register(sys, "Org", oldAdmin);
      await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(id);
      await expect(
        sys.orgRegistry.connect(sys.other).transferOrgAdmin(id, newAdmin)
      ).to.be.revertedWithCustomError(sys.orgRegistry, "NotOrgAdmin");
      await expect(sys.orgRegistry.connect(sys.orgAdmin).transferOrgAdmin(id, newAdmin))
        .to.emit(sys.orgRegistry, "OrgAdminTransferred")
        .withArgs(id, oldAdmin, newAdmin);
    });

    it("rejects transfer to same admin", async () => {
      const sys = await loadFixture(deploySystem);
      const admin = await sys.orgAdmin.getAddress();
      const id = await register(sys, "Org", admin);
      await expect(sys.orgRegistry.connect(sys.orgAdmin).transferOrgAdmin(id, admin)).to.be.revertedWithCustomError(
        sys.orgRegistry,
        "SameAdmin"
      );
    });
  });

  describe("membership", () => {
    it("admin is implicitly a member; non-members start false", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      expect(await sys.orgRegistry.isMember(id, await sys.orgAdmin.getAddress())).to.equal(true);
      expect(await sys.orgRegistry.isMember(id, await sys.member1.getAddress())).to.equal(false);
    });

    it("addMember/removeMember are admin-only and emit events", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      const m = await sys.member1.getAddress();
      await expect(sys.orgRegistry.connect(sys.orgAdmin).addMember(id, m))
        .to.emit(sys.orgRegistry, "MemberAdded")
        .withArgs(id, m);
      expect(await sys.orgRegistry.isMember(id, m)).to.equal(true);
      await expect(sys.orgRegistry.connect(sys.other).addMember(id, await sys.member2.getAddress())).to.be.reverted;
      await expect(sys.orgRegistry.connect(sys.orgAdmin).addMember(id, m)).to.be.revertedWithCustomError(
        sys.orgRegistry,
        "MemberAlreadyAdded"
      );
      await expect(sys.orgRegistry.connect(sys.orgAdmin).removeMember(id, m))
        .to.emit(sys.orgRegistry, "MemberRemoved")
        .withArgs(id, m);
      expect(await sys.orgRegistry.isMember(id, m)).to.equal(false);
    });

    it("removing a non-member reverts", async () => {
      const sys = await loadFixture(deploySystem);
      const id = await register(sys, "Org", await sys.orgAdmin.getAddress());
      await expect(
        sys.orgRegistry.connect(sys.orgAdmin).removeMember(id, await sys.member1.getAddress())
      ).to.be.revertedWithCustomError(sys.orgRegistry, "MemberNotFound");
    });
  });

  describe("pause", () => {
    it("PAUSER_ROLE can pause; writes revert while paused", async () => {
      const sys = await loadFixture(deploySystem);
      await sys.orgRegistry.connect(sys.rootAdmin).pause();
      await expect(
        sys.orgRegistry.connect(sys.orgAdmin).registerOrg("Org", await sys.orgAdmin.getAddress())
      ).to.be.revertedWithCustomError(sys.orgRegistry, "EnforcedPause");
      await sys.orgRegistry.connect(sys.rootAdmin).unpause();
      await sys.orgRegistry.connect(sys.orgAdmin).registerOrg("Org", await sys.orgAdmin.getAddress());
    });
  });

  describe("queries", () => {
    it("getOrg returns full struct; reverts for missing org", async () => {
      const sys = await loadFixture(deploySystem);
      const missing = "0x" + "ff".repeat(32);
      await expect(sys.orgRegistry.getOrg(missing)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
      const id = await register(sys, "Org Seven", await sys.orgAdmin.getAddress());
      const o = await sys.orgRegistry.getOrg(id);
      expect(o.did).to.equal("Org Seven");
      expect(o.approved).to.equal(false);
    });
  });
});
