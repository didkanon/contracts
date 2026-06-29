import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256 } from "ethers";

import { deploySystem, setupApprovedOrg, registerOrgAndGetId } from "./helpers/fixtures";

describe("SchemaRegistry", () => {
  const schemaId = keccak256(ethers.toUtf8Bytes("KYC-v1"));
  const schemaHash = keccak256(ethers.toUtf8Bytes("schema-content"));
  const uri = "ipfs://Qm-schema-v1";

  describe("registerSchema", () => {
    it("approved org member can register; emits SchemaRegistered", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys, [sys.member1]);
      await expect(sys.schemaRegistry.connect(sys.member1).registerSchema(orgId, schemaId, schemaHash, uri))
        .to.emit(sys.schemaRegistry, "SchemaRegistered")
        .withArgs(schemaId, orgId, schemaHash, uri);
      const sc = await sys.schemaRegistry.getSchema(schemaId);
      expect(sc.issuerOrg).to.equal(orgId);
      expect(sc.schemaHash).to.equal(schemaHash);
      expect(sc.uri).to.equal(uri);
      expect(sc.deprecated).to.equal(false);
    });

    it("non-member is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await expect(
        sys.schemaRegistry.connect(sys.other).registerSchema(orgId, schemaId, schemaHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "NotOrgMember");
    });

    it("non-approved org is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      // Register but don't approve
      const adminAddr = await sys.orgAdmin.getAddress();
      const orgId = await registerOrgAndGetId(sys.orgRegistry, sys.orgAdmin, "Org", adminAddr);
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "OrgNotApprovedOrActive");
    });

    it("suspended org cannot register new schemas", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await sys.orgRegistry.connect(sys.rootAdmin).suspendOrg(orgId);
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "OrgNotApprovedOrActive");
    });

    it("duplicate schemaId is rejected", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri);
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "SchemaAlreadyExists");
    });

    it("zero schemaId / hash / empty URI revert", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, ethers.ZeroHash, schemaHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "ZeroSchemaId");
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, ethers.ZeroHash, uri)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "ZeroSchemaHash");
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, "")
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "EmptyUri");
    });
  });

  describe("deprecateSchema", () => {
    it("only org member can deprecate", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri);
      await expect(
        sys.schemaRegistry.connect(sys.other).deprecateSchema(schemaId)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "NotOrgMember");
      await expect(sys.schemaRegistry.connect(sys.orgAdmin).deprecateSchema(schemaId))
        .to.emit(sys.schemaRegistry, "SchemaDeprecated")
        .withArgs(schemaId);
      expect(await sys.schemaRegistry.isActive(schemaId)).to.equal(false);
      expect(await sys.schemaRegistry.exists(schemaId)).to.equal(true);
    });

    it("cannot deprecate twice", async () => {
      const sys = await loadFixture(deploySystem);
      const orgId = await setupApprovedOrg(sys);
      await sys.schemaRegistry.connect(sys.orgAdmin).registerSchema(orgId, schemaId, schemaHash, uri);
      await sys.schemaRegistry.connect(sys.orgAdmin).deprecateSchema(schemaId);
      await expect(
        sys.schemaRegistry.connect(sys.orgAdmin).deprecateSchema(schemaId)
      ).to.be.revertedWithCustomError(sys.schemaRegistry, "SchemaDeprecated_");
    });
  });

  describe("queries", () => {
    it("getSchema reverts on unknown id", async () => {
      const sys = await loadFixture(deploySystem);
      await expect(sys.schemaRegistry.getSchema(schemaId)).to.be.revertedWithCustomError(
        sys.schemaRegistry,
        "SchemaNotFound"
      );
    });
  });
});
