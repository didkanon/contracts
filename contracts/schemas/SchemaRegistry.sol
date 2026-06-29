// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {ISchemaRegistry} from "../interfaces/ISchemaRegistry.sol";
import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";

/// @title SchemaRegistry
/// @notice Schemas are published by approved-and-active organizations. The on-chain record is a
///         hash + URI tuple — the canonical JSON Schema lives off-chain and verifiers MUST
///         validate fetched JSON against the on-chain schemaHash before accepting it.
contract SchemaRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ISchemaRegistry
{
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");

    /// @custom:storage-location erc7201:kanon.SchemaRegistry
    struct SchemaStorage {
        mapping(bytes32 => Schema) schemas;
        IOrganizationRegistry orgRegistry;
        uint256[48] __gap;
    }

    bytes32 private constant SCHEMA_STORAGE_SLOT =
        0x0218941d0934cb96730a67fa3b2fd374974ab4864361c3d8c56b89e240f84200;

    function _schemaStorage() private pure returns (SchemaStorage storage s) {
        bytes32 slot = SCHEMA_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin, address orgRegistry_) external initializer {
        require(rootAdmin != address(0), "ZeroAdmin");
        require(orgRegistry_ != address(0), "ZeroOrgRegistry");
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
        _grantRole(CONFIG_ROLE, rootAdmin);
        _schemaStorage().orgRegistry = IOrganizationRegistry(orgRegistry_);
    }

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc ISchemaRegistry
    function registerSchema(bytes32 orgId, bytes32 schemaId, bytes32 schemaHash, string calldata uri)
        external
        override
        whenNotPaused
    {
        if (schemaId == bytes32(0)) revert ZeroSchemaId();
        if (schemaHash == bytes32(0)) revert ZeroSchemaHash();
        if (bytes(uri).length == 0) revert EmptyUri();
        SchemaStorage storage s = _schemaStorage();
        if (s.schemas[schemaId].createdAt != 0) revert SchemaAlreadyExists(schemaId);
        if (!s.orgRegistry.isApprovedAndActive(orgId)) revert OrgNotApprovedOrActive(orgId);
        if (!s.orgRegistry.isMember(orgId, msg.sender)) revert NotOrgMember(orgId, msg.sender);
        s.schemas[schemaId] = Schema({
            issuerOrg: orgId,
            schemaHash: schemaHash,
            uri: uri,
            createdAt: uint64(block.timestamp),
            deprecated: false
        });
        emit SchemaRegistered(schemaId, orgId, schemaHash, uri);
    }

    /// @inheritdoc ISchemaRegistry
    function deprecateSchema(bytes32 schemaId) external override whenNotPaused {
        SchemaStorage storage s = _schemaStorage();
        Schema storage sc = s.schemas[schemaId];
        if (sc.createdAt == 0) revert SchemaNotFound(schemaId);
        if (sc.deprecated) revert SchemaDeprecated_(schemaId);
        if (!s.orgRegistry.isMember(sc.issuerOrg, msg.sender)) revert NotOrgMember(sc.issuerOrg, msg.sender);
        sc.deprecated = true;
        emit SchemaDeprecated(schemaId);
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc ISchemaRegistry
    function getSchema(bytes32 schemaId) external view override returns (Schema memory) {
        SchemaStorage storage s = _schemaStorage();
        Schema memory sc = s.schemas[schemaId];
        if (sc.createdAt == 0) revert SchemaNotFound(schemaId);
        return sc;
    }

    /// @inheritdoc ISchemaRegistry
    function exists(bytes32 schemaId) external view override returns (bool) {
        return _schemaStorage().schemas[schemaId].createdAt != 0;
    }

    /// @inheritdoc ISchemaRegistry
    function isActive(bytes32 schemaId) external view override returns (bool) {
        Schema storage sc = _schemaStorage().schemas[schemaId];
        return sc.createdAt != 0 && !sc.deprecated;
    }

    function orgRegistry() external view returns (IOrganizationRegistry) {
        return _schemaStorage().orgRegistry;
    }

    function setOrgRegistry(address newOrgRegistry) external onlyRole(CONFIG_ROLE) {
        require(newOrgRegistry != address(0), "ZeroOrgRegistry");
        _schemaStorage().orgRegistry = IOrganizationRegistry(newOrgRegistry);
    }

    // ──────────────────────────────────────────────────────────────────
    // Pause + upgrade
    // ──────────────────────────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
