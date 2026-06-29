// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {ICredentialDefinitionRegistry} from "../interfaces/ICredentialDefinitionRegistry.sol";
import {ISchemaRegistry} from "../interfaces/ISchemaRegistry.sol";
import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";

/// @title CredentialDefinitionRegistry
/// @notice Binds a schema to a specific issuer key + policy. Only members of the schema's
///         issuing organization may register credential definitions against it.
contract CredentialDefinitionRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ICredentialDefinitionRegistry
{
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");

    /// @notice Tier flags exposed to callers.
    uint8 public constant TIER_ONE_TIME = 1 << 0; // 0b01
    uint8 public constant TIER_ZK_SNARK = 1 << 1; // 0b10
    uint8 public constant TIER_ALL = TIER_ONE_TIME | TIER_ZK_SNARK; // 0b11

    /// @notice Maximum issuer public key length in bytes (BLS12-381 G2 compressed = 96 bytes; allow slack).
    uint256 public constant MAX_ISSUER_PUBKEY_LENGTH = 256;

    /// @notice BN254 scalar field prime. BabyJubjub point coordinates live in this
    ///         field — values >= this are not valid keys and would silently fail to
    ///         match anything the circuit produces.
    uint256 private constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @custom:storage-location erc7201:kanon.CredentialDefinitionRegistry
    struct CredDefStorage {
        mapping(bytes32 => CredentialDefinition) credDefs;
        ISchemaRegistry schemaRegistry;
        IOrganizationRegistry orgRegistry;
        // Tier 2 BabyJubjub issuer pubkey, set-once via `setIssuerZkPubKey`. Holding
        // ax/ay as uint256 lets the verifier compare directly against
        // `publicSignals[3]/[4]` without coordinate decoding.
        mapping(bytes32 => IssuerZkPubKey) issuerZkPubKeys;
        uint256[46] __gap;
    }

    bytes32 private constant CREDDEF_STORAGE_SLOT =
        0x8a3991a41e40eebb024b76621ed36fb622358d67357bb5d4ef611a9d8896e800;

    function _cdStorage() private pure returns (CredDefStorage storage s) {
        bytes32 slot = CREDDEF_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin, address schemaRegistry, address orgRegistry) external initializer {
        require(rootAdmin != address(0) && schemaRegistry != address(0) && orgRegistry != address(0), "ZeroAddr");
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
        _grantRole(CONFIG_ROLE, rootAdmin);
        CredDefStorage storage s = _cdStorage();
        s.schemaRegistry = ISchemaRegistry(schemaRegistry);
        s.orgRegistry = IOrganizationRegistry(orgRegistry);
    }

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc ICredentialDefinitionRegistry
    function registerCredentialDefinition(
        bytes32 credDefId,
        bytes32 schemaId,
        bytes calldata issuerPubKey,
        uint8 policyMask,
        string calldata uri,
        uint256 issuerZkPubKeyAx,
        uint256 issuerZkPubKeyAy
    ) external override whenNotPaused {
        if (credDefId == bytes32(0)) revert ZeroCredDefId();
        if (issuerPubKey.length == 0 || issuerPubKey.length > MAX_ISSUER_PUBKEY_LENGTH) {
            revert EmptyIssuerPubKey();
        }
        if (policyMask == 0 || (policyMask & ~TIER_ALL) != 0) revert InvalidPolicyMask(policyMask);

        CredDefStorage storage s = _cdStorage();
        if (s.credDefs[credDefId].createdAt != 0) revert CredDefAlreadyExists(credDefId);
        if (!s.schemaRegistry.isActive(schemaId)) revert SchemaNotActive(schemaId);

        ISchemaRegistry.Schema memory sc = s.schemaRegistry.getSchema(schemaId);
        if (!s.orgRegistry.isApprovedAndActive(sc.issuerOrg)) {
            revert IssuerOrgNotApprovedOrActive(sc.issuerOrg);
        }
        if (!s.orgRegistry.isMember(sc.issuerOrg, msg.sender)) {
            revert NotIssuerOrgMember(sc.issuerOrg, msg.sender);
        }

        // Tier 2 BabyJubjub key validation. The gating is policyMask-driven so
        // Mode A-only callers don't have to think about ZK at all. The key is
        // committed to the credDef record in the same tx — no separate setter,
        // no half-provisioned state, and matches the "credDef is immutable"
        // mental model the AnonCreds API already gives you.
        bool wantsZk = (policyMask & TIER_ZK_SNARK) != 0;
        if (wantsZk) {
            // Reject the BabyJubjub identity (ax=0 ∧ ay=1) — the circuit happily
            // accepts any signature under it, but it is never a real issuer key.
            // Also reject coordinates >= the BN254 scalar field; those values
            // can never match a `publicSignals` output from snarkjs and would
            // brick the credDef.
            if (issuerZkPubKeyAx >= BN254_SCALAR_FIELD || issuerZkPubKeyAy >= BN254_SCALAR_FIELD) {
                revert InvalidIssuerZkPubKey();
            }
            if (issuerZkPubKeyAx == 0 && issuerZkPubKeyAy == 0) revert InvalidIssuerZkPubKey();
            if (issuerZkPubKeyAx == 0 && issuerZkPubKeyAy == 1) revert InvalidIssuerZkPubKey();
        } else {
            // Mode A-only credDefs must not carry a ZK key. Catching this here
            // avoids silent misconfiguration — a caller that supplied ax/ay
            // probably meant to set the policy mask too.
            if (issuerZkPubKeyAx != 0 || issuerZkPubKeyAy != 0) revert UnexpectedIssuerZkPubKey();
        }

        s.credDefs[credDefId] = CredentialDefinition({
            schemaId: schemaId,
            issuerOrg: sc.issuerOrg,
            issuerPubKey: issuerPubKey,
            policyMask: policyMask,
            createdAt: uint64(block.timestamp),
            deprecated: false,
            uri: uri
        });
        emit CredentialDefinitionRegistered(credDefId, schemaId, sc.issuerOrg, policyMask);

        if (wantsZk) {
            s.issuerZkPubKeys[credDefId] = IssuerZkPubKey({
                ax: issuerZkPubKeyAx,
                ay: issuerZkPubKeyAy,
                set: true
            });
            emit IssuerZkPubKeySet(credDefId, issuerZkPubKeyAx, issuerZkPubKeyAy);
        }
    }

    /// @inheritdoc ICredentialDefinitionRegistry
    function deprecateCredentialDefinition(bytes32 credDefId) external override whenNotPaused {
        CredDefStorage storage s = _cdStorage();
        CredentialDefinition storage cd = s.credDefs[credDefId];
        if (cd.createdAt == 0) revert CredDefNotFound(credDefId);
        if (cd.deprecated) revert CredDefDeprecated_(credDefId);
        if (!s.orgRegistry.isMember(cd.issuerOrg, msg.sender)) {
            revert NotIssuerOrgMember(cd.issuerOrg, msg.sender);
        }
        cd.deprecated = true;
        emit CredentialDefinitionDeprecated(credDefId);
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc ICredentialDefinitionRegistry
    function getCredentialDefinition(bytes32 credDefId)
        external
        view
        override
        returns (CredentialDefinition memory)
    {
        CredDefStorage storage s = _cdStorage();
        CredentialDefinition memory cd = s.credDefs[credDefId];
        if (cd.createdAt == 0) revert CredDefNotFound(credDefId);
        return cd;
    }

    /// @inheritdoc ICredentialDefinitionRegistry
    function exists(bytes32 credDefId) external view override returns (bool) {
        return _cdStorage().credDefs[credDefId].createdAt != 0;
    }

    /// @inheritdoc ICredentialDefinitionRegistry
    function isActive(bytes32 credDefId) external view override returns (bool) {
        CredentialDefinition storage cd = _cdStorage().credDefs[credDefId];
        return cd.createdAt != 0 && !cd.deprecated;
    }

    /// @inheritdoc ICredentialDefinitionRegistry
    function supportsTier(bytes32 credDefId, uint8 tier) external view override returns (bool) {
        CredentialDefinition storage cd = _cdStorage().credDefs[credDefId];
        if (cd.createdAt == 0 || cd.deprecated) return false;
        return (cd.policyMask & tier) == tier && tier != 0;
    }

    /// @inheritdoc ICredentialDefinitionRegistry
    function getIssuerZkPubKey(bytes32 credDefId)
        external
        view
        override
        returns (IssuerZkPubKey memory)
    {
        return _cdStorage().issuerZkPubKeys[credDefId];
    }

    function schemaRegistry() external view returns (ISchemaRegistry) {
        return _cdStorage().schemaRegistry;
    }

    function orgRegistry() external view returns (IOrganizationRegistry) {
        return _cdStorage().orgRegistry;
    }

    function setSchemaRegistry(address newSchemaRegistry) external onlyRole(CONFIG_ROLE) {
        require(newSchemaRegistry != address(0), "ZeroAddr");
        _cdStorage().schemaRegistry = ISchemaRegistry(newSchemaRegistry);
    }

    function setOrgRegistry(address newOrgRegistry) external onlyRole(CONFIG_ROLE) {
        require(newOrgRegistry != address(0), "ZeroAddr");
        _cdStorage().orgRegistry = IOrganizationRegistry(newOrgRegistry);
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
