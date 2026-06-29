// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IAnonCredsStatusRegistry} from "../interfaces/IAnonCredsStatusRegistry.sol";
import {ICredentialDefinitionRegistry} from "../interfaces/ICredentialDefinitionRegistry.sol";
import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";

/// @title AnonCredsStatusRegistry
/// @notice Per-credential issuance + revocation registry for the AnonCreds VDR mode.
///         Status is keyed by (credDefId, credIdHash). Org-gated: only members of the
///         credDef's issuing org may write.
/// @dev    UUPS upgradeable, ERC-7201 namespaced storage, Pausable, AccessControl.
contract AnonCredsStatusRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    IAnonCredsStatusRegistry
{
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");

    struct Entry {
        Status status;
        uint64 issuedAt;
        uint64 revokedAt;
    }

    /// @custom:storage-location erc7201:kanon.AnonCredsStatusRegistry
    struct AnonCredsStatusStorage {
        mapping(bytes32 => mapping(bytes32 => Entry)) entries;
        ICredentialDefinitionRegistry credDefRegistry;
        IOrganizationRegistry orgRegistry;
        uint256[47] __gap;
    }

    bytes32 private constant ANONCREDS_STATUS_STORAGE_SLOT =
        0x448a05a54dbcb23f4cb9da39443493f5ca3570879b1a0548a5fc5c78047d1e00;

    function _s() private pure returns (AnonCredsStatusStorage storage st) {
        bytes32 slot = ANONCREDS_STATUS_STORAGE_SLOT;
        assembly {
            st.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin, address credDefRegistry_, address orgRegistry_) external initializer {
        require(rootAdmin != address(0) && credDefRegistry_ != address(0) && orgRegistry_ != address(0), "ZeroAddr");
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
        _grantRole(CONFIG_ROLE, rootAdmin);
        AnonCredsStatusStorage storage st = _s();
        st.credDefRegistry = ICredentialDefinitionRegistry(credDefRegistry_);
        st.orgRegistry = IOrganizationRegistry(orgRegistry_);
    }

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IAnonCredsStatusRegistry
    function issueCredential(bytes32 credDefId, bytes32 credIdHash) external override whenNotPaused {
        _requireValid(credDefId, credIdHash);
        bytes32 orgId = _requireIssuerOrgMember(credDefId);

        AnonCredsStatusStorage storage st = _s();
        Entry storage e = st.entries[credDefId][credIdHash];
        if (e.status != Status.Unknown) revert AlreadyIssued(credDefId, credIdHash);

        uint64 nowTs = uint64(block.timestamp);
        e.status = Status.Issued;
        e.issuedAt = nowTs;
        emit CredentialIssued(credDefId, credIdHash, msg.sender, nowTs);
        // silence unused-var warning for orgId
        orgId;
    }

    /// @inheritdoc IAnonCredsStatusRegistry
    function revokeCredential(bytes32 credDefId, bytes32 credIdHash) external override whenNotPaused {
        _requireValid(credDefId, credIdHash);
        bytes32 orgId = _requireIssuerOrgMember(credDefId);

        AnonCredsStatusStorage storage st = _s();
        Entry storage e = st.entries[credDefId][credIdHash];
        if (e.status == Status.Unknown) revert NotIssued(credDefId, credIdHash);
        if (e.status == Status.Revoked) revert AlreadyRevoked(credDefId, credIdHash);

        uint64 nowTs = uint64(block.timestamp);
        e.status = Status.Revoked;
        e.revokedAt = nowTs;
        emit CredentialRevoked(credDefId, credIdHash, msg.sender, nowTs);
        orgId;
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IAnonCredsStatusRegistry
    function getStatus(bytes32 credDefId, bytes32 credIdHash) external view override returns (Status) {
        return _s().entries[credDefId][credIdHash].status;
    }

    /// @inheritdoc IAnonCredsStatusRegistry
    function isRevoked(bytes32 credDefId, bytes32 credIdHash) external view override returns (bool) {
        return _s().entries[credDefId][credIdHash].status == Status.Revoked;
    }

    /// @inheritdoc IAnonCredsStatusRegistry
    function isActive(bytes32 credDefId, bytes32 credIdHash) external view override returns (bool) {
        return _s().entries[credDefId][credIdHash].status == Status.Issued;
    }

    function getEntry(bytes32 credDefId, bytes32 credIdHash) external view returns (Entry memory) {
        return _s().entries[credDefId][credIdHash];
    }

    function credDefRegistry() external view returns (ICredentialDefinitionRegistry) {
        return _s().credDefRegistry;
    }

    function orgRegistry() external view returns (IOrganizationRegistry) {
        return _s().orgRegistry;
    }

    // ──────────────────────────────────────────────────────────────────
    // Config + pause + upgrade
    // ──────────────────────────────────────────────────────────────────

    function setCredDefRegistry(address newCredDefRegistry) external onlyRole(CONFIG_ROLE) {
        require(newCredDefRegistry != address(0), "ZeroAddr");
        _s().credDefRegistry = ICredentialDefinitionRegistry(newCredDefRegistry);
    }

    function setOrgRegistry(address newOrgRegistry) external onlyRole(CONFIG_ROLE) {
        require(newOrgRegistry != address(0), "ZeroAddr");
        _s().orgRegistry = IOrganizationRegistry(newOrgRegistry);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    // ──────────────────────────────────────────────────────────────────
    // Internal
    // ──────────────────────────────────────────────────────────────────

    function _requireValid(bytes32 credDefId, bytes32 credIdHash) private pure {
        if (credDefId == bytes32(0)) revert ZeroCredDefId();
        if (credIdHash == bytes32(0)) revert ZeroCredIdHash();
    }

    /// @dev    Reverts if credDef does not exist, is deprecated, the issuer org is not
    ///         approved+active, or the caller is not a member of the issuer org.
    function _requireIssuerOrgMember(bytes32 credDefId) private view returns (bytes32 orgId) {
        AnonCredsStatusStorage storage st = _s();
        if (!st.credDefRegistry.exists(credDefId)) revert CredDefNotFound(credDefId);
        if (!st.credDefRegistry.isActive(credDefId)) revert CredDefNotActive(credDefId);

        ICredentialDefinitionRegistry.CredentialDefinition memory cd =
            st.credDefRegistry.getCredentialDefinition(credDefId);
        orgId = cd.issuerOrg;
        if (!st.orgRegistry.isApprovedAndActive(orgId)) revert IssuerOrgNotApprovedOrActive(orgId);
        if (!st.orgRegistry.isMember(orgId, msg.sender)) revert NotIssuerOrgMember(orgId, msg.sender);
    }
}
