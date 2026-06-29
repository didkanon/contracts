// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";

/// @title OrganizationRegistry
/// @notice Approved organizations may issue schemas and credential definitions. Org admins manage membership.
/// @dev Storage uses ERC-7201 namespaced slots to keep upgrade-safe layout.
contract OrganizationRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    IOrganizationRegistry
{
    bytes32 public constant GOVERNANCE_ROLE = keccak256("kanon.GOVERNANCE_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");

    /// @custom:storage-location erc7201:kanon.OrganizationRegistry
    struct OrgStorage {
        mapping(bytes32 => Organization) orgs;
        mapping(bytes32 => mapping(address => bool)) members;
        uint256 nonce;
        uint256[47] __gap;
    }

    // keccak256(abi.encode(uint256(keccak256("kanon.OrganizationRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ORG_STORAGE_SLOT =
        0x0732cfed656a6c1f22e70d2a49bf011df01e84847616023018a7d31e15631f00;

    function _orgStorage() private pure returns (OrgStorage storage s) {
        bytes32 slot = ORG_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin) external initializer {
        if (rootAdmin == address(0)) revert ZeroAdmin();
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(GOVERNANCE_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
    }

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IOrganizationRegistry
    function registerOrg(string calldata did, address admin)
        external
        override
        whenNotPaused
        returns (bytes32 orgId)
    {
        if (bytes(did).length == 0) revert EmptyDid();
        if (admin == address(0)) revert ZeroAdmin();
        OrgStorage storage s = _orgStorage();

        // Assign a random, collision-free, non-zero id. A handful of re-hashes is
        // astronomically sufficient given keccak's range; revert if the (impossible)
        // happens repeatedly so an id is never silently reused.
        uint256 nonce = s.nonce;
        for (uint256 i = 0; i < 8; ++i) {
            orgId = keccak256(
                abi.encodePacked(msg.sender, did, block.timestamp, block.prevrandao, nonce)
            );
            unchecked {
                ++nonce;
            }
            if (orgId != bytes32(0) && s.orgs[orgId].createdAt == 0) {
                s.nonce = nonce;
                break;
            }
            orgId = bytes32(0);
        }
        if (orgId == bytes32(0)) revert OrgIdCollision();

        s.orgs[orgId] = Organization({
            did: did,
            admin: admin,
            approved: false,
            suspended: false,
            createdAt: uint64(block.timestamp),
            approvedAt: 0
        });
        emit OrgRegistered(orgId, did, admin);
    }

    /// @inheritdoc IOrganizationRegistry
    function approveOrg(bytes32 orgId) external override onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (o.approved && !o.suspended) revert OrgAlreadyApproved(orgId);
        o.approved = true;
        o.suspended = false;
        if (o.approvedAt == 0) {
            o.approvedAt = uint64(block.timestamp);
            emit OrgApproved(orgId);
        } else {
            emit OrgReactivated(orgId);
        }
    }

    /// @inheritdoc IOrganizationRegistry
    function suspendOrg(bytes32 orgId) external override onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (!o.approved) revert OrgNotApproved(orgId);
        if (o.suspended) revert OrgSuspended(orgId);
        o.suspended = true;
        emit OrgSuspended_(orgId);
    }

    /// @inheritdoc IOrganizationRegistry
    function reactivateOrg(bytes32 orgId) external override onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (!o.suspended) revert OrgAlreadyApproved(orgId);
        o.suspended = false;
        emit OrgReactivated(orgId);
    }

    /// @inheritdoc IOrganizationRegistry
    function transferOrgAdmin(bytes32 orgId, address newAdmin) external override whenNotPaused {
        if (newAdmin == address(0)) revert ZeroAdmin();
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (o.admin != msg.sender) revert NotOrgAdmin(orgId, msg.sender);
        if (o.admin == newAdmin) revert SameAdmin();
        address old = o.admin;
        o.admin = newAdmin;
        emit OrgAdminTransferred(orgId, old, newAdmin);
    }

    /// @inheritdoc IOrganizationRegistry
    function addMember(bytes32 orgId, address member) external override whenNotPaused {
        if (member == address(0)) revert ZeroAdmin();
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (o.admin != msg.sender) revert NotOrgAdmin(orgId, msg.sender);
        if (s.members[orgId][member]) revert MemberAlreadyAdded(orgId, member);
        s.members[orgId][member] = true;
        emit MemberAdded(orgId, member);
    }

    /// @inheritdoc IOrganizationRegistry
    function removeMember(bytes32 orgId, address member) external override whenNotPaused {
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        if (o.admin != msg.sender) revert NotOrgAdmin(orgId, msg.sender);
        if (!s.members[orgId][member]) revert MemberNotFound(orgId, member);
        s.members[orgId][member] = false;
        emit MemberRemoved(orgId, member);
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IOrganizationRegistry
    function getOrg(bytes32 orgId) external view override returns (Organization memory) {
        OrgStorage storage s = _orgStorage();
        Organization memory o = s.orgs[orgId];
        if (o.createdAt == 0) revert OrgNotFound(orgId);
        return o;
    }

    /// @inheritdoc IOrganizationRegistry
    function isApprovedAndActive(bytes32 orgId) external view override returns (bool) {
        OrgStorage storage s = _orgStorage();
        Organization storage o = s.orgs[orgId];
        return o.createdAt != 0 && o.approved && !o.suspended;
    }

    /// @inheritdoc IOrganizationRegistry
    function isMember(bytes32 orgId, address who) external view override returns (bool) {
        OrgStorage storage s = _orgStorage();
        // Org admin is implicitly a member (can act on behalf of the org)
        if (s.orgs[orgId].admin == who && who != address(0)) return true;
        return s.members[orgId][who];
    }

    /// @inheritdoc IOrganizationRegistry
    function isAdmin(bytes32 orgId, address who) external view override returns (bool) {
        OrgStorage storage s = _orgStorage();
        return s.orgs[orgId].admin == who && who != address(0);
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
