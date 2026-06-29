// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title IOrganizationRegistry
/// @notice Public interface for the organization lifecycle and membership registry.
/// @dev Org IDs are random bytes32 values assigned at registration. The canonical DID for an org is
///      "did:kanon:org:0x<64-hex>" (the lowercase hex encoding of the bytes32 id).
interface IOrganizationRegistry {
    struct Organization {
        string did;
        address admin;
        bool approved;
        bool suspended;
        uint64 createdAt;
        uint64 approvedAt;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error OrgNotFound(bytes32 orgId);
    error OrgAlreadyApproved(bytes32 orgId);
    error OrgNotApproved(bytes32 orgId);
    error OrgSuspended(bytes32 orgId);
    error NotOrgAdmin(bytes32 orgId, address caller);
    error ZeroAdmin();
    error EmptyDid();
    error MemberAlreadyAdded(bytes32 orgId, address member);
    error MemberNotFound(bytes32 orgId, address member);
    error SameAdmin();
    error OrgIdCollision();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event OrgRegistered(bytes32 indexed orgId, string did, address indexed admin);
    event OrgApproved(bytes32 indexed orgId);
    event OrgSuspended_(bytes32 indexed orgId);
    event OrgReactivated(bytes32 indexed orgId);
    event OrgAdminTransferred(bytes32 indexed orgId, address indexed oldAdmin, address indexed newAdmin);
    event MemberAdded(bytes32 indexed orgId, address indexed member);
    event MemberRemoved(bytes32 indexed orgId, address indexed member);

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    function registerOrg(string calldata did, address admin) external returns (bytes32 orgId);

    function approveOrg(bytes32 orgId) external;

    function suspendOrg(bytes32 orgId) external;

    function reactivateOrg(bytes32 orgId) external;

    function transferOrgAdmin(bytes32 orgId, address newAdmin) external;

    function addMember(bytes32 orgId, address member) external;

    function removeMember(bytes32 orgId, address member) external;

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    function getOrg(bytes32 orgId) external view returns (Organization memory);

    function isApprovedAndActive(bytes32 orgId) external view returns (bool);

    function isMember(bytes32 orgId, address who) external view returns (bool);

    function isAdmin(bytes32 orgId, address who) external view returns (bool);
}
