// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title IAnonCredsStatusRegistry
/// @notice Per-credential AnonCreds-VDR-style status registry. The chain tracks issuance
///         and revocation events keyed by (credDefId, credIdHash). Privacy mode: verifier
///         reads `credId` from a disclosed AnonCreds attribute and looks the status up
///         directly. No SNARK is required in the wallet to verifier flow.
/// @dev    Designed to slot into the Credo AnonCredsRegistry interface so plugins can
///         use kanonv2 as a drop-in VDR without modifying Credo's anoncreds package.
interface IAnonCredsStatusRegistry {
    enum Status {
        Unknown,
        Issued,
        Revoked
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error CredDefNotFound(bytes32 credDefId);
    error CredDefNotActive(bytes32 credDefId);
    error IssuerOrgNotApprovedOrActive(bytes32 orgId);
    error NotIssuerOrgMember(bytes32 orgId, address caller);
    error AlreadyIssued(bytes32 credDefId, bytes32 credIdHash);
    error NotIssued(bytes32 credDefId, bytes32 credIdHash);
    error AlreadyRevoked(bytes32 credDefId, bytes32 credIdHash);
    error ZeroCredDefId();
    error ZeroCredIdHash();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event CredentialIssued(
        bytes32 indexed credDefId,
        bytes32 indexed credIdHash,
        address indexed issuer,
        uint64 issuedAt
    );

    event CredentialRevoked(
        bytes32 indexed credDefId,
        bytes32 indexed credIdHash,
        address indexed issuer,
        uint64 revokedAt
    );

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @notice Marks a credential as issued under `credDefId`. Caller must be a member of the
    ///         credDef's issuer organization, and the org must be approved + active.
    /// @param  credDefId   Credential definition the credential belongs to.
    /// @param  credIdHash  keccak256(utf8(credId)) — stable hash of the AnonCreds credential id.
    function issueCredential(bytes32 credDefId, bytes32 credIdHash) external;

    /// @notice Revokes a previously-issued credential. Caller must be a member of the credDef's
    ///         issuer organization.
    function revokeCredential(bytes32 credDefId, bytes32 credIdHash) external;

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @notice Returns the current status of (credDefId, credIdHash).
    function getStatus(bytes32 credDefId, bytes32 credIdHash) external view returns (Status);

    /// @notice True iff the credential has been revoked. Returns false for never-issued and
    ///         active credentials. Verifiers can use this as a post-`verifyProof` check.
    function isRevoked(bytes32 credDefId, bytes32 credIdHash) external view returns (bool);

    /// @notice True iff the credential has been issued and not revoked.
    function isActive(bytes32 credDefId, bytes32 credIdHash) external view returns (bool);
}
