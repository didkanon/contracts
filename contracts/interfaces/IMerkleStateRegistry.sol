// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title IMerkleStateRegistry
/// @notice Tracks the dual-Merkle-root state of every credential definition.
///         - rootKeccak supports Tier 1 (one-time-use credentials with cheap on-chain Merkle verify)
///         - rootPoseidon supports Tier 2 (Halo2-KZG SNARK presentations)
///         A sliding window of recent roots lets holders present against a slightly stale root
///         without needing perfectly-synced replicas.
interface IMerkleStateRegistry {
    struct MerkleState {
        bytes32 rootKeccak;
        bytes32 rootPoseidon;
        uint64 epoch;
        uint64 lastUpdated;
        uint256 issuedCount;
        uint256 revokedCount;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error CredDefNotActive(bytes32 credDefId);
    error IssuerOrgNotApprovedOrActive(bytes32 orgId);
    error NotIssuerOrgMember(bytes32 orgId, address caller);
    error NotInitialized(bytes32 credDefId);
    error AlreadyInitialized(bytes32 credDefId);
    error MembershipProofFailed();
    error NullifierAlreadyUsed(bytes32 credDefId, bytes32 credId);
    error TierNotSupported(bytes32 credDefId, uint8 tier);
    error InvalidVerifier();
    error VerifierNotAllowlisted(address verifier, bytes32 reportedVersion);
    error BatchSizeMismatch();
    error VerifierRegistryNotSet();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event MerkleStateInitialized(bytes32 indexed credDefId, bytes32 initialRootKeccak, bytes32 initialRootPoseidon);
    event RootsUpdated(
        bytes32 indexed credDefId,
        uint64 indexed epoch,
        bytes32 newRootKeccak,
        bytes32 newRootPoseidon,
        uint256 added,
        uint256 revoked
    );
    event CredentialAdded(bytes32 indexed credDefId, bytes32 leafKeccak, bytes32 leafPoseidon);
    event CredentialRevoked(bytes32 indexed credDefId, bytes32 leafKeccak, bytes32 leafPoseidon);
    event OneTimeConsumed(bytes32 indexed credDefId, bytes32 leaf);
    event ZkVerifierSet(bytes32 indexed credDefId, address indexed verifier);
    event VerifierRegistrySet(address indexed registry);

    // ──────────────────────────────────────────────────────────────────
    // Issuer-side writes
    // ──────────────────────────────────────────────────────────────────

    function initializeCredDefState(
        bytes32 credDefId,
        bytes32 initialRootKeccak,
        bytes32 initialRootPoseidon
    ) external;

    function batchUpdate(
        bytes32 credDefId,
        bytes32[] calldata addedLeavesKeccak,
        bytes32[] calldata addedLeavesPoseidon,
        bytes32[] calldata revokedLeavesKeccak,
        bytes32[] calldata revokedLeavesPoseidon,
        bytes32 newRootKeccak,
        bytes32 newRootPoseidon
    ) external;

    function setZkVerifier(bytes32 credDefId, address verifier) external;

    // ──────────────────────────────────────────────────────────────────
    // Tier 1 reads / consumption
    // ──────────────────────────────────────────────────────────────────

    /// @param credId The holder's SECRET credId. The leaf is derived on-chain via `deriveLeaf`.
    function verifyKeccakMembership(
        bytes32 credDefId,
        bytes32 credId,
        bytes32[] calldata proof
    ) external view returns (bool);

    /// @param credId The holder's SECRET credId (never published; only the derived leaf is).
    function consumeOneTime(
        bytes32 credDefId,
        bytes32 credId,
        bytes32[] calldata proof
    ) external;

    /// @notice Derive the public Merkle leaf from a secret credId (double-keccak).
    function deriveLeaf(bytes32 credId) external pure returns (bytes32);

    // ──────────────────────────────────────────────────────────────────
    // Tier 2 reads
    // ──────────────────────────────────────────────────────────────────

    function verifyZKMembership(
        bytes32 credDefId,
        bytes calldata proof,
        bytes32[] calldata publicSignals
    ) external view returns (bool);

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    function getState(bytes32 credDefId) external view returns (MerkleState memory);

    function isInitialized(bytes32 credDefId) external view returns (bool);

    function isCurrentKeccakRoot(bytes32 credDefId, bytes32 root) external view returns (bool);

    function isRecentKeccakRoot(bytes32 credDefId, bytes32 root) external view returns (bool);

    function isRecentPoseidonRoot(bytes32 credDefId, bytes32 root) external view returns (bool);

    function isNullifierUsed(bytes32 credDefId, bytes32 credId) external view returns (bool);

    function zkVerifierOf(bytes32 credDefId) external view returns (address);
}
