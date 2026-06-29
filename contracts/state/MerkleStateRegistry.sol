// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IMerkleStateRegistry} from "../interfaces/IMerkleStateRegistry.sol";
import {ICredentialDefinitionRegistry} from "../interfaces/ICredentialDefinitionRegistry.sol";
import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";
import {IHalo2Verifier} from "../interfaces/IHalo2Verifier.sol";
import {Halo2VerifierRegistry} from "../verifiers/Halo2VerifierRegistry.sol";
import {MerkleProofLib} from "./lib/MerkleProofLib.sol";

/// @title MerkleStateRegistry
/// @notice The canonical on-chain state for credential validity across both tiers:
///         - Tier 1 uses the keccak Merkle root + a one-time-use nullifier mapping
///         - Tier 2 uses the Poseidon Merkle root + an injected Halo2 verifier
///         A sliding window of recent roots (RECENT_ROOTS_WINDOW) lets holders present
///         against a slightly stale root, balancing replication latency vs. revocation immediacy.
contract MerkleStateRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    IMerkleStateRegistry
{
    using MerkleProofLib for bytes32[];

    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");

    /// @notice Size of the sliding window of recent Keccak/Poseidon roots considered valid.
    uint8 public constant RECENT_ROOTS_WINDOW = 16;

    /// @notice BN254 scalar-field prime. Tier 2 `publicSignals[1]` (credDefId in
    ///         the circuit) is the on-chain credDefId reduced mod this prime —
    ///         the registry mirrors that reduction when binding.
    uint256 private constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Maximum size of one batchUpdate's added/revoked arrays. Prevents OOG on a single tx.
    uint256 public constant MAX_BATCH_SIZE = 256;

    /// @custom:storage-location erc7201:kanon.MerkleStateRegistry
    struct MsrStorage {
        mapping(bytes32 => MerkleState) state;
        mapping(bytes32 => bytes32[RECENT_ROOTS_WINDOW]) recentKeccakRoots;
        mapping(bytes32 => bytes32[RECENT_ROOTS_WINDOW]) recentPoseidonRoots;
        mapping(bytes32 => mapping(bytes32 => bool)) nullifierUsed;
        mapping(bytes32 => address) zkVerifiers;
        mapping(bytes32 => bool) initialized;
        ICredentialDefinitionRegistry credDefRegistry;
        IOrganizationRegistry orgRegistry;
        Halo2VerifierRegistry verifierRegistry;
        uint256 reentrancyStatus;
        uint256[41] __gap;
    }

    // Storage-based reentrancy guard (this chain's London fork lacks transient storage).
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    error ReentrantCall();

    modifier nonReentrant() {
        MsrStorage storage s = _msrStorage();
        if (s.reentrancyStatus == _ENTERED) revert ReentrantCall();
        s.reentrancyStatus = _ENTERED;
        _;
        s.reentrancyStatus = _NOT_ENTERED;
    }

    bytes32 private constant MSR_STORAGE_SLOT =
        0xf2f2890e09dd41b8c69b9ac809b30ff98d35eb5a8298f8bfb94949ec7f9c8c00;

    function _msrStorage() private pure returns (MsrStorage storage s) {
        bytes32 slot = MSR_STORAGE_SLOT;
        assembly {
            s.slot := slot
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
        MsrStorage storage s = _msrStorage();
        s.credDefRegistry = ICredentialDefinitionRegistry(credDefRegistry_);
        s.orgRegistry = IOrganizationRegistry(orgRegistry_);
        s.reentrancyStatus = _NOT_ENTERED;
    }

    /// @notice Wire the Halo2 verifier allowlist registry. Must run once before any
    ///         Tier-2 `setZkVerifier` call succeeds.
    function initializeV2(address verifierRegistry_) external reinitializer(2) onlyRole(CONFIG_ROLE) {
        require(verifierRegistry_ != address(0), "ZeroAddr");
        _msrStorage().verifierRegistry = Halo2VerifierRegistry(verifierRegistry_);
        emit VerifierRegistrySet(verifierRegistry_);
    }

    // ──────────────────────────────────────────────────────────────────
    // Issuer-side writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IMerkleStateRegistry
    function initializeCredDefState(bytes32 credDefId, bytes32 initialRootKeccak, bytes32 initialRootPoseidon)
        external
        override
        whenNotPaused
    {
        MsrStorage storage s = _msrStorage();
        if (s.initialized[credDefId]) revert AlreadyInitialized(credDefId);
        _requireIssuerOrgMember(s, credDefId);

        s.initialized[credDefId] = true;
        MerkleState storage st = s.state[credDefId];
        st.rootKeccak = initialRootKeccak;
        st.rootPoseidon = initialRootPoseidon;
        st.epoch = 0;
        st.lastUpdated = uint64(block.timestamp);

        // Seed the recent-roots windows so isRecent*() works immediately.
        s.recentKeccakRoots[credDefId][0] = initialRootKeccak;
        s.recentPoseidonRoots[credDefId][0] = initialRootPoseidon;

        emit MerkleStateInitialized(credDefId, initialRootKeccak, initialRootPoseidon);
    }

    /// @inheritdoc IMerkleStateRegistry
    function batchUpdate(
        bytes32 credDefId,
        bytes32[] calldata addedLeavesKeccak,
        bytes32[] calldata addedLeavesPoseidon,
        bytes32[] calldata revokedLeavesKeccak,
        bytes32[] calldata revokedLeavesPoseidon,
        bytes32 newRootKeccak,
        bytes32 newRootPoseidon
    ) external override whenNotPaused {
        MsrStorage storage s = _msrStorage();
        if (!s.initialized[credDefId]) revert NotInitialized(credDefId);
        _requireIssuerOrgMember(s, credDefId);

        if (addedLeavesKeccak.length != addedLeavesPoseidon.length) revert BatchSizeMismatch();
        if (revokedLeavesKeccak.length != revokedLeavesPoseidon.length) revert BatchSizeMismatch();
        if (addedLeavesKeccak.length > MAX_BATCH_SIZE || revokedLeavesKeccak.length > MAX_BATCH_SIZE) {
            revert BatchSizeMismatch();
        }

        MerkleState storage st = s.state[credDefId];
        st.rootKeccak = newRootKeccak;
        st.rootPoseidon = newRootPoseidon;
        unchecked {
            st.epoch += 1;
        }
        st.lastUpdated = uint64(block.timestamp);
        st.issuedCount += addedLeavesKeccak.length;
        st.revokedCount += revokedLeavesKeccak.length;

        uint256 slot = st.epoch % RECENT_ROOTS_WINDOW;
        s.recentKeccakRoots[credDefId][slot] = newRootKeccak;
        s.recentPoseidonRoots[credDefId][slot] = newRootPoseidon;

        uint256 nAdded = addedLeavesKeccak.length;
        for (uint256 i = 0; i < nAdded; ++i) {
            emit CredentialAdded(credDefId, addedLeavesKeccak[i], addedLeavesPoseidon[i]);
        }
        uint256 nRevoked = revokedLeavesKeccak.length;
        for (uint256 i = 0; i < nRevoked; ++i) {
            emit CredentialRevoked(credDefId, revokedLeavesKeccak[i], revokedLeavesPoseidon[i]);
        }

        emit RootsUpdated(credDefId, st.epoch, newRootKeccak, newRootPoseidon, nAdded, nRevoked);
    }

    /// @inheritdoc IMerkleStateRegistry
    /// @dev A non-zero verifier must already be registered in `Halo2VerifierRegistry`
    ///      under the version it reports. Setting to address(0) clears the slot.
    function setZkVerifier(bytes32 credDefId, address verifier) external override whenNotPaused {
        MsrStorage storage s = _msrStorage();
        if (!s.initialized[credDefId]) revert NotInitialized(credDefId);
        _requireIssuerOrgMember(s, credDefId);
        if (verifier != address(0)) {
            if (address(s.verifierRegistry) == address(0)) revert VerifierRegistryNotSet();
            bytes32 reportedVersion;
            try IHalo2Verifier(verifier).circuitVersion() returns (bytes32 v) {
                reportedVersion = v;
            } catch {
                revert InvalidVerifier();
            }
            address registered;
            try s.verifierRegistry.verifierFor(reportedVersion) returns (address r) {
                registered = r;
            } catch {
                revert VerifierNotAllowlisted(verifier, reportedVersion);
            }
            if (registered != verifier) revert VerifierNotAllowlisted(verifier, reportedVersion);
        }
        s.zkVerifiers[credDefId] = verifier;
        emit ZkVerifierSet(credDefId, verifier);
    }

    /// @notice Set or rotate the Halo2 verifier registry pointer.
    /// @dev Available to CONFIG_ROLE for emergencies (e.g., the original registry is replaced).
    ///      V-05 fix: smoke-call `knownVersions()` on the candidate to confirm it implements
    ///      the Halo2VerifierRegistry surface before persisting the pointer. This prevents a
    ///      misconfiguration from bricking Tier-2 `setZkVerifier` for every credDef.
    function setVerifierRegistry(address newRegistry) external onlyRole(CONFIG_ROLE) {
        require(newRegistry != address(0), "ZeroAddr");
        try Halo2VerifierRegistry(newRegistry).knownVersions() returns (bytes32[] memory) {
            // conforms
        } catch {
            revert InvalidVerifier();
        }
        _msrStorage().verifierRegistry = Halo2VerifierRegistry(newRegistry);
        emit VerifierRegistrySet(newRegistry);
    }

    /// @notice Read the current Halo2 verifier registry address.
    function verifierRegistry() external view returns (address) {
        return address(_msrStorage().verifierRegistry);
    }

    // ──────────────────────────────────────────────────────────────────
    // Tier 1: cheap on-chain verification
    // ──────────────────────────────────────────────────────────────────

    /// @notice Derive the Merkle leaf from a holder's secret credId.
    /// @dev Double-hash per the OpenZeppelin StandardMerkleTree convention. This domain-separates
    ///      leaves from internal nodes (which are single keccak of a 64-byte pair), so a truncated
    ///      proof presenting an internal node or the root cannot validate as a leaf. The off-chain
    ///      issuer/SDK builds the tree from these same derived leaves; the secret credId is never
    ///      published — only the derived leaf appears in events.
    function deriveLeaf(bytes32 credId) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(credId))));
    }

    /// @inheritdoc IMerkleStateRegistry
    function verifyKeccakMembership(bytes32 credDefId, bytes32 credId, bytes32[] calldata proof)
        external
        view
        override
        returns (bool)
    {
        MsrStorage storage s = _msrStorage();
        if (!s.initialized[credDefId]) return false;
        bytes32 recovered = MerkleProofLib.processProof(proof, deriveLeaf(credId));
        return _isRecentKeccak(s, credDefId, recovered);
    }

    /// @inheritdoc IMerkleStateRegistry
    /// @dev Reverts on any failure; suitable for use as a modifier inside gated contracts.
    ///      The caller presents the SECRET credId; the contract derives the public leaf.
    function consumeOneTime(bytes32 credDefId, bytes32 credId, bytes32[] calldata proof)
        external
        override
        whenNotPaused
        nonReentrant
    {
        MsrStorage storage s = _msrStorage();
        if (!s.initialized[credDefId]) revert NotInitialized(credDefId);
        if (!_credDefSupports(s, credDefId, 1)) revert TierNotSupported(credDefId, 1);

        bytes32 leaf = deriveLeaf(credId);
        if (s.nullifierUsed[credDefId][leaf]) revert NullifierAlreadyUsed(credDefId, leaf);

        bytes32 recovered = MerkleProofLib.processProof(proof, leaf);
        if (!_isRecentKeccak(s, credDefId, recovered)) revert MembershipProofFailed();

        s.nullifierUsed[credDefId][leaf] = true;
        emit OneTimeConsumed(credDefId, leaf);
    }

    // ──────────────────────────────────────────────────────────────────
    // Tier 2: SNARK verification (delegates to injected verifier)
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IMerkleStateRegistry
    function verifyZKMembership(bytes32 credDefId, bytes calldata proof, bytes32[] calldata publicSignals)
        external
        view
        override
        returns (bool)
    {
        MsrStorage storage s = _msrStorage();
        if (!s.initialized[credDefId]) return false;
        if (!_credDefSupports(s, credDefId, 2)) return false;
        address verifier = s.zkVerifiers[credDefId];
        if (verifier == address(0)) return false;

        // Public-signal layout: [root, credDefId, challenge, issuerAx, issuerAy, idx, val].
        // Need root + credDefId + the two issuer-key signals.
        if (publicSignals.length < 5) return false;

        // publicSignals[0] must be a recent Poseidon root.
        if (!_isRecentPoseidon(s, credDefId, publicSignals[0])) return false;

        // Bind publicSignals[1] to the function parameter. The circuit treats
        // credDefId as a BN254 felt, so the holder supplied `uint256(credDefId) %
        // BN254_SCALAR_FIELD`; the registry mirrors that reduction. Without this
        // check, a holder of a valid credential under credDefA could replay it as
        // a credDefB proof if A and B ever shared both a recent root AND the same
        // issuer ZK key — defense-in-depth, neither condition is plausible alone.
        if (uint256(publicSignals[1]) != uint256(credDefId) % BN254_SCALAR_FIELD) return false;

        // Bind the proof to the credDef's registered Tier 2 issuer key: the
        // BabyJubjub (Ax, Ay) the circuit verified the EdDSA-Poseidon signature
        // against must be the one published via `setIssuerZkPubKey`. Reject if
        // no Tier 2 key has been published (`set == false`) — it means the
        // issuer hasn't opted the credDef into Mode B yet.
        ICredentialDefinitionRegistry.IssuerZkPubKey memory zkKey =
            s.credDefRegistry.getIssuerZkPubKey(credDefId);
        if (!zkKey.set) return false;
        if (uint256(publicSignals[3]) != zkKey.ax || uint256(publicSignals[4]) != zkKey.ay) return false;

        return IHalo2Verifier(verifier).verify(proof, publicSignals);
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IMerkleStateRegistry
    function getState(bytes32 credDefId) external view override returns (MerkleState memory) {
        return _msrStorage().state[credDefId];
    }

    /// @inheritdoc IMerkleStateRegistry
    function isInitialized(bytes32 credDefId) external view override returns (bool) {
        return _msrStorage().initialized[credDefId];
    }

    /// @inheritdoc IMerkleStateRegistry
    function isCurrentKeccakRoot(bytes32 credDefId, bytes32 root) external view override returns (bool) {
        return _msrStorage().state[credDefId].rootKeccak == root;
    }

    /// @inheritdoc IMerkleStateRegistry
    function isRecentKeccakRoot(bytes32 credDefId, bytes32 root) external view override returns (bool) {
        return _isRecentKeccak(_msrStorage(), credDefId, root);
    }

    /// @inheritdoc IMerkleStateRegistry
    function isRecentPoseidonRoot(bytes32 credDefId, bytes32 root) external view override returns (bool) {
        return _isRecentPoseidon(_msrStorage(), credDefId, root);
    }

    /// @inheritdoc IMerkleStateRegistry
    /// @dev Accepts the secret credId and derives the leaf the nullifier is keyed by.
    function isNullifierUsed(bytes32 credDefId, bytes32 credId) external view override returns (bool) {
        return _msrStorage().nullifierUsed[credDefId][deriveLeaf(credId)];
    }

    /// @inheritdoc IMerkleStateRegistry
    function zkVerifierOf(bytes32 credDefId) external view override returns (address) {
        return _msrStorage().zkVerifiers[credDefId];
    }

    function credDefRegistry() external view returns (ICredentialDefinitionRegistry) {
        return _msrStorage().credDefRegistry;
    }

    function orgRegistry() external view returns (IOrganizationRegistry) {
        return _msrStorage().orgRegistry;
    }

    function setCredDefRegistry(address newCredDefRegistry) external onlyRole(CONFIG_ROLE) {
        require(newCredDefRegistry != address(0), "ZeroAddr");
        _msrStorage().credDefRegistry = ICredentialDefinitionRegistry(newCredDefRegistry);
    }

    function setOrgRegistry(address newOrgRegistry) external onlyRole(CONFIG_ROLE) {
        require(newOrgRegistry != address(0), "ZeroAddr");
        _msrStorage().orgRegistry = IOrganizationRegistry(newOrgRegistry);
    }

    // ──────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────

    function _requireIssuerOrgMember(MsrStorage storage s, bytes32 credDefId) internal view {
        if (!s.credDefRegistry.isActive(credDefId)) revert CredDefNotActive(credDefId);
        ICredentialDefinitionRegistry.CredentialDefinition memory cd =
            s.credDefRegistry.getCredentialDefinition(credDefId);
        if (!s.orgRegistry.isApprovedAndActive(cd.issuerOrg)) {
            revert IssuerOrgNotApprovedOrActive(cd.issuerOrg);
        }
        if (!s.orgRegistry.isMember(cd.issuerOrg, msg.sender)) {
            revert NotIssuerOrgMember(cd.issuerOrg, msg.sender);
        }
    }

    function _credDefSupports(MsrStorage storage s, bytes32 credDefId, uint8 tier) internal view returns (bool) {
        return s.credDefRegistry.supportsTier(credDefId, tier);
    }

    function _isRecentKeccak(MsrStorage storage s, bytes32 credDefId, bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        bytes32[RECENT_ROOTS_WINDOW] storage window = s.recentKeccakRoots[credDefId];
        for (uint256 i = 0; i < RECENT_ROOTS_WINDOW; ++i) {
            if (window[i] == root) return true;
        }
        return false;
    }

    function _isRecentPoseidon(MsrStorage storage s, bytes32 credDefId, bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        bytes32[RECENT_ROOTS_WINDOW] storage window = s.recentPoseidonRoots[credDefId];
        for (uint256 i = 0; i < RECENT_ROOTS_WINDOW; ++i) {
            if (window[i] == root) return true;
        }
        return false;
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
