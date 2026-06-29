// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title ICredentialDefinitionRegistry
/// @notice Binds a schema to an issuer's signing key. Only members of the schema's
///         issuing organization may register a credential definition referencing that schema.
/// @dev Policy masks:
///         bit 0 (= 1): supports Tier 1 (one-time-use credentials, keccak Merkle proof on-chain)
///         bit 1 (= 2): supports Tier 2 (Groth16 SNARK, Poseidon Merkle proof)
///      A credDef may support either or both.
///
///      For Tier 2 credDefs the issuer additionally publishes a BabyJubjub
///      EdDSA public key (`(ax, ay)`) in the SAME `registerCredentialDefinition`
///      call. The verifier of a `non_revocation.circom` SNARK proof checks
///      that the public signals `(issuerAx, issuerAy)` it carries match the
///      registered values — this is how the on-chain root is bound to a
///      specific issuer identity. The key is immutable for the life of the
///      credDef, because rotating would silently invalidate every
///      previously-issued Tier 2 proof.
interface ICredentialDefinitionRegistry {
    struct CredentialDefinition {
        bytes32 schemaId;
        bytes32 issuerOrg;
        // AnonCreds CL signature public key (used by Tier 1 / standard AnonCreds
        // verification). Opaque bytes — the registry doesn't parse it. Tier 2
        // (Groth16) does NOT use this field; its BabyJubjub-EdDSA key lives in
        // `IssuerZkPubKey` and is set separately via `setIssuerZkPubKey`.
        bytes issuerPubKey;
        uint8 policyMask;     // Combination of TIER_* flags
        uint64 createdAt;
        bool deprecated;
        string uri;           // Cred-def body (e.g. inline data: URI) so holders can resolve it cross-agent.
    }

    /// @notice BabyJubjub-EdDSA public key the Tier 2 circuit verifies signatures
    ///         against. Coordinates are BN254 scalar-field elements; encoded as
    ///         uint256 so they round-trip into `publicSignals[3]/[4]` without
    ///         conversion. `set == false` means no Tier 2 key has been published
    ///         for this credDef and Mode B proofs MUST be rejected.
    struct IssuerZkPubKey {
        uint256 ax;
        uint256 ay;
        bool set;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error CredDefAlreadyExists(bytes32 credDefId);
    error CredDefNotFound(bytes32 credDefId);
    error CredDefDeprecated_(bytes32 credDefId);
    error SchemaNotActive(bytes32 schemaId);
    error IssuerOrgNotApprovedOrActive(bytes32 orgId);
    error NotIssuerOrgMember(bytes32 orgId, address caller);
    error EmptyIssuerPubKey();
    error InvalidPolicyMask(uint8 mask);
    error ZeroCredDefId();
    /// @dev Mode A credDef registered with a non-zero BabyJubjub key (would be
    ///      stored but never used — likely a misconfiguration the caller wants
    ///      to know about).
    error UnexpectedIssuerZkPubKey();
    /// @dev Mode B credDef registered with `(0, 0)` or other invalid key.
    error InvalidIssuerZkPubKey();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event CredentialDefinitionRegistered(
        bytes32 indexed credDefId,
        bytes32 indexed schemaId,
        bytes32 indexed issuerOrg,
        uint8 policyMask
    );
    event CredentialDefinitionDeprecated(bytes32 indexed credDefId);
    /// @notice Emitted alongside `CredentialDefinitionRegistered` whenever the
    ///         credDef opts into Tier 2 — lets indexers track the BabyJubjub
    ///         issuer key without re-decoding the parent event payload.
    event IssuerZkPubKeySet(bytes32 indexed credDefId, uint256 ax, uint256 ay);

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @notice Register a credential definition.
    /// @param credDefId         32-byte resource-id (keccak256 of the canonical DID path).
    /// @param schemaId          The schema this credDef binds to. MUST be active.
    /// @param issuerPubKey      AnonCreds CL signature key (Tier 1). Opaque bytes.
    /// @param policyMask        Bitmask of `TIER_*` flags. Must be non-zero and ≤ `TIER_ALL`.
    /// @param uri               Cred-def body URI (e.g. inline `data:` payload).
    /// @param issuerZkPubKeyAx  BabyJubjub Ax for the Tier 2 EdDSA key. MUST be
    ///                          non-zero (and != identity) when `policyMask & TIER_ZK_SNARK != 0`;
    ///                          MUST be `0` otherwise.
    /// @param issuerZkPubKeyAy  BabyJubjub Ay, same gating as Ax.
    function registerCredentialDefinition(
        bytes32 credDefId,
        bytes32 schemaId,
        bytes calldata issuerPubKey,
        uint8 policyMask,
        string calldata uri,
        uint256 issuerZkPubKeyAx,
        uint256 issuerZkPubKeyAy
    ) external;

    function deprecateCredentialDefinition(bytes32 credDefId) external;

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    function getCredentialDefinition(bytes32 credDefId) external view returns (CredentialDefinition memory);

    function exists(bytes32 credDefId) external view returns (bool);

    function isActive(bytes32 credDefId) external view returns (bool);

    function supportsTier(bytes32 credDefId, uint8 tier) external view returns (bool);

    /// @notice Returns the published BabyJubjub Tier 2 key (and whether one is
    ///         set). Verifiers MUST treat `set == false` as "Mode B not enabled".
    function getIssuerZkPubKey(bytes32 credDefId) external view returns (IssuerZkPubKey memory);
}
