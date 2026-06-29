// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title IDIDRegistry
/// @notice W3C DID Core 1.0 compliant registry for the "did:kanon:" method.
/// @dev User DIDs must commit to msg.sender at registration: the handle equals
///      keccak256("did:kanon:user:salt:" || msg.sender || salt). Org DIDs are
///      bound to the org admin via OrganizationRegistry lookup; the org handle is
///      "did:kanon:org:0x<64-hex>" — the lowercase hex of the bytes32 org id.
interface IDIDRegistry {
    enum VerificationMethodType {
        Ed25519VerificationKey2020,
        EcdsaSecp256k1VerificationKey2019,
        Bls12381G2Key2020,
        JsonWebKey2020
    }

    enum DIDScope {
        User,
        Org
    }

    struct VerificationMethod {
        bytes32 id;
        VerificationMethodType vmType;
        bytes publicKey;
    }

    struct Service {
        bytes32 id;
        string serviceType;
        string endpoint;
    }

    struct DIDDocument {
        address controller;
        bytes32 orgId;
        DIDScope scope;
        VerificationMethod[] verificationMethods;
        bytes32[] authentication;
        bytes32[] assertionMethod;
        bytes32[] capabilityInvocation;
        bytes32[] capabilityDelegation;
        bytes32[] keyAgreement;
        Service[] services;
        bytes32 docHash;
        uint64 createdAt;
        uint64 updatedAt;
        bool deactivated;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error DIDAlreadyExists(string did);
    error DIDNotFound(string did);
    error DIDDeactivated_(string did);
    error NotController(string did, address caller);
    error EmptyDid();
    error InvalidController();
    error HandleNotBoundToCaller();
    error OrgScopeRequiresOrgAdmin(bytes32 orgId);
    error OrgNotApprovedOrActive(bytes32 orgId);
    error OrgDidFormatMismatch(string expected, string got);
    error TooManyVerificationMethods(uint256 provided, uint256 max);
    error TooManyServices(uint256 provided, uint256 max);
    error InvalidVerificationMethodReference(bytes32 ref);
    error SameController();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event DIDRegistered(string did, address indexed controller, bytes32 indexed orgId, DIDScope scope);
    event DIDUpdated(string did, address indexed controller, uint64 updatedAt);
    event ControllerRotated(string did, address indexed oldController, address indexed newController);
    event DIDDeactivated(string did);

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    function registerDID(string calldata did, bytes32 salt, DIDDocument calldata doc) external;

    function updateDID(string calldata did, DIDDocument calldata doc) external;

    function rotateController(string calldata did, address newController) external;

    function deactivateDID(string calldata did) external;

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    function resolveDID(string calldata did) external view returns (DIDDocument memory);

    function controllerOf(string calldata did) external view returns (address);

    function exists(string calldata did) external view returns (bool);

    function isDeactivated(string calldata did) external view returns (bool);
}
