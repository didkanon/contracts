// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";


import {IDIDRegistry} from "../interfaces/IDIDRegistry.sol";
import {IOrganizationRegistry} from "../interfaces/IOrganizationRegistry.sol";

/// @title DIDRegistry
/// @notice W3C DID Core 1.0 compliant registry for the "did:kanon:" method.
/// @dev Handle binding rules (enforced at registration):
///       - User DIDs: keccak256(abi.encodePacked("did:kanon:user:", msg.sender, salt))
///         encoded as hex must match the handle portion of the DID.
///       - Org DIDs: the DID handle must equal "did:kanon:org:0x<64-hex>" — the lowercase
///         hex of the org's bytes32 ID, and msg.sender must be the org admin or a member.
contract DIDRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    IDIDRegistry
{
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");

    /// @notice Maximum number of verification methods per DID Document. Prevents griefing.
    uint256 public constant MAX_VERIFICATION_METHODS = 16;
    /// @notice Maximum number of service endpoints per DID Document.
    uint256 public constant MAX_SERVICES = 16;
    /// @notice Maximum number of references in any of the relationship arrays.
    uint256 public constant MAX_RELATIONSHIP_REFS = 16;

    /// @custom:storage-location erc7201:kanon.DIDRegistry
    struct DIDStorage {
        mapping(string => DIDDocument) docs;
        mapping(string => address) controllers; // hot-path
        mapping(string => bool) exists_;
        IOrganizationRegistry orgRegistry;
        uint256[46] __gap;
    }

    bytes32 private constant DID_STORAGE_SLOT =
        0x63eeb5a704e2e39d3f5db2198645669ddf6986a905b72d053476a1683c2c9600;

    function _didStorage() private pure returns (DIDStorage storage s) {
        bytes32 slot = DID_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin, address orgRegistry_) external initializer {
        if (rootAdmin == address(0)) revert InvalidController();
        if (orgRegistry_ == address(0)) revert InvalidController();
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
        _grantRole(CONFIG_ROLE, rootAdmin);
        _didStorage().orgRegistry = IOrganizationRegistry(orgRegistry_);
    }

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IDIDRegistry
    /// @param salt Sender-binding salt; required when scope == User. Ignored for org DIDs.
    function registerDID(string calldata did, bytes32 salt, DIDDocument calldata doc)
        external
        override
        whenNotPaused
    {
        if (bytes(did).length == 0) revert EmptyDid();
        DIDStorage storage s = _didStorage();
        if (s.exists_[did]) revert DIDAlreadyExists(did);

        _validateDocumentShape(doc);

        if (doc.scope == DIDScope.User) {
            // did = "did:kanon:user:0x<keccak(prefix||msg.sender||salt)>" — binds DID to caller.
            bytes32 expected = keccak256(abi.encodePacked("did:kanon:user:", msg.sender, salt));
            if (!_didMatchesUserBinding(did, expected)) revert HandleNotBoundToCaller();
        } else {
            bytes32 orgId = doc.orgId;
            if (!s.orgRegistry.isApprovedAndActive(orgId)) revert OrgNotApprovedOrActive(orgId);
            if (!s.orgRegistry.isMember(orgId, msg.sender)) revert OrgScopeRequiresOrgAdmin(orgId);
            string memory expected = string.concat("did:kanon:org:", _toHexString(orgId));
            if (keccak256(bytes(did)) != keccak256(bytes(expected))) {
                revert OrgDidFormatMismatch(expected, did);
            }
        }

        DIDDocument storage stored = s.docs[did];
        stored.controller = msg.sender;
        stored.orgId = doc.orgId;
        stored.scope = doc.scope;
        stored.docHash = doc.docHash;
        stored.createdAt = uint64(block.timestamp);
        stored.updatedAt = uint64(block.timestamp);
        stored.deactivated = false;
        _copyArrays(stored, doc);

        s.controllers[did] = msg.sender;
        s.exists_[did] = true;

        emit DIDRegistered(did, msg.sender, doc.orgId, doc.scope);
    }

    /// @inheritdoc IDIDRegistry
    function updateDID(string calldata did, DIDDocument calldata doc) external override whenNotPaused {
        DIDStorage storage s = _didStorage();
        if (!s.exists_[did]) revert DIDNotFound(did);
        if (s.docs[did].deactivated) revert DIDDeactivated_(did);
        if (s.controllers[did] != msg.sender) revert NotController(did, msg.sender);
        _validateDocumentShape(doc);

        DIDDocument storage stored = s.docs[did];
        // controller, orgId, scope, createdAt are immutable post-registration.
        stored.docHash = doc.docHash;
        stored.updatedAt = uint64(block.timestamp);
        _clearArrays(stored);
        _copyArrays(stored, doc);

        emit DIDUpdated(did, msg.sender, uint64(block.timestamp));
    }

    /// @inheritdoc IDIDRegistry
    function rotateController(string calldata did, address newController) external override whenNotPaused {
        if (newController == address(0)) revert InvalidController();
        DIDStorage storage s = _didStorage();
        if (!s.exists_[did]) revert DIDNotFound(did);
        if (s.docs[did].deactivated) revert DIDDeactivated_(did);
        address current = s.controllers[did];
        if (current != msg.sender) revert NotController(did, msg.sender);
        if (current == newController) revert SameController();
        s.controllers[did] = newController;
        s.docs[did].controller = newController;
        s.docs[did].updatedAt = uint64(block.timestamp);
        emit ControllerRotated(did, current, newController);
    }

    /// @inheritdoc IDIDRegistry
    function deactivateDID(string calldata did) external override whenNotPaused {
        DIDStorage storage s = _didStorage();
        if (!s.exists_[did]) revert DIDNotFound(did);
        if (s.docs[did].deactivated) revert DIDDeactivated_(did);
        if (s.controllers[did] != msg.sender) revert NotController(did, msg.sender);
        s.docs[did].deactivated = true;
        s.docs[did].updatedAt = uint64(block.timestamp);
        emit DIDDeactivated(did);
    }

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    /// @inheritdoc IDIDRegistry
    function resolveDID(string calldata did) external view override returns (DIDDocument memory) {
        DIDStorage storage s = _didStorage();
        if (!s.exists_[did]) revert DIDNotFound(did);
        return s.docs[did];
    }

    /// @inheritdoc IDIDRegistry
    function controllerOf(string calldata did) external view override returns (address) {
        return _didStorage().controllers[did];
    }

    /// @inheritdoc IDIDRegistry
    function exists(string calldata did) external view override returns (bool) {
        return _didStorage().exists_[did];
    }

    /// @inheritdoc IDIDRegistry
    function isDeactivated(string calldata did) external view override returns (bool) {
        DIDStorage storage s = _didStorage();
        if (!s.exists_[did]) return false;
        return s.docs[did].deactivated;
    }

    // ──────────────────────────────────────────────────────────────────
    // Configuration
    // ──────────────────────────────────────────────────────────────────

    function setOrgRegistry(address newOrgRegistry) external onlyRole(CONFIG_ROLE) {
        if (newOrgRegistry == address(0)) revert InvalidController();
        _didStorage().orgRegistry = IOrganizationRegistry(newOrgRegistry);
    }

    function orgRegistry() external view returns (IOrganizationRegistry) {
        return _didStorage().orgRegistry;
    }

    // ──────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────

    function _validateDocumentShape(DIDDocument calldata doc) internal pure {
        if (doc.verificationMethods.length > MAX_VERIFICATION_METHODS) {
            revert TooManyVerificationMethods(doc.verificationMethods.length, MAX_VERIFICATION_METHODS);
        }
        if (doc.services.length > MAX_SERVICES) {
            revert TooManyServices(doc.services.length, MAX_SERVICES);
        }
        if (doc.authentication.length > MAX_RELATIONSHIP_REFS) {
            revert TooManyVerificationMethods(doc.authentication.length, MAX_RELATIONSHIP_REFS);
        }
        if (doc.assertionMethod.length > MAX_RELATIONSHIP_REFS) {
            revert TooManyVerificationMethods(doc.assertionMethod.length, MAX_RELATIONSHIP_REFS);
        }
        if (doc.capabilityInvocation.length > MAX_RELATIONSHIP_REFS) {
            revert TooManyVerificationMethods(doc.capabilityInvocation.length, MAX_RELATIONSHIP_REFS);
        }
        if (doc.capabilityDelegation.length > MAX_RELATIONSHIP_REFS) {
            revert TooManyVerificationMethods(doc.capabilityDelegation.length, MAX_RELATIONSHIP_REFS);
        }
        if (doc.keyAgreement.length > MAX_RELATIONSHIP_REFS) {
            revert TooManyVerificationMethods(doc.keyAgreement.length, MAX_RELATIONSHIP_REFS);
        }

        for (uint256 i = 0; i < doc.authentication.length; ++i) {
            if (!_isVerificationMethodPresent(doc, doc.authentication[i])) {
                revert InvalidVerificationMethodReference(doc.authentication[i]);
            }
        }
        for (uint256 i = 0; i < doc.assertionMethod.length; ++i) {
            if (!_isVerificationMethodPresent(doc, doc.assertionMethod[i])) {
                revert InvalidVerificationMethodReference(doc.assertionMethod[i]);
            }
        }
        for (uint256 i = 0; i < doc.capabilityInvocation.length; ++i) {
            if (!_isVerificationMethodPresent(doc, doc.capabilityInvocation[i])) {
                revert InvalidVerificationMethodReference(doc.capabilityInvocation[i]);
            }
        }
        for (uint256 i = 0; i < doc.capabilityDelegation.length; ++i) {
            if (!_isVerificationMethodPresent(doc, doc.capabilityDelegation[i])) {
                revert InvalidVerificationMethodReference(doc.capabilityDelegation[i]);
            }
        }
        for (uint256 i = 0; i < doc.keyAgreement.length; ++i) {
            if (!_isVerificationMethodPresent(doc, doc.keyAgreement[i])) {
                revert InvalidVerificationMethodReference(doc.keyAgreement[i]);
            }
        }
    }

    function _isVerificationMethodPresent(DIDDocument calldata doc, bytes32 id) internal pure returns (bool) {
        for (uint256 i = 0; i < doc.verificationMethods.length; ++i) {
            if (doc.verificationMethods[i].id == id) return true;
        }
        return false;
    }

    function _copyArrays(DIDDocument storage stored, DIDDocument calldata doc) internal {
        for (uint256 i = 0; i < doc.verificationMethods.length; ++i) {
            stored.verificationMethods.push(doc.verificationMethods[i]);
        }
        for (uint256 i = 0; i < doc.authentication.length; ++i) {
            stored.authentication.push(doc.authentication[i]);
        }
        for (uint256 i = 0; i < doc.assertionMethod.length; ++i) {
            stored.assertionMethod.push(doc.assertionMethod[i]);
        }
        for (uint256 i = 0; i < doc.capabilityInvocation.length; ++i) {
            stored.capabilityInvocation.push(doc.capabilityInvocation[i]);
        }
        for (uint256 i = 0; i < doc.capabilityDelegation.length; ++i) {
            stored.capabilityDelegation.push(doc.capabilityDelegation[i]);
        }
        for (uint256 i = 0; i < doc.keyAgreement.length; ++i) {
            stored.keyAgreement.push(doc.keyAgreement[i]);
        }
        for (uint256 i = 0; i < doc.services.length; ++i) {
            stored.services.push(doc.services[i]);
        }
    }

    function _clearArrays(DIDDocument storage stored) internal {
        while (stored.verificationMethods.length > 0) stored.verificationMethods.pop();
        while (stored.authentication.length > 0) stored.authentication.pop();
        while (stored.assertionMethod.length > 0) stored.assertionMethod.pop();
        while (stored.capabilityInvocation.length > 0) stored.capabilityInvocation.pop();
        while (stored.capabilityDelegation.length > 0) stored.capabilityDelegation.pop();
        while (stored.keyAgreement.length > 0) stored.keyAgreement.pop();
        while (stored.services.length > 0) stored.services.pop();
    }

    /// @dev Expected DID format: "did:kanon:user:0x<64-hex-chars>" where the hex equals `expected`.
    function _didMatchesUserBinding(string calldata did, bytes32 expected) internal pure returns (bool) {
        bytes memory raw = bytes(did);
        bytes memory prefix = bytes("did:kanon:user:0x");
        if (raw.length != prefix.length + 64) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (raw[i] != prefix[i]) return false;
        }
        bytes32 parsed = 0;
        for (uint256 i = 0; i < 64; ++i) {
            uint8 c = uint8(raw[prefix.length + i]);
            uint8 nibble;
            if (c >= 0x30 && c <= 0x39) {
                nibble = c - 0x30;
            } else if (c >= 0x61 && c <= 0x66) {
                nibble = c - 0x61 + 10;
            } else if (c >= 0x41 && c <= 0x46) {
                nibble = c - 0x41 + 10;
            } else {
                return false;
            }
            parsed = bytes32(uint256(parsed) << 4 | uint256(nibble));
        }
        return parsed == expected;
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

    /// @dev "0x" + 64 lowercase hex chars for a bytes32 (replaces OZ Strings/Bytes, whose
    ///      implementation uses the Cancun-only MCOPY opcode unavailable on this London-fork chain).
    ///      Mirrors the user-DID hex form so org DIDs read "did:kanon:org:0x<64-hex>".
    function _toHexString(bytes32 value) private pure returns (string memory) {
        bytes memory HEX = "0123456789abcdef";
        bytes memory buffer = new bytes(66);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(value[i]);
            buffer[2 + i * 2] = HEX[b >> 4];
            buffer[3 + i * 2] = HEX[b & 0x0f];
        }
        return string(buffer);
    }
}
