// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IHalo2Verifier} from "../interfaces/IHalo2Verifier.sol";

/// @title Halo2VerifierRegistry
/// @notice Indexes deployed Halo2-KZG verifier contracts by circuit version.
///         `MerkleStateRegistry.setZkVerifier` accepts only addresses found here.
contract Halo2VerifierRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable
{
    bytes32 public constant CIRCUIT_REGISTRAR_ROLE = keccak256("kanon.CIRCUIT_REGISTRAR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("kanon.PAUSER_ROLE");

    /// @custom:storage-location erc7201:kanon.Halo2VerifierRegistry
    struct VerifierStorage {
        mapping(bytes32 => address) verifierByVersion;
        bytes32[] versions;
        uint256[48] __gap;
    }

    bytes32 private constant VERIFIER_STORAGE_SLOT =
        0xec6382bc2eb21c4b3f353f3d087f6c3cc56b3c7224433a0688a2897d64eb0700;

    function _verifierStorage() private pure returns (VerifierStorage storage s) {
        bytes32 slot = VERIFIER_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    error VerifierAlreadyRegistered(bytes32 circuitVersion);
    error ZeroVerifier();
    error UnknownCircuitVersion(bytes32 circuitVersion);

    event VerifierRegistered(bytes32 indexed circuitVersion, address indexed verifier);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin) external initializer {
        require(rootAdmin != address(0), "ZeroAdmin");
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(CIRCUIT_REGISTRAR_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
        _grantRole(PAUSER_ROLE, rootAdmin);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Register a ZK verifier under the circuit version it reports.
    function registerVerifier(address verifier) external onlyRole(CIRCUIT_REGISTRAR_ROLE) whenNotPaused {
        if (verifier == address(0)) revert ZeroVerifier();
        bytes32 version = IHalo2Verifier(verifier).circuitVersion();
        VerifierStorage storage s = _verifierStorage();
        if (s.verifierByVersion[version] != address(0)) revert VerifierAlreadyRegistered(version);
        s.verifierByVersion[version] = verifier;
        s.versions.push(version);
        emit VerifierRegistered(version, verifier);
    }

    function verifierFor(bytes32 circuitVersion) external view returns (address) {
        address v = _verifierStorage().verifierByVersion[circuitVersion];
        if (v == address(0)) revert UnknownCircuitVersion(circuitVersion);
        return v;
    }

    function knownVersions() external view returns (bytes32[] memory) {
        return _verifierStorage().versions;
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
