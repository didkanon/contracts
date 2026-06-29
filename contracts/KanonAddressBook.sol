// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import {IKanonAddressBook} from "./interfaces/IKanonAddressBook.sol";

/// @title KanonAddressBook
/// @notice A single directory contract holding the seven kanon registry proxy
///         addresses. Consumers (SDK, plugins, agents) configure only this
///         book's address and read the registries from it — one address to
///         wire instead of seven.
contract KanonAddressBook is Initializable, UUPSUpgradeable, AccessControlUpgradeable, IKanonAddressBook {
    bytes32 public constant CONFIG_ROLE = keccak256("kanon.CONFIG_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("kanon.UPGRADER_ROLE");

    /// @custom:storage-location erc7201:kanon.KanonAddressBook
    struct AddressBookStorage {
        Registries r;
        uint256[43] __gap;
    }

    bytes32 private constant STORAGE_SLOT =
        0x9e1e6eeb2f5a84ca590314c4adc34590194c835285d42d67c25f02f9d98e8000;

    function _s() private pure returns (AddressBookStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address rootAdmin) external initializer {
        require(rootAdmin != address(0), "ZeroAddr");
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, rootAdmin);
        _grantRole(CONFIG_ROLE, rootAdmin);
        _grantRole(UPGRADER_ROLE, rootAdmin);
    }

    /// @inheritdoc IKanonAddressBook
    function setRegistries(Registries calldata r) external override onlyRole(CONFIG_ROLE) {
        if (r.organizationRegistry == address(0)) revert ZeroRegistryAddress("organizationRegistry");
        if (r.didRegistry == address(0)) revert ZeroRegistryAddress("didRegistry");
        if (r.schemaRegistry == address(0)) revert ZeroRegistryAddress("schemaRegistry");
        if (r.credentialDefinitionRegistry == address(0)) {
            revert ZeroRegistryAddress("credentialDefinitionRegistry");
        }
        if (r.merkleStateRegistry == address(0)) revert ZeroRegistryAddress("merkleStateRegistry");
        if (r.anonCredsStatusRegistry == address(0)) revert ZeroRegistryAddress("anonCredsStatusRegistry");
        if (r.halo2VerifierRegistry == address(0)) revert ZeroRegistryAddress("halo2VerifierRegistry");
        _s().r = r;
        emit RegistriesUpdated(r);
    }

    /// @inheritdoc IKanonAddressBook
    function registries() external view override returns (Registries memory) {
        return _s().r;
    }

    function organizationRegistry() external view override returns (address) {
        return _s().r.organizationRegistry;
    }

    function didRegistry() external view override returns (address) {
        return _s().r.didRegistry;
    }

    function schemaRegistry() external view override returns (address) {
        return _s().r.schemaRegistry;
    }

    function credentialDefinitionRegistry() external view override returns (address) {
        return _s().r.credentialDefinitionRegistry;
    }

    function merkleStateRegistry() external view override returns (address) {
        return _s().r.merkleStateRegistry;
    }

    function anonCredsStatusRegistry() external view override returns (address) {
        return _s().r.anonCredsStatusRegistry;
    }

    function halo2VerifierRegistry() external view override returns (address) {
        return _s().r.halo2VerifierRegistry;
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
