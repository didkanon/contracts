// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title IKanonAddressBook
/// @notice Single on-chain directory of the kanon registry proxies. Consumers
///         configure ONE address (this book) and resolve the rest from it —
///         restoring v1's single-address ergonomics over the modular registries.
interface IKanonAddressBook {
    struct Registries {
        address organizationRegistry;
        address didRegistry;
        address schemaRegistry;
        address credentialDefinitionRegistry;
        address merkleStateRegistry;
        address anonCredsStatusRegistry;
        address halo2VerifierRegistry;
    }

    event RegistriesUpdated(Registries registries);

    error ZeroRegistryAddress(string name);

    /// @notice Governance: set/replace the full registry set.
    function setRegistries(Registries calldata r) external;

    /// @notice The full registry set in one call.
    function registries() external view returns (Registries memory);

    function organizationRegistry() external view returns (address);
    function didRegistry() external view returns (address);
    function schemaRegistry() external view returns (address);
    function credentialDefinitionRegistry() external view returns (address);
    function merkleStateRegistry() external view returns (address);
    function anonCredsStatusRegistry() external view returns (address);
    function halo2VerifierRegistry() external view returns (address);
}
