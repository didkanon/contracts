// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title ISchemaRegistry
/// @notice Schemas are owned by an organization. Only approved-and-active org members can register.
interface ISchemaRegistry {
    struct Schema {
        bytes32 issuerOrg;
        bytes32 schemaHash; // keccak256 of canonical off-chain JSON Schema
        string uri;          // IPFS CID or HTTPS URL
        uint64 createdAt;
        bool deprecated;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error SchemaAlreadyExists(bytes32 schemaId);
    error SchemaNotFound(bytes32 schemaId);
    error SchemaDeprecated_(bytes32 schemaId);
    error OrgNotApprovedOrActive(bytes32 orgId);
    error NotOrgMember(bytes32 orgId, address caller);
    error EmptyUri();
    error ZeroSchemaId();
    error ZeroSchemaHash();

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event SchemaRegistered(bytes32 indexed schemaId, bytes32 indexed issuerOrg, bytes32 schemaHash, string uri);
    event SchemaDeprecated(bytes32 indexed schemaId);

    // ──────────────────────────────────────────────────────────────────
    // Writes
    // ──────────────────────────────────────────────────────────────────

    function registerSchema(bytes32 orgId, bytes32 schemaId, bytes32 schemaHash, string calldata uri) external;

    function deprecateSchema(bytes32 schemaId) external;

    // ──────────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────────

    function getSchema(bytes32 schemaId) external view returns (Schema memory);

    function exists(bytes32 schemaId) external view returns (bool);

    function isActive(bytes32 schemaId) external view returns (bool);
}
