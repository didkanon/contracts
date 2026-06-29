// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title KanonTimelock
/// @notice Thin wrapper around OZ TimelockController for kanonv2 governance.
/// @dev Use as the holder of DEFAULT_ADMIN_ROLE / UPGRADER_ROLE / GOVERNANCE_ROLE
///      on every registry. A Safe multisig proposes; the timelock enforces the delay;
///      then the action executes.
///
/// Recommended configuration (configurable at construction):
///   - minDelay: 48 hours for production upgrades
///   - proposers: [Safe multisig address]
///   - executors: [Safe multisig address] or [address(0)] for permissionless execution
///   - admin: address(0) for timelock to manage itself (no super-admin)
contract KanonTimelock is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}
}
