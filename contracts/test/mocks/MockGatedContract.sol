// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IMerkleStateRegistry} from "../../interfaces/IMerkleStateRegistry.sol";

/// @notice Example credential-gated contract that consumes a one-time-use credential per action.
/// @dev This is the canonical pattern for credential-gated contracts. Other consumers
///      (DAOs, marketplaces, age gates) should follow the same shape.
contract MockGatedContract {
    IMerkleStateRegistry public immutable registry;
    bytes32 public immutable credDefId;

    mapping(address => uint256) public actionsByCaller;
    uint256 public totalActions;

    event GatedActionPerformed(address indexed caller, bytes32 credId, uint256 callerActions);

    constructor(IMerkleStateRegistry registry_, bytes32 credDefId_) {
        registry = registry_;
        credDefId = credDefId_;
    }

    /// @notice Perform a gated action. Reverts unless the caller presents a valid, unused credential.
    function performAction(bytes32 credId, bytes32[] calldata proof) external {
        registry.consumeOneTime(credDefId, credId, proof);
        unchecked {
            actionsByCaller[msg.sender] += 1;
            totalActions += 1;
        }
        emit GatedActionPerformed(msg.sender, credId, actionsByCaller[msg.sender]);
    }
}
