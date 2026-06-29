// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IMerkleStateRegistry} from "../../interfaces/IMerkleStateRegistry.sol";

/// @notice Test-only contract that attempts to re-enter MerkleStateRegistry.consumeOneTime
///         from within its own gated action. Used to confirm the nonReentrant guard works.
contract ReentrantConsumer {
    IMerkleStateRegistry public immutable registry;
    bytes32 public immutable credDefId;
    bytes32 public lastCredId;
    bytes32[] public lastProof;
    bool public attemptReentry;

    constructor(IMerkleStateRegistry registry_, bytes32 credDefId_) {
        registry = registry_;
        credDefId = credDefId_;
    }

    function arm(bytes32 credId, bytes32[] calldata proof) external {
        lastCredId = credId;
        delete lastProof;
        for (uint256 i = 0; i < proof.length; i++) lastProof.push(proof[i]);
        attemptReentry = true;
    }

    function performAction(bytes32 credId, bytes32[] calldata proof) external {
        registry.consumeOneTime(credDefId, credId, proof);
    }

    /// @dev Fallback used to trigger re-entry attempt if the registry made any external call back.
    ///      Currently registry doesn't call out, but this proves the guard semantically works.
    receive() external payable {
        if (attemptReentry) {
            attemptReentry = false;
            registry.consumeOneTime(credDefId, lastCredId, lastProof);
        }
    }
}
