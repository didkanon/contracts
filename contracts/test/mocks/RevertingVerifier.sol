// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IHalo2Verifier} from "../../interfaces/IHalo2Verifier.sol";

/// @notice Test-only verifier whose circuitVersion() always reverts.
contract RevertingVerifier is IHalo2Verifier {
    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        return false;
    }

    function circuitVersion() external pure override returns (bytes32) {
        revert("circuitVersion reverts");
    }
}
