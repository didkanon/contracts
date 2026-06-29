// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IHalo2Verifier} from "../../interfaces/IHalo2Verifier.sol";

/// @notice Test-only verifier. Returns the result configured at construction time.
contract MockHalo2Verifier is IHalo2Verifier {
    bool public immutable accept;
    bytes32 public immutable version;

    constructor(bool accept_, bytes32 version_) {
        accept = accept_;
        version = version_;
    }

    function verify(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return accept;
    }

    function circuitVersion() external view override returns (bytes32) {
        return version;
    }
}
