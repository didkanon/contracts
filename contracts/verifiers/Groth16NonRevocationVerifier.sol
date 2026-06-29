// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IHalo2Verifier} from "../interfaces/IHalo2Verifier.sol";

/// @dev The snarkjs-generated Groth16 verifier (BN254). Auto-generated; do not hand-edit.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[7] calldata publicSignals
    ) external view returns (bool);
}

/// @title Groth16NonRevocationVerifier
/// @notice Adapts the snarkjs Groth16 verifier to the registry's `IHalo2Verifier` interface
///         (the interface name is a historical artifact; the backend is Groth16 over BN254).
///         `MerkleStateRegistry.verifyZKMembership` already checks publicSignals[0] against the
///         recent Poseidon-root window before delegating here.
/// @dev Public-signal layout (7), matching circom/src/non_revocation.circom:
///        [0] root, [1] credDefId, [2] challenge, [3] issuerAx, [4] issuerAy,
///        [5] disclosedIndex[0], [6] disclosedValue[0]
contract Groth16NonRevocationVerifier is IHalo2Verifier {
    IGroth16Verifier public immutable groth16;

    uint256 internal constant NUM_PUBLIC_SIGNALS = 7;

    /// @notice Circuit version identifier (must NOT be the registry's stub sentinel).
    bytes32 public constant CIRCUIT_VERSION = keccak256("kanonv2.non_revocation.groth16.v1");

    error MalformedProof();
    error WrongPublicSignalCount(uint256 got, uint256 expected);

    constructor(address groth16Verifier) {
        groth16 = IGroth16Verifier(groth16Verifier);
    }

    /// @inheritdoc IHalo2Verifier
    /// @param proof abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)
    /// @param publicSignals exactly 7 field elements in the circuit's public order
    function verify(bytes calldata proof, bytes32[] calldata publicSignals)
        external
        view
        override
        returns (bool)
    {
        if (publicSignals.length != NUM_PUBLIC_SIGNALS) {
            revert WrongPublicSignalCount(publicSignals.length, NUM_PUBLIC_SIGNALS);
        }
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            _decodeProof(proof);

        uint256[7] memory signals;
        for (uint256 i = 0; i < NUM_PUBLIC_SIGNALS; ++i) {
            signals[i] = uint256(publicSignals[i]);
        }
        return groth16.verifyProof(a, b, c, signals);
    }

    /// @inheritdoc IHalo2Verifier
    function circuitVersion() external pure override returns (bytes32) {
        return CIRCUIT_VERSION;
    }

    function _decodeProof(bytes calldata proof)
        internal
        pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        if (proof.length != 32 * 8) revert MalformedProof();
        (a, b, c) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
    }

    /// @notice Helper for off-chain callers to encode a proof the way `verify` expects.
    function encodeProof(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c)
        external
        pure
        returns (bytes memory)
    {
        return abi.encode(a, b, c);
    }
}
