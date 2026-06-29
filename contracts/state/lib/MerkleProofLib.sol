// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title MerkleProofLib
/// @notice Thin wrapper around OZ MerkleProof that fixes the standard-Merkle-tree convention
///         (sorted-pair hashing). The off-chain SMT must use the same convention; the
///         Phase-2 SDK uses the openzeppelin merkle-tree package which matches.
library MerkleProofLib {
    /// @notice Recover the Merkle root from a leaf and its sibling-hash path.
    /// @param proof Sibling hashes from leaf level up to (but not including) the root.
    /// @param leaf The leaf value being proved.
    /// @return root The computed root.
    function processProof(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        return MerkleProof.processProofCalldata(proof, leaf);
    }

    /// @notice Verify that `leaf` is in the tree rooted at `root` with `proof`.
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }
}
