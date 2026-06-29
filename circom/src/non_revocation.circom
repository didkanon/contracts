pragma circom 2.1.6;

include "poseidon.circom";
include "eddsaposeidon.circom";
include "comparators.circom";

// ─── Domain separation tags ────────────────────────────────────────────────
// Both the leaf hash and the Merkle parent hash use Poseidon over the same
// field. Without tags an internal node value could be confused with a
// (credId, attrHash) leaf — collisions become structurally meaningful instead
// of just being random. We bake a constant tag into each position so a leaf
// can never be misinterpreted as a node and vice versa. Tags MUST be mirrored
// in the off-chain JS / Python Merkle trees that compute the same roots.
//
//   LEAF_TAG = 1   marks `Poseidon(LEAF_TAG, credDefId, credId, attrHash)`
//   NODE_TAG = 2   marks `Poseidon(NODE_TAG, left, right)`
// (Circom 2.1.x doesn't accept `var` at global scope, so each template
//  declares its own copy. Both MUST stay in lockstep.)

// Fixed-depth binary Merkle inclusion using Poseidon(3). The parent is
// `Poseidon(NODE_TAG, left, right)` where ordering is determined by the path
// index bit (0 = current node is the left child, 1 = right child). The
// off-chain JS / Python trees MUST use the identical tagged + index-ordered
// hashing.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    var NODE_TAG = 2;

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    signal left[depth];
    signal right[depth];

    for (var i = 0; i < depth; i++) {
        // index bit must be boolean
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // swap-by-bit
        left[i] <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);

        // Tagged Poseidon(3) parent — domain-separated from the leaf hash.
        hashers[i] = Poseidon(3);
        hashers[i].inputs[0] <== NODE_TAG;
        hashers[i].inputs[1] <== left[i];
        hashers[i].inputs[2] <== right[i];
        cur[i + 1] <== hashers[i].out;
    }

    root <== cur[depth];
}

// Constrain `attributes[disclosedIndex] === disclosedValue` without revealing
// the other attributes. Array indexing by a signal is done with an equality
// fan-out: `eq[j].out` is 1 only at the matching index. We additionally count
// the matches and require exactly one — without this, an out-of-range index
// (e.g. `disclosedIndex = 999`) silently produces `partial[nAttr] = 0` and
// the prover can "disclose" `disclosedValue = 0` for an attribute that does
// not exist. The match-count constraint closes that hole.
template AttributeSelector(nAttr) {
    signal input attributes[nAttr];
    signal input index;
    signal input value;

    component eq[nAttr];
    signal partial[nAttr + 1];
    signal matches[nAttr + 1];

    partial[0] <== 0;
    matches[0] <== 0;

    for (var j = 0; j < nAttr; j++) {
        eq[j] = IsEqual();
        eq[j].in[0] <== index;
        eq[j].in[1] <== j;

        partial[j + 1] <== partial[j] + eq[j].out * attributes[j];
        matches[j + 1] <== matches[j] + eq[j].out;
    }

    // Reject out-of-range indices: every `IsEqual` is 0, so without this the
    // prover could set (index=999, value=0) and the proof passes.
    matches[nAttr] === 1;

    // The selected attribute equals the disclosed value.
    value === partial[nAttr];
}

// Non-revocation + selective-disclosure proof.
//
// Proves, in zero knowledge, that the prover holds a credential whose leaf is
// in the issuer's current Merkle tree (non-revocation), that the credential
// was signed by the issuer (EdDSA-BabyJubjub over Poseidon), and selectively
// reveals chosen attribute values — without revealing credId, the other
// attributes, or which leaf is being proven.
//
// The leaf binds `credDefId` so the issuer's signature can never be re-used
// under a different credDef even if the issuer's BabyJubjub key happens to be
// shared across credDefs.
//
// Public signal order (index 0 MUST be the Poseidon root — MerkleStateRegistry
// checks publicSignals[0] against its recent-roots window):
//   0: root
//   1: credDefId
//   2: challenge
//   3: issuerAx
//   4: issuerAy
//   5 + 2k:     disclosedIndex[k]
//   6 + 2k:     disclosedValue[k]
template NonRevocation(depth, nAttr, nDisclose) {
    // ── public ──
    signal input root;
    signal input credDefId;
    signal input challenge;
    signal input issuerAx;
    signal input issuerAy;
    signal input disclosedIndex[nDisclose];
    signal input disclosedValue[nDisclose];

    // ── private ──
    signal input credId;
    signal input attributes[nAttr];
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input sigS;
    signal input sigR8x;
    signal input sigR8y;

    // 1. attributesHash = Poseidon(attributes)
    component attrHash = Poseidon(nAttr);
    for (var i = 0; i < nAttr; i++) {
        attrHash.inputs[i] <== attributes[i];
    }

    // 2. leaf = Poseidon(LEAF_TAG, credDefId, credId, attributesHash).
    //    Domain-separated from Merkle node hashes (NODE_TAG = 2) and
    //    intrinsically credDef-specific — the issuer's signature can no longer
    //    be re-used under a different credDef.
    var LEAF_TAG = 1;
    component leafHash = Poseidon(4);
    leafHash.inputs[0] <== LEAF_TAG;
    leafHash.inputs[1] <== credDefId;
    leafHash.inputs[2] <== credId;
    leafHash.inputs[3] <== attrHash.out;
    signal leaf;
    leaf <== leafHash.out;

    // 3. EdDSA-BabyJubjub signature verification over the leaf.
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== issuerAx;
    sig.Ay <== issuerAy;
    sig.S <== sigS;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.M <== leaf;

    // 4. Merkle non-revocation membership against the public root.
    component inc = MerkleInclusion(depth);
    inc.leaf <== leaf;
    for (var i = 0; i < depth; i++) {
        inc.pathElements[i] <== pathElements[i];
        inc.pathIndices[i] <== pathIndices[i];
    }
    inc.root === root;

    // 5. Selective disclosure with a valid-index guard (see AttributeSelector).
    component sel[nDisclose];
    for (var k = 0; k < nDisclose; k++) {
        sel[k] = AttributeSelector(nAttr);
        for (var i = 0; i < nAttr; i++) {
            sel[k].attributes[i] <== attributes[i];
        }
        sel[k].index <== disclosedIndex[k];
        sel[k].value <== disclosedValue[k];
    }

    // 6. Bind the challenge into the constraint system. credDefId is now bound
    //    via the leaf hash itself (step 2), so we only need the challenge no-op
    //    here for verifier-checked anti-replay — the SNARK ensures the proof
    //    commits to the public challenge value, and the verifier asserts
    //    publicSignals[2] equals the nonce it issued.
    signal challengeSq;
    challengeSq <== challenge * challenge;
}

component main {
    public [root, credDefId, challenge, issuerAx, issuerAy, disclosedIndex, disclosedValue]
} = NonRevocation(26, 16, 1);
