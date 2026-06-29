import { keccak256, hexlify, getBytes, concat } from "ethers";

/**
 * Standard OZ-compatible Merkle tree using sorted-pair keccak256 hashing.
 * Matches @openzeppelin/contracts MerkleProof.verify semantics.
 */
export class StandardMerkleTree {
  readonly leaves: string[];
  readonly layers: string[][];

  constructor(leaves: string[]) {
    if (leaves.length === 0) throw new Error("StandardMerkleTree: empty leaves");
    // Sort leaves to make tree canonical
    this.leaves = [...leaves].sort();
    this.layers = [this.leaves.slice()];
    let current = this.layers[0];
    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(hashPair(current[i], current[i + 1]));
        } else {
          next.push(current[i]); // odd node propagates
        }
      }
      this.layers.push(next);
      current = next;
    }
  }

  get root(): string {
    return this.layers[this.layers.length - 1][0];
  }

  proofFor(leaf: string): string[] {
    let idx = this.leaves.indexOf(leaf);
    if (idx === -1) throw new Error("StandardMerkleTree: leaf not found");
    const proof: string[] = [];
    for (let l = 0; l < this.layers.length - 1; l++) {
      const layer = this.layers[l];
      const siblingIdx = idx ^ 1;
      if (siblingIdx < layer.length) {
        proof.push(layer[siblingIdx]);
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }
}

function hashPair(a: string, b: string): string {
  const ab = a.toLowerCase();
  const bb = b.toLowerCase();
  const [lo, hi] = ab < bb ? [ab, bb] : [bb, ab];
  return keccak256(concat([getBytes(lo), getBytes(hi)]));
}

/**
 * Public leaf for a one-time credential, matching on-chain `MerkleStateRegistry.deriveLeaf`:
 * double-keccak of the secret credId. `abi.encode(bytes32)` is the raw 32 bytes, so this is
 * keccak256(keccak256(credId)).
 */
export function deriveLeaf(credId: string): string {
  return keccak256(keccak256(credId));
}

/**
 * Build a Merkle tree of one-time credentials. Leaves are the public derived leaves; the
 * `credIds` returned are the SECRETS that holders present to `consumeOneTime`. Tier 1 is a
 * bearer model — the credId is the bearer secret and the leaf is its double-keccak
 * commitment, so `owner` is not folded in.
 */
export function buildOneTimeCredentialTree(
  pairs: { credId: string; owner: string }[]
): { tree: StandardMerkleTree; leaves: string[]; credIds: string[] } {
  const credIds = pairs.map((p) => p.credId);
  const leaves = credIds.map(deriveLeaf);
  const tree = new StandardMerkleTree(leaves);
  return { tree, leaves, credIds };
}
