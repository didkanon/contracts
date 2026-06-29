// @ts-nocheck
// Self-contained ZK glue for the Tier-2 hardhat tests. It mirrors sdk/src/zk but is kept
// standalone because the SDK is packaged as ESM ("type":"module") and the hardhat test
// runner is CJS (ts-node) — it cannot require() the ESM SDK. Logic is identical; the SDK
// is the published source of truth, this is the test-runner-compatible copy.
import * as path from "path";
import { AbiCoder } from "ethers";
import { buildPoseidon, buildEddsa } from "circomlibjs";
import * as snarkjs from "snarkjs";

const BUILD = path.resolve(__dirname, "..", "..", "circom", "build");
export const WASM_PATH = path.join(BUILD, "non_revocation_js", "non_revocation.wasm");
export const ZKEY_PATH = path.join(BUILD, "nr_final.zkey");

export const DEPTH = 26;
export const N_ATTR = 16;

// Domain-separation tags — MUST match `non_revocation.circom`:
//   LEAF_TAG = 1 → first input of `Poseidon(LEAF_TAG, credDefId, credId, attrHash)`
//   NODE_TAG = 2 → first input of `Poseidon(NODE_TAG, left, right)`
export const LEAF_TAG = 1n;
export const NODE_TAG = 2n;

// BN254 scalar-field prime. The circuit treats credDefId / credId as felts, so
// the on-chain registry's bytes32 values are reduced mod this prime before
// being supplied to the circuit. The MerkleStateRegistry mirrors the reduction.
export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let _poseidon: any;
let _eddsa: any;

export async function zkInit() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  if (!_eddsa) _eddsa = await buildEddsa();
  return { poseidon: _poseidon, eddsa: _eddsa };
}

const toBig = (F: any, x: any): bigint => F.toObject(x);

function poseidonBig(inputs: bigint[]): bigint {
  const F = _poseidon.F;
  return F.toObject(_poseidon(inputs.map((x) => F.e(x))));
}

/** Tagged Merkle parent — `Poseidon(NODE_TAG, left, right)`. Matches the circuit. */
function hashNode(left: bigint, right: bigint): bigint {
  return poseidonBig([NODE_TAG, left, right]);
}

export class PoseidonTree {
  depth: number;
  private zeros: bigint[];
  private nodes: Map<number, bigint>[];

  constructor(depth: number, leaves: bigint[]) {
    this.depth = depth;
    this.zeros = new Array(depth + 1);
    this.zeros[0] = 0n;
    for (let d = 1; d <= depth; d++) this.zeros[d] = hashNode(this.zeros[d - 1], this.zeros[d - 1]);
    this.nodes = Array.from({ length: depth + 1 }, () => new Map<number, bigint>());
    for (let i = 0; i < leaves.length; i++) this.insert(i, leaves[i]);
  }

  private nodeAt(level: number, index: number): bigint {
    const v = this.nodes[level].get(index);
    return v !== undefined ? v : this.zeros[level];
  }

  private insert(leafIndex: number, value: bigint): void {
    this.nodes[0].set(leafIndex, value);
    let idx = leafIndex;
    for (let level = 0; level < this.depth; level++) {
      const isRight = idx % 2;
      const left = isRight ? this.nodeAt(level, idx - 1) : this.nodeAt(level, idx);
      const right = isRight ? this.nodeAt(level, idx) : this.nodeAt(level, idx + 1);
      idx = Math.floor(idx / 2);
      this.nodes[level + 1].set(idx, hashNode(left, right));
    }
  }

  get root(): bigint {
    return this.nodeAt(this.depth, 0);
  }

  proof(index: number): { pathElements: bigint[]; pathIndices: number[] } {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = index;
    for (let d = 0; d < this.depth; d++) {
      const isRight = idx % 2;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(this.nodeAt(d, siblingIdx));
      pathIndices.push(isRight);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }
}

export interface IssuerKeys {
  sk: Buffer;
  Ax: bigint;
  Ay: bigint;
}

export function newIssuer(seed = 1): IssuerKeys {
  const sk = Buffer.alloc(32, seed);
  const pub = _eddsa.prv2pub(sk);
  return { sk, Ax: toBig(_eddsa.F, pub[0]), Ay: toBig(_eddsa.F, pub[1]) };
}

export interface IssuedCredential {
  credId: bigint;
  attributes: bigint[];
  attributesHash: bigint;
  leaf: bigint;
  sigR8x: bigint;
  sigR8y: bigint;
  sigS: bigint;
}

export function issueCredential(
  issuer: IssuerKeys,
  credDefId: bigint,
  credId: bigint,
  attributes: bigint[]
): IssuedCredential {
  const F = _poseidon.F;
  const attributesHash = poseidonBig(attributes);
  // leaf = Poseidon(LEAF_TAG, credDefId, credId, attrHash) — must match the
  // circuit exactly. The issuer signs this leaf with their BabyJubjub key, and
  // the same value is what the off-chain Poseidon tree hashes at the leaves.
  const leaf = poseidonBig([LEAF_TAG, credDefId, credId, attributesHash]);
  const sig = _eddsa.signPoseidon(issuer.sk, F.e(leaf));
  return {
    credId,
    attributes,
    attributesHash,
    leaf,
    sigR8x: toBig(_eddsa.F, sig.R8[0]),
    sigR8y: toBig(_eddsa.F, sig.R8[1]),
    sigS: BigInt(sig.S),
  };
}

export interface ProofForChain {
  proofBytes: string;
  publicSignals: string[];
  root: bigint;
}

export async function proveNonRevocation(params: {
  issuer: IssuerKeys;
  cred: IssuedCredential;
  tree: PoseidonTree;
  leafIndex: number;
  credDefId: bigint;
  challenge: bigint;
  disclosedIndex: number;
}): Promise<ProofForChain> {
  const { issuer, cred, tree, leafIndex, credDefId, challenge, disclosedIndex } = params;
  const { pathElements, pathIndices } = tree.proof(leafIndex);

  const input = {
    root: tree.root.toString(),
    credDefId: credDefId.toString(),
    challenge: challenge.toString(),
    issuerAx: issuer.Ax.toString(),
    issuerAy: issuer.Ay.toString(),
    disclosedIndex: [disclosedIndex.toString()],
    disclosedValue: [cred.attributes[disclosedIndex].toString()],
    credId: cred.credId.toString(),
    attributes: cred.attributes.map((a) => a.toString()),
    pathElements: pathElements.map((p) => p.toString()),
    pathIndices: pathIndices.map((p) => p.toString()),
    sigS: cred.sigS.toString(),
    sigR8x: cred.sigR8x.toString(),
    sigR8y: cred.sigR8y.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, inputs] = JSON.parse("[" + calldata + "]");
  const proofBytes = AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]"],
    [a, b, c]
  );
  const toBytes32 = (v: string) => "0x" + BigInt(v).toString(16).padStart(64, "0");
  return {
    proofBytes,
    publicSignals: (inputs as string[]).map(toBytes32),
    root: tree.root,
  };
}

export function toBytes32(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}
