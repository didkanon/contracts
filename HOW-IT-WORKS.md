# How Kanon Works

A short technical walkthrough of the kanon SSI stack — what the pieces are,
how they fit, and what happens when a credential is issued, presented and
revoked.

---

## What it is

Kanon is an AnonCreds-compatible Self-Sovereign Identity stack that
replaces the traditional Indy ledger with a set of EVM contracts. The
underlying credential format and the wallet-side AnonCreds CL signature
flow are unchanged — anything that speaks AnonCreds can issue / verify
credentials on the kanon VDR.

Two tiers of revocation are supported:

- **Mode A — TIER_ONE_TIME**
  Per-credential revocation status is stored on chain, keyed by a hash
  of the credential's id. Simple, cheap, and works with any AnonCreds
  proof, but reveals the credId to the verifier (links presentations).

- **Mode B — TIER_ZK_SNARK**
  Non-revocation is proven by a Groth16 SNARK over a tagged Poseidon
  Merkle tree of currently-active credential leaves. The proof reveals
  only the credDef id, the issuer's BabyJubjub public key, a verifier
  nonce, and one AnonCreds-revealed attribute. Different presentations
  of the same credential to different verifiers are not linkable.

A credDef may opt into either mode or both (`TIER_ALL`).

---

## On-chain contracts

All contracts are UUPS-upgradeable with role-gated upgrade authority.

| Contract                          | Purpose                                                                                                                            |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `OrganizationRegistry`            | Tracks issuer orgs and their members. Issuance writes are gated on org membership.                                                 |
| `DIDRegistry`                     | Resolves `did:kanon:user:*` and `did:kanon:org:*` DIDs. Documents include verification methods.                                    |
| `SchemaRegistry`                  | Stores AnonCreds schemas: `(schemaHash, issuerOrg, uri)`. The full schema body rides inline as a `data:` URI so it resolves cross-agent. |
| `CredentialDefinitionRegistry`    | Stores AnonCreds credDefs: `(schemaId, issuerOrg, issuerPubKey, policyMask, uri)`. For Mode B credDefs also stores the BabyJubjub issuer key `(ax, ay)`. |
| `AnonCredsStatusRegistry`         | Mode A. Maps `(credDefId, credIdHash) → {Issued, Revoked}`. Verifiers query after the AnonCreds proof verifies.                    |
| `MerkleStateRegistry`             | Mode B. Stores per-credDef Merkle roots (one keccak root for Mode A's nullifier path, one Poseidon root for Mode B's SNARK path) with a sliding window of recent roots. |
| `Halo2VerifierRegistry`           | Allowlist of approved SNARK verifier contracts (legacy interface name — backend is Groth16).                                       |
| `Groth16NonRevocationVerifier`    | Thin adapter implementing the registry's verifier interface and delegating to the snarkjs-generated `Groth16Verifier`.             |
| `Groth16Verifier`                 | Auto-generated from the `non_revocation.circom` proving key. Takes 7 public signals.                                               |

The credential definition registry rejects:

- Mode A registrations that carry a non-zero BabyJubjub key.
- Mode B / TIER_ALL registrations whose key is `(0, 0)`, the BabyJubjub
  identity `(0, 1)`, or any coordinate `>= BN254 scalar field`.

Once registered, the credDef's policy mask and issuer ZK key are
immutable — rotating them would silently invalidate every previously
issued Mode B proof.

---

## The roles

- **Issuer organisation** — a registered org with one or more member
  addresses. Owns schemas and credDefs. Holds the AnonCreds CL signing
  key (off-chain) and, for Mode B credDefs, a BabyJubjub EdDSA key.
- **Holder** — any wallet running a credo-ts agent with the kanon
  plugin. Receives credentials, stores them in an Askar (or in-memory)
  wallet, presents them in response to proof requests.
- **Verifier** — any party that issues an AnonCreds proof request and
  validates the response. With the kanon plugin, the validation also
  consults the chain for revocation status (Mode A) and the on-chain
  Groth16 verifier (Mode B).

---

## The circuit

`non_revocation.circom` proves:

1. The credential's leaf
   `Poseidon(LEAF_TAG=1, credDefId, credId, Poseidon(attrs))`
   is signed by the issuer's BabyJubjub key.
2. The leaf is in the Merkle tree rooted at `publicSignals[0]`.
   Parents are `Poseidon(NODE_TAG=2, left, right)`.
3. One selectively disclosed attribute equals a public value at a
   specific position in the attribute array.

Public signals layout:

```
[0] root            — recent Poseidon root of the credDef's active set
[1] credDefId       — bound to uint256(credDefId) mod p
[2] challenge       — the proof-request nonce reduced mod p
[3] issuerAx        — issuer's BabyJubjub public key coord
[4] issuerAy
[5] disclosedIndex  — canonical-sort position of the revealed attribute
[6] disclosedValue  — felt of the revealed attribute value
```

Private inputs: the credId, the full attribute array, the Merkle path,
and the BabyJubjub signature components.

The proving key was generated from the public Hermez Perpetual Powers of
Tau ceremony (2^16, hundreds of independent contributors) followed by a
per-circuit phase-2 setup. The Solidity verifier is auto-generated from
the resulting zkey.

---

## What lives where off-chain

| Layer                | Where                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| TypeScript SDK       | `@ajna-inc/kanon-sdk`. Single source of truth for contract ABIs, attribute encoding, Poseidon helpers, leaf computation, BabyJubjub key handling, snarkjs prover wrapper. |
| credo-ts plugin (v5) | `@ajna-inc/kanon` (credo 0.5 track). AnonCreds registry, issuance tracker, wrapped verifier service, revocation API.                                                       |
| credo-ts plugin (v6) | `@ajna-inc/kanon` (credo 0.6 track). Everything in v5, plus Mode B: wrapped holder service that injects SNARK proofs, wrapped verifier service that validates them on chain, BabyJubjub key lifecycle service, path-discovery service. |
| ACA-Py plugin        | `did_kanon` (Python). Mirror of the issuer side for Aries Cloud Agent Python deployments. Vendors a circomlib-compatible Poseidon implementation.                          |

---

## Lifecycle: Mode A (TIER_ONE_TIME)

```
issuer ───▶ register schema    on SchemaRegistry
issuer ───▶ register credDef   on CredentialDefinitionRegistry (policyMask=1)
issuer ───▶ issue credential   AnonCreds CL signature; credential includes kanonCredId
issuer ───▶ on credential.done event:
           issuanceTracker.issueCredentialStatus(credDefId, kanonCredIdHash(credId))
                                ▶ AnonCredsStatusRegistry

holder ───▶ presents AnonCreds proof revealing kanonCredId
verifier ──▶ runs AnonCreds verifyProof (CL signature check)
        ──▶ wrapped verifier additionally queries:
            AnonCredsStatusRegistry.isRevoked(credDefId, kanonCredIdHash(credId))
            ▶ pass / fail

issuer ───▶ revoke:
           AnonCredsStatusRegistry.revokeCredential(credDefId, kanonCredIdHash(credId))
```

The `kanonCredId` is a per-credential 32-byte secret placed in a
reserved AnonCreds attribute slot. Verifiers ask for it as a revealed
attribute in their proof requests via the helper
`buildKanonProofRequest({ kanonCredDefIds: [...] })`.

---

## Lifecycle: Mode B (TIER_ZK_SNARK)

```
issuer ───▶ register schema    (schema MUST include kanonCredId and kanonZkSig attrs)
issuer ───▶ register credDef   policyMask=2 or 3; auto-provisions a BabyJubjub keypair,
                                writes (ax, ay) on chain in the same tx

issuer ───▶ prepareModeBCredential({credDefId, domainAttributes}):
           ▶ generates a fresh kanonCredId
           ▶ computes the tagged leaf
           ▶ BabyJubjub-signs the leaf
           ▶ returns the credential attribute set with kanonCredId + kanonZkSig
             injected, ready to feed into the standard AnonCreds offer

issuer ───▶ issue via standard AnonCreds flow (CL signs over everything,
           including kanonCredId and kanonZkSig — preserves the AnonCreds
           "signs over the whole credential" property)

issuer ───▶ on credential.done event:
           issuanceTracker reads the credential attributes, felt-encodes them,
           computes the same leaf locally, publishes it to MerkleStateRegistry
           via batchUpdate(addedLeaves, ..., newRoot)

verifier ──▶ proof request includes `kanon_<credDefId>_zkProof` as a
            self-attestable referent and at least one revealed attribute
            restricted to the credDef.

holder ───▶ kanon-aware wrapped holder service intercepts createProof:
           ▶ resolves the current Poseidon tree by replaying CredentialAdded
             / CredentialRevoked events
           ▶ reads the issuer's BabyJubjub (Ax, Ay) from on chain
           ▶ runs the snarkjs prover with the wallet's stored kanonZkSig
             and the local credId
           ▶ encodes the proof + public signals as a base64 string and
             puts it in self_attested_attributes.kanon_<credDefId>_zkProof
           ▶ delegates to the standard AnonCreds proof creation

verifier ──▶ kanon-aware wrapped verifier service intercepts verifyProof:
           ▶ standard AnonCreds CL verification first
           ▶ checks publicSignals[1] == credDefId mod p
           ▶ checks publicSignals[2] == proofRequest.nonce mod p (challenge binding)
           ▶ checks publicSignals[3,4] == on-chain issuer key for this credDef
           ▶ checks (publicSignals[5], publicSignals[6]) match a
             (position, value) pair the holder also revealed in AnonCreds
           ▶ submits to MerkleStateRegistry.verifyZKMembership, which
             additionally checks the recent-roots window and delegates
             to the Groth16Verifier

issuer ───▶ revoke:
           KanonZkService.revoke(credDefId, [credId])
           ▶ recomputes the active set, publishes a new Poseidon root via
             MerkleStateRegistry.batchUpdate
```

A credDef with `policyMask = TIER_ALL` runs both flows in parallel — the
issuance tracker writes to both registries, and the verifier wrapper
checks both.

---

## Cryptographic agreement points

All three implementations of Poseidon (`circomlibjs` in the SDK, the
vendored pure-Python port in the ACA-Py plugin, and the auto-generated
Solidity verifier) use identical parameters, constants and tags. They
produce bit-identical hashes for the same inputs.

Tags:

- `LEAF_TAG = 1` — first input to every leaf hash.
- `NODE_TAG = 2` — first input to every Merkle parent hash.

Domain separation prevents any internal Merkle node value from being
structurally interpretable as a leaf (and vice versa). The tags must be
mirrored across the off-chain JavaScript and Python trees.

Attribute encoding:

- Domain attribute values are felt-encoded as
  `uint256(keccak256(utf8(value))) mod BN254_SCALAR_FIELD`.
- The attribute array fed to the circuit is sorted lexicographically by
  attribute name, with the SDK-reserved names (`kanonCredId`,
  `kanonZkSig`) excluded. The same canonical ordering is used by the
  issuer at signing time, by the issuance tracker at publish time, and
  by the holder when generating the SNARK.

Field reduction:

- `credDefId` and `credId` are reduced from their on-chain `bytes32`
  form to BN254 felts via `uint256(...) mod p`. Both sides agree.
- The challenge is `uint256(proofRequest.nonce) mod p`. AnonCreds
  already binds the nonce to the exchange, so reusing it inherits
  anti-replay.

---

## Reserved AnonCreds attribute names

| Name           | Type             | Purpose                                                              |
| -------------- | ---------------- | -------------------------------------------------------------------- |
| `kanonCredId`  | revealed         | Mode A's per-credential identifier. Verifiers hash it for the status lookup. |
| `kanonZkSig`   | regular cred attr| Mode B's BabyJubjub signature over the leaf. The CL signature covers it; the holder NEVER reveals it (the wrapper refuses if a verifier asks). |
| `kanon_<credDefId>_zkProof` | self-attested | Mode B's SNARK proof + public signals (base64). |

---

## Unlinkability properties

**Mode A** intentionally reveals the credId to the verifier. Verifiers
who collude can correlate "this is the same credential" across
presentations. Anyone watching the chain can correlate `(credDefId,
credIdHash)` to issuance and revocation events. This is the documented
tradeoff for cheap on-chain revocation.

**Mode B** SNARK proofs only carry:

- `root`, `credDefId`, `issuerAx`, `issuerAy` — same for every holder of
  the credDef at that epoch.
- `challenge` — verifier-chosen per session.
- `disclosedIndex`, `disclosedValue` — bound to an AnonCreds-revealed
  attribute the verifier was already going to see.

No per-credential identifier leaks through the proof. Different
presentations of the same credential to different verifiers are not
linkable through the SNARK output.

---

## File layout

```
besi_blockchain/kanonv2/
├── contracts/                      Solidity sources
├── circom/                         non_revocation.circom + build artifacts
├── sdk/                            @ajna-inc/kanon-sdk
├── test/                           hardhat tests
└── scripts/                        deploy, upgrade, ceremony

credo-ts-kanon/credo-ts/packages/kanon/    @ajna-inc/kanon (credo 0.5)
credo-ts-6/credo-ts/packages/kanon/        @ajna-inc/kanon (credo 0.6)
digicred-crms/plugins/did_kanon/           ACA-Py issuer plugin
```

---

## Deployments + configuration

A credo agent loading the kanon plugin needs one of:

- `addressBook` — address of an on-chain `KanonAddressBook` that
  resolves the seven registry addresses for the chain.
- `deployment` — an inline object with the registry addresses.
- `deploymentPath` — path to a deployments JSON.
- `chainId` — load a bundled deployment from the SDK.

Plus:

- `rpcUrl` — JSON-RPC endpoint.
- `privateKey` — the operator key for on-chain writes.
- `anonCredsStatusRegistryAddress` — optional. Required to enable Mode A
  status checks at verification time.
- `issuerOrgId` — required for issuance flows.

When `addressBook` is configured, the seven registry addresses (plus the
optional status registry) are resolved on chain at agent initialise
time.
