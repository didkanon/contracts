# Kanon — ZK Unlinkability Model

This document is a precise description of what "uncorrelatable" means in Kanon's Tier 2 (ZK)
path: which dimensions of correlation we defend against, the cryptographic mechanisms that
produce each property, the threats we do *not* defend against, how this compares to other
SSI approaches, and the honest current implementation status.

Tier 1 (one-time-use bearer credentials) is deliberately *not* unlinkable — it's a low-cost
on-chain claim-code path documented elsewhere. This document is exclusively about Tier 2.

---

## 1. What "uncorrelatable" means here

We separate four distinct correlation axes. Saying "ZK" without naming the axis is the source
of most confusion in SSI. Kanon's Tier 2 design targets all four; we say so explicitly so the
implementation can be reviewed against the claim.

| Axis | Question being asked | Tier-2 stance |
|---|---|---|
| **A. Presentation–presentation** | Can a single verifier (or two colluding verifiers) tell two of holder X's presentations are the same person? | No — distinct proofs are statistically independent. |
| **B. Verifier–verifier** | If verifiers V1 and V2 share notes, do they see a shared identifier they can link on? | No — there is no shared identifier on the wire. |
| **C. Issuer ↔ presentation** | Can the issuer who minted the credential observe when/where it is later used? | No — the issuer learns nothing from presentations they are not the relying party for. |
| **D. Chain observer ↔ holder** | Can a chain observer link a presentation to a credential entry or a wallet address? | No — presentations leak no on-chain footprint by default; when on-chain verification is used, only the proof bytes and chosen disclosures appear, never the credential or holder key. |

Two further properties we claim but call out separately because they are weaker:

- **Selective disclosure soundness.** A holder cannot reveal an attribute value they don't
  hold; padding/unused-disclosure slots cannot be used to smuggle attacker-chosen values.
- **Replay locality.** A given presentation is bound to a single verifier challenge so it
  cannot be re-played by an eavesdropper against a different verifier session.

---

## 2. Threat model

### 2.1 Adversaries we explicitly defend against

- **Curious verifier (active).** Chooses the challenge; sees the proof and any attributes the
  holder discloses. Goal: re-identify the holder or link presentations.
- **Colluding verifiers.** Pool their proofs, public inputs, and chosen disclosures. Goal:
  cross-link presentations of the same holder.
- **Curious issuer.** Knows everything they issued (credId, attributes, leaf commitment).
  Sees all on-chain events including Merkle roots and their own `CredentialAdded` entries.
  Goal: learn when their credentials are presented and to whom.
- **Chain observer (passive).** Indexes the chain, sees every event, RPC reads. Goal: link
  any on-chain footprint of a presentation to a credential or holder.
- **Network observer.** Sees presentation packets (proof + public inputs) over the wire.
  Goal: link two such packets to the same prover.

### 2.2 Out of scope — adversaries we do not defend against

- **Compromise of the holder's signing key.** A key holder can produce real presentations.
  Standard wallet hygiene.
- **Issuer signing-key compromise.** The issuer can mint new credentials. Mitigation is
  issuer key custody (HSM) and revocation, not ZK.
- **The verifier asks for enough attributes to identify the holder.** If a holder discloses
  attributes that are jointly unique, they are de-anonymized. ZK does not defend against the
  holder's own disclosure choices.
- **Side channels.** Timing, IP-level traffic analysis at the network layer, hardware
  forensics on the prover device, browser fingerprinting on a holder's wallet UI.
- **Out-of-band linkage.** If the verifier already knows the holder's identity (logged in,
  KYC'd at a parent level, paid via a linked rail), ZK presentations made within that session
  are linkable through that out-of-band channel — not through the ZK protocol.

The honest summary: **ZK gives you protocol-level unlinkability; product and ops design
have to preserve it.**

---

## 3. Construction

The construction is described at a level that is independent of the SNARK backend. Both
Halo2-KZG (the documented Phase-2 target) and Circom+Groth16 (the implementability pivot
under evaluation) provide the same zero-knowledge guarantee at the level discussed here. The
mechanics below hold for either; backend choice affects setup, proof size, and gas only.

### 3.1 The leaf commitment

When the issuer issues credential *i* to holder *H*:

```
leaf_i = Poseidon( Poseidon(credId_i, attrHash_i),
                   Poseidon(holderBindingKey_i, randomness_i) )
```

Each leaf hides four secrets behind a Poseidon hash:

- `credId_i` — random 32 bytes, never published, known only to the holder.
- `attrHash_i` — Merkle-Damgard chain of Poseidon over a fixed-length `MAX_ATTRIBUTES`-padded
  attribute vector (so all attributes are bound, not just the first two).
- `holderBindingKey_i` — the holder's secret signing key for this credential.
- `randomness_i` — issuer-chosen 32 bytes of fresh entropy *per leaf*. Two leaves carrying
  identical attribute vectors and the same holder still differ.

`leaf_i` is the *public* commitment placed into the credential definition's Poseidon Sparse
Merkle Tree. The tree's root is committed on-chain via `RootsUpdated`.

The four secrets are delivered to the holder over an authenticated, off-chain issuance
channel. The issuer then deletes `holderBindingKey_i` and ideally `randomness_i`; storing
them lets a future issuer key compromise enable presentation forgery.

### 3.2 The presentation circuit

A holder constructs a presentation by running the SNARK prover with this layout:

| | Quantity |
|---|---|
| **Public inputs** | `rootPoseidon`, `credDefId`, `challengeHash`, `disclosure[MAX_DISCLOSED]` |
| **Private witnesses** | `credId`, `attributes[]`, `holderBindingKey`, `randomness`, `merklePath`, `pathDirections`, `issuerSignature`, `issuerPubKey` (witness-only copy of the registry-known value) |

The circuit constrains:

1. The leaf is correctly formed from the witnessed secrets (the `Poseidon(Poseidon(...),
   Poseidon(...))` construction in §3.1).
2. `MerkleVerify(leaf, merklePath, pathDirections) == rootPoseidon`.
3. `EdDSAVerify(issuerPubKey, Poseidon(credId, attrHash), issuerSignature) == valid`.
4. For each disclosed index *k*, the prover-supplied `disclosure[k]` is constrained equal to
   the corresponding `attributes[idx_k]` via copy-constraints; unused disclosure slots are
   constrained to constant zero.
5. The verifier's `challengeHash` is replayed: `challengeHash == Poseidon(verifierNonce,
   sessionContext)`. The holder absorbs the nonce; the circuit binds the resulting proof to
   that specific session.

`rootPoseidon` is checked off the recent-roots sliding window inside `MerkleStateRegistry`
(also documented in the existing audit notes): a presentation against a freshly-revoked tree
is rejected after the window slides past.

### 3.3 Why each correlation axis is closed

- **(A) Presentation–presentation.** The SNARK is zero-knowledge: the proof bytes are
  statistically independent of the witnesses, and Groth16/PLONK proofs incorporate fresh
  randomness during proving so two proofs over the same witness are themselves distinct
  random-looking byte strings. The public inputs do not include the credId, the leaf, the
  holder key, or the Merkle path, so there is nothing constant to fingerprint across
  presentations.
- **(B) Verifier–verifier.** Verifiers see only the proof + the holder's chosen disclosures +
  their own challenge. Two verifiers cannot link presentations because no shared identifier
  crosses both sessions. (They *can* link via disclosed attributes if those attributes are
  themselves identifying — that is a disclosure-policy issue, not a protocol issue, and it is
  out of scope per §2.2.)
- **(C) Issuer ↔ presentation.** The issuer published the tree but does not appear in the
  presentation flow. If the issuer is not the relying party, they observe no presentation
  packets at all. If they are *also* a relying party they see no more than any other verifier.
  Critically, there is no nullifier or per-credId on-chain footprint at presentation time —
  the consumeOneTime style of Tier 1, which emits a per-leaf event, does *not* apply here.
- **(D) Chain observer ↔ holder.** Off-chain presentations leave no chain footprint at all.
  When a presentation is verified on-chain (a credential-gated contract action), the
  observer sees only the proof bytes and the public inputs (`rootPoseidon`, `credDefId`,
  `challengeHash`, disclosed attributes). None of those identify the credId, the holder key,
  or the leaf. A holder who wants the on-chain transaction's `msg.sender` to also be
  unlinked from their wallet can relay through a meta-tx relayer; the protocol does not bind
  `msg.sender` to the credential.

### 3.4 What the `challengeHash` buys (and does not)

Including `challengeHash = Poseidon(verifierNonce, sessionContext)` as a public input and
constraining the same value inside the circuit makes a proof unusable in any session whose
challenge differs. This is *replay locality*: a curious verifier cannot record holder H's
proof and replay it to a different verifier.

It does **not**:

- Prevent the same holder from making many presentations to many verifiers; that is the
  whole point of Tier 2.
- Provide on-chain rate limiting; if a deployment needs that, it should layer a per-session
  nullifier on top — at the cost of correlatability inside that session's scope only.
- Identify the holder; the holder's identity is never an input.

### 3.5 What randomness in the leaf buys

The `randomness_i` factor in the leaf commitment (V-04 in the audit notes) ensures that two
credentials carrying *identical* attributes and *identical* holder binding keys still have
distinct leaves, distinct Merkle paths, and distinct attributesHash inputs to the issuer
signature. This makes static analysis of the tree (e.g. by an issuer who issued the same
attributes to multiple holders) unable to deduce that two leaves belong to the same person.

It is *not* per-presentation freshness — that comes from the SNARK's prover randomness
(§3.3 axis A).

### 3.6 Domain separation

Cross-tier and within-tier domain separation:

- **Tier 1 leaves** are computed as `keccak256(bytes.concat(keccak256(abi.encode(credId))))`
  per the OZ StandardMerkleTree convention. This double-keccak domain-separates leaves from
  the internal nodes of the Tier 1 tree, killing the "present an internal node as a leaf"
  attack class (P-01 in the audit notes).
- **Tier 2 leaves** are Poseidon commitments per §3.1; they live in a different tree (the
  Poseidon SMT). The two tier surfaces share storage in `MerkleStateRegistry` but are *never*
  collapsed; a leaf is meaningful only against the root of the tree it was built for.
- **In-circuit hashes** are tagged structurally — `Poseidon(credId, attrHash)` for the
  signing message, `Poseidon(R, pubkey, msg)` for the EdDSA challenge, `Poseidon(left,
  right)` for Merkle levels. These shapes are not interchangeable, so a value from one
  domain cannot be reused as if it came from another.

---

## 4. What we explicitly do *not* promise

Stating these as bullets keeps reviewers from inferring a property that is not actually
there.

- **We do not promise rate limiting.** A holder can present the same credential to the same
  verifier ten times without on-chain detection. If a deployment needs single-use semantics
  it must layer a nullifier on top, accepting the in-session linkability that creates.
- **We do not promise forward unlinkability against issuer-key compromise *before*
  issuance.** Anyone who knew `randomness_i` and `holderBindingKey_i` at issuance time and
  retains them can later reconstruct the leaf and link it to a presentation if they also
  observe the presentation's disclosures. The issuer should delete these immediately.
- **We do not promise unlinkability of off-band identifiers.** Disclosed attributes that are
  themselves identifying (full name, full DOB, government ID number) defeat ZK trivially;
  that is a policy concern, not a protocol concern.
- **We do not currently promise an audited working verifier.** The chip composition is
  designed correctly; the EdDSA chip is *fail-closed* (returns `Unimplemented`) and the
  Halo2 verifier contract refuses every proof. No real proof has been generated or verified
  end-to-end yet. See §6.
- **We do not promise quantum resistance.** Both backend choices (Halo2-KZG/BLS12-381 and
  Groth16/BN254) are pre-quantum. Long-lived credentials should plan for re-issuance under a
  PQ-secure construction when one is selected.

---

## 5. Comparison to other approaches

A short, non-marketing comparison. Each row notes where we stand and where the other approach
makes a different design choice.

| Approach | Unlinkability stance | How Kanon differs |
|---|---|---|
| **AnonCreds (Indy)** | CL signatures + cryptographic accumulator. Unlinkable across presentations; accumulator-based revocation. | Same unlinkability target; we use a Poseidon SMT + EdDSA inside a SNARK rather than CL+accumulator. Maps more cleanly onto Solidity verification and EVM tooling, at the cost of needing a SNARK trusted setup or transparent-setup backend. |
| **BBS+ / VCDM 2.0 cryptosuite** | Unlinkable selective-disclosure signatures. The signature itself supports disclosure without ZK at the credential level. | BBS+ is presented as a credential-level signature. Kanon's leaves are bound by EdDSA inside a SNARK and the SMT membership gives on-chain revocation. The two can interoperate at the VC level. |
| **Semaphore / Tornado-style nullifiers** | Each presentation emits a per-action nullifier; identity is unlinkable but actions in the same identity context are *linkable through the nullifier*. | We do not include a per-credential nullifier in Tier 2 (we do in Tier 1, where it is the point). Re-presentation is not protocol-detected; verifiers wanting at-most-once semantics layer their own session nullifier. |
| **Bitstring status list** | Revocation status is fetched from a public list; correlated by index. | We use SMT root rotation. Revocation does not require revealing a per-credential index; the recent-roots window controls revocation latency without leaking which leaf was removed. |
| **`did:ethr` events-only** | No protocol unlinkability; identity is the EOA. | Kanon disentangles holder address from credential by design; the holder's address is not bound to a presentation unless the deployment chooses to do so. |

---

## 6. Open design questions

- **Should we add a per-session nullifier hook?** Useful for deployments that need
  at-most-once semantics inside a session without sacrificing cross-session unlinkability.
  Could be a circuit option (`emitNullifier = true|false`) gated per credDef.
- **Should the holder address be bindable optionally?** Some regulated flows (KYC + on-chain
  action together) want the proof to commit to a specific recipient address. This is a
  trivial circuit addition (one extra public input + one constraint) but it should be off by
  default and clearly labelled when on.
- **Selective disclosure with predicates.** Current disclosure is value-equality only. Range
  proofs (`age >= 18`) require additional chips.
- **Backend choice.** The repo documents Halo2-KZG; the most recent decision in chat was to
  switch to Circom+Groth16 for implementability. Mechanism descriptions in §3 are
  backend-agnostic, but the §6 status items name the Halo2 toolchain. When the backend
  decision is finalized, this document and the audit notes should be updated to agree.

---

## 8. Quick reference — what each public input does for privacy

| Public input | Why it's public | Why it does not break unlinkability |
|---|---|---|
| `rootPoseidon` | Verifier must know the tree we are proving membership against. | Roots roll forward per epoch; the root is not credential-specific, only credDef-specific. |
| `credDefId` | Verifier must know which credential definition the presentation is against. | A credDefId is shared across all holders of that credential; it is a population, not an individual. |
| `challengeHash` | Binds the proof to one verifier session, defeating replay. | Computed from a verifier nonce; carries no holder-specific entropy. |
| `disclosure[k]` | The holder chose to reveal this attribute value. | Anything the holder did not list is hidden; unused positions are constrained to zero. |

| Private witness | Why it's hidden | Consequence if it leaked |
|---|---|---|
| `credId` | Identifies the credential uniquely. | An attacker could pose as the holder. |
| `attributes[]` | May identify the holder. | Loss of selective-disclosure privacy for that holder. |
| `holderBindingKey` | Identifies the holder across presentations of this credential. | Holder impersonation. |
| `randomness` | Distinguishes otherwise-identical credentials. | An attacker who knows it can recompute the leaf and link presentations. |
| `merklePath`, `pathDirections` | Reveal the leaf's position in the tree → identify the credential. | Per-credential linkability via tree index. |
| `issuerSignature` | Could carry low-bits structure linking back to the issuance event. | Issuance-to-presentation linkage. |

---

## 9. Glossary

- **Unlinkable.** Two presentations cannot be tied to the same holder *via the protocol*.
- **Selective disclosure.** The holder reveals chosen attributes; everything else is hidden.
- **Bearer credential.** A credential whose secret material is the credential. Tier 1.
- **Nullifier.** A value that, once seen, prevents the same credential from being spent
  again. Used in Tier 1; deliberately not used in Tier 2 by default.
- **Recent-roots window.** A 16-epoch sliding window of Merkle roots that the chain accepts
  as "recent enough." Lets revocation propagate without bricking honest holders mid-flight.
- **Challenge hash.** Per-session value supplied by the verifier and absorbed into the proof
  so it can't be replayed to a different verifier.

---

Document owner: protocol team. Update when the SNARK backend choice is finalized, when the
EdDSA chip ships, or when any of the public-input or witness layouts change.
