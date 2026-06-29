# Trusted-setup ceremony — non_revocation (Groth16 / BN254)

Groth16 needs a per-circuit trusted setup. Its soundness rests on **at least one honest
contributor** and a **public, unpredictable final beacon**. `circom/scripts/ceremony.sh`
implements the full, verifiable ceremony; this doc covers how it works, how to reproduce it,
and what must change for production.

## What the script does

```
bash circom/scripts/ceremony.sh
```

**Phase 1 (powers of tau) is REUSED from the public Hermez Perpetual Powers of Tau** —
hundreds of independent contributors already did it; we do not run our own. The script:
1. downloads `powersOfTau28_hez_final_16.ptau` (2^16 domain) if absent, from `$PTAU_URL`
   (default `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau`).
   The circuit — `NonRevocation(depth=26, attrs=16, disclose=1)` — has ~24.3k total
   constraints (14.7k non-linear); snarkjs sizes the setup off the total count and needs 2^16
2. records its sha256 in the transcript
3. runs `powersoftau verify` → prints **"Powers Of tau file OK!"** (checks every contribution
   + the beacon cryptographically — stronger than a hash compare)

**Phase 2 (circuit-specific)** is the only part we run:
1. `groth16 setup` from the Hermez ptau + the circuit `r1cs`
2. two contributions (`phase2-contributor-1..2`)
3. a public random **beacon**
4. `zkey verify <r1cs> <ptau> <zkey>` → prints **"ZKey Ok!"** (the proving/verifying keys
   correspond to the compiled circuit and the transcript is consistent)

Outputs, installed automatically:
- `circom/build/nr_final.zkey` — proving key (used by the holder prover and the Tier-2 test)
- `contracts/verifiers/Groth16Verifier.sol` — the on-chain verifier (regenerated from the vkey)
- `contracts/verifiers/non_revocation_vk.json` — verification key
- `circom/build/ceremony/transcript.txt` — the attestation (committed): Hermez sha256, the
  `powersoftau verify` result, the phase-2 contributions + beacon, and the `zkey verify` result

The shipped verifier was produced this way: the committed `transcript.txt` shows
`Powers Of tau file OK!` (Hermez phase-1, 54 prior contributions + its beacon) and `ZKey Ok!`
(our phase-2). The Tier-2 test (`test/Tier2ZK.test.ts`) generates a real proof against this
verifier and confirms it on-chain.

### Reuse note

Because phase 1 is the public Hermez ceremony, **you do not need to gather contributors for it
— it is already done.** Phase 2 needs at least one honest contributor; that can be you alone
(generate entropy, discard it), optionally plus a few colleagues so no single party must be
trusted. You never need to recruit strangers.

## Reproduce / verify an existing zkey

```
cd circom/build
npx snarkjs powersoftau verify ptau/powersOfTau28_hez_final_16.ptau   # "Powers Of tau file OK!"
npx snarkjs zkey verify non_revocation.r1cs ptau/powersOfTau28_hez_final_16.ptau nr_final.zkey   # "ZKey Ok!"
```

The committed `ceremony/transcript.txt` records the verify results from the run that produced
the shipped verifier.

## ⚠ The committed ceremony is DEV-only

The run in CI uses scripted entropy and a fixed beacon so the build is reproducible. That makes
it **single-operator** — it is NOT production-trustworthy. The cryptography is correct and
verifiable; the *trust* is not, because all entropy came from one machine.

## Production ceremony

**One command does everything** — compile, fetch + integrity-check the public Hermez phase-1,
run phase-2 with your own entropy, seal with a real future drand beacon, install the verifier,
`hardhat compile`, and run the on-chain Tier-2 test:

```
bash circom/scripts/contribute-prod.sh
# options: BEACON=<64-hex> (supply your own beacon)  VERIFY_PTAU=1 (slow full ptau verify)  SKIP_TEST=1
```

It writes the attestation to `circom/build/prod/transcript.txt` (ptau sha256, beacon round,
verify results). Your entropy comes from `openssl rand` at run time and is discarded. For a
stronger setup where no single party is trusted, see the multi-contributor flow below.

The manual building blocks (if you'd rather run them yourself):

**A. Reuse a large public phase 1 (recommended).** Use the Hermez perpetual-powers-of-tau
file sized for the circuit (`powersOfTau28_hez_final_16.ptau`, 2^16 domain — covers the
~24.3k total constraints), verify its published hash, then run only **phase 2** with
independent contributors. The easiest path is `circom/scripts/contribute-prod.sh` (one honest
contributor + real beacon); the manual flow is:

```
# phase 1 inherited from the public Hermez ceremony (verify the hash!)
npx snarkjs groth16 setup non_revocation.r1cs powersOfTau28_hez_final_16.ptau nr_0000.zkey
# each external contributor, on their own machine:
npx snarkjs zkey contribute nr_000<i-1>.zkey nr_000<i>.zkey --name="<who>" -e="<their entropy>"
# final public beacon (real future randomness — see below):
npx snarkjs zkey beacon nr_000<N>.zkey nr_final.zkey <beaconHash> 10 -n="final beacon"
npx snarkjs zkey verify non_revocation.r1cs powersOfTau28_hez_final_16.ptau nr_final.zkey
```

**B. Run phase 1 yourself** with many independent external contributors (same flow as the
script, but contributions collected from separate parties/machines, not scripted).

### Contributor flow (independent machines)

Each contributor receives the latest `.zkey`/`.ptau`, runs one `contribute` with entropy only
they know (and ideally destroy afterward), publishes the output + the contribution hash snarkjs
prints, and passes the file to the next contributor. Anyone can later `verify` the chain. A
single honest contributor who discards their entropy makes the setup sound.

### The beacon

The final contribution must be a value that was **unpredictable** at contribution time and is
**publicly verifiable** afterward — e.g. a specific future [drand](https://drand.love) round, or
a future Bitcoin block hash. Record its provenance (round number / block height) in the
transcript. The dev `BEACON_HASH` in the script is a placeholder; replace it.

## After a production ceremony

1. Re-export and commit `Groth16Verifier.sol` + `non_revocation_vk.json` from the final zkey.
2. Deploy the new `Groth16Verifier` + `Groth16NonRevocationVerifier`, register in
   `Halo2VerifierRegistry`, and `setZkVerifier` on the affected credDefs.
3. Publish the full transcript (ptau + zkey contribution hashes, beacon provenance, verify logs)
   so verifiers can audit the setup.
4. Have the circuit + ceremony reviewed by a ZK-specialized auditor before mainnet.
