# Deploy runbook — kanonv2 on `besu.ajna.inc`

Step-by-step playbook for landing the seven kanonv2 registries (plus the
Mode B Groth16 verifier) on the Ajna Inc Besu network. Designed to be
followed line-by-line; nothing here is implicit.

---

## 0 · Preconditions

| Check | How |
|---|---|
| Chain is reachable | `curl -s https://besu.ajna.inc -H 'content-type: application/json' --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'` — must return `0x79b` (1947) or a known override |
| You have a funded deployer EOA | Will spend ~0 gas (consortium chain, gasPrice=0); still needs to exist on chain. The genesis allocates accounts — confirm yours is one |
| Local working tree clean | `git status` shows no diff that affects contracts or scripts |
| Ceremony output committed | `contracts/verifiers/Groth16Verifier.sol` and `circom/build/nr_final.zkey` must reflect the production ceremony — see §3 |
| Node + pnpm install done | `cd kanonv2 && npm install` |
| Hardhat compile clean | `npx hardhat compile` |
| Test suite green | `npx hardhat test` — should print "passing" with no failures |

The hardhat config (`kanonv2/hardhat.config.ts`) already declares `besu-ajna` as a network.
You supply the credential at deploy time via env vars — never check the key in.

## 1 · Env vars for the deploy session

```bash
# Required for write commands
export BESU_AJNA_DEPLOYER_KEY=0x…                          # secp256k1 private key, 0x-prefixed
# Optional overrides (defaults in parentheses)
export BESU_AJNA_RPC_URL=https://besu.ajna.inc             # default already set
export BESU_AJNA_CHAIN_ID=1947                             # default 1947
export ROOT_ADMIN=0x…                                      # if set, root admin role goes here instead of the deployer
```

The `ROOT_ADMIN` is who can pause, upgrade, and grant org-governance roles. For
production this should be a Safe multisig — see `scripts/deploy-production.ts` for
the Safe-backed variant. For initial bring-up it can be the deployer.

## 2 · Sanity check the connection BEFORE you spend gas

```bash
cd kanonv2
npx hardhat console --network besu-ajna
> const [d] = await ethers.getSigners(); console.log(await d.getAddress());
> console.log(Number((await ethers.provider.getNetwork()).chainId));
> console.log(ethers.formatEther(await ethers.provider.getBalance(await d.getAddress())));
```

Verify (a) the deployer address matches what you expect and (b) chainId is what
genesis says. Gas balance only matters if the chain charges; consortium Besu at
gasPrice=0 doesn't.

## 3 · ⚠️ Ceremony state — read before deploying Mode B

The transcript currently committed (`circom/build/ceremony/transcript.txt`) was
produced with **scripted entropy and the placeholder beacon
`0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`**. That makes
the setup cryptographically sound but trust-wise **dev-only** — the soundness
argument requires at least one honest contributor on an isolated machine, and
the published transcript doesn't demonstrate that for this run.

Three options for Mode B:

- **A. Defer Mode B** — deploy only the seven core registries; skip §5 below. Mode A
  (AnonCreds VDR with `AnonCredsStatusRegistry`) works without any ceremony at all.
- **B. Reuse Hermez phase-1 + run phase-2 with real contributors** (recommended for
  shipping Mode B). See `circom/scripts/ceremony.sh` for the contributor flow and
  `docs/CEREMONY.md` §"Production ceremony" option A.
- **C. Ship the dev zkey for testnet** — fine for besu-ajna *if it is a testnet*.
  The deployed verifier is cryptographically real; the trust caveat just means an
  attacker who could replicate the scripted entropy could forge proofs. For an
  internal testbed this is acceptable; for any externally-facing claim it is not.

Whichever you pick, document it in the commit message that ships the deployment
record.

## 4 · Deploy the seven core registries

```bash
npx hardhat run scripts/deploy.ts --network besu-ajna
```

What this does, in order:

1. `OrganizationRegistry` (UUPS proxy, root admin = `ROOT_ADMIN || deployer`)
2. `DIDRegistry`
3. `SchemaRegistry`
4. `CredentialDefinitionRegistry`
5. `MerkleStateRegistry`
6. `Halo2VerifierRegistry`
7. `AnonCredsStatusRegistry`
8. Wires `MerkleStateRegistry.initializeV2(verifierRegistry)` so Tier-2 calls work.
   This is auto-run only if `ROOT_ADMIN === deployer`; otherwise the script prints
   the call you must make manually from the admin signer.

Output: `kanonv2/deployments/1947.json` with `addresses` for all 7 proxies and
their implementation addresses.

Verify everything landed:

```bash
cat deployments/1947.json | jq .addresses
```

## 5 · Wire Mode B (only if you chose option B or C above)

```bash
npx hardhat run scripts/deploy-verifier-and-wire.ts --network besu-ajna
```

This deploys two more contracts and registers the adapter:

1. `Groth16Verifier` — the raw snarkjs-generated verifier (uses BN254 precompiles
   `0x06/0x07/0x08` — universal across EVM chains, does not need EIP-2537).
2. `Groth16NonRevocationVerifier(groth16Address)` — the `IHalo2Verifier`-shaped
   adapter the registry accepts.
3. `Halo2VerifierRegistry.registerVerifier(adapter)`.

After this, **each credential definition that wants Mode B** must opt in:

```ts
await merkleStateRegistry.setZkVerifier(credDefId, adapter.address);
```

That call is per-credDef and is normally driven by the SDK (`KanonClient`) or by
the issuer org's onboarding script.

## 6 · Seed a smoke-test org + schema (optional but useful)

```bash
npx hardhat run scripts/seed-dev-data.ts --network besu-ajna
```

Confirms the contracts respond correctly under the deployer's signer. Skip in a
clean prod deploy where you'll bootstrap via the governance Safe.

## 7 · Hand-off

| Artefact | Where it lives | Who consumes |
|---|---|---|
| `deployments/1947.json` | repo, committed | `@ajna-inc/kanon-sdk` (`loadDeployment`), `@ajna-inc/kanon` Credo plugin, `did_kanon` Python plugin |
| `Groth16Verifier.sol` + `non_revocation_vk.json` | repo, committed | clients running off-chain verify |
| `nr_final.zkey` | check whether you publish (see CEREMONY.md) | holders generating Mode B proofs |
| `RootAdmin` private key | rotate to the Safe multisig if you bootstrapped with the deployer | governance signer |

Update the consumer side:

- **Credo plugin** (`@ajna-inc/kanon`): set
  `anonCredsStatusRegistryAddress` to `deployments/1947.json.addresses.AnonCredsStatusRegistry`
  in the plugin config of every agent.
- **Python plugin** (`did_kanon`): wire the new addresses into the
  `KANON_ANONCREDS_STATUS_REGISTRY_ADDRESS` env var (or `--plugin-config` YAML).

## 8 · Verify Mode A works end-to-end

```bash
# Status read on a fresh credDef should return 0 (Unknown)
npx hardhat console --network besu-ajna
> const reg = await ethers.getContractAt("AnonCredsStatusRegistry", "<addr>");
> await reg.getStatus(ethers.id("test-credDef"), ethers.id("test-credId"));
0n
```

A 0n response without revert means the contract is wired correctly. To check a
real round-trip, run an issuer flow from the SDK or the Credo plugin and watch
for the `CredentialIssued` event.

## 9 · Roll back (if needed)

UUPS proxies cannot be deleted but their implementation can be replaced via
`upgradeTo` from the `UPGRADER_ROLE`. To pause everything:

```ts
await orgRegistry.pause();
await didRegistry.pause();
await schemaRegistry.pause();
await credDefRegistry.pause();
await merkleStateRegistry.pause();
await halo2VerifierRegistry.pause();
await anonCredsStatusRegistry.pause();
```

These calls go through the `PAUSER_ROLE` and are gated by AccessControl.

---

## Key handover protocol (for the user supplying `BESU_AJNA_DEPLOYER_KEY`)

When you're ready to hand off the deployer key:

1. **Generate** the key on an air-gapped or otherwise trusted machine.
2. **Confirm** it has not been used previously (`eth_getTransactionCount` returns 0)
   and is allocated in the network genesis (`curl … eth_getBalance`).
3. **Set** the env var `BESU_AJNA_DEPLOYER_KEY=0x…` in the deploy shell ONLY —
   not in a `.env` file checked into git, not in CI variables for any branch other
   than the deploy branch.
4. **Run** §4 through §7 of this runbook in one shell session.
5. **Rotate** by calling `grantRole(DEFAULT_ADMIN_ROLE, <safeAddress>)` then
   `renounceRole(DEFAULT_ADMIN_ROLE, deployer)` on every registry from the
   deployer signer. After that the deployer key cannot pause/upgrade anything —
   it becomes a regular EOA.
