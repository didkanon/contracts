# kanonv2

W3C-compliant Self-Sovereign Identity protocol on any EVM chain. Ships UUPS-upgradeable registries for organizations, DIDs, schemas, credential definitions, Merkle state, and a Halo2 verifier registry, with two credential-gating tiers: a Tier-1 (one-time-use, cheap on-chain Merkle proof) flow and a Tier-2 (Groth16 SNARK over BN254) flow for unlinkable presentations.

## Quick start

```
npm install
npx hardhat compile
npx hardhat test
```

Deploy to a local Besu chain:

```
export ROOT_ADMIN=<your-multisig-or-EOA-address>
npx hardhat run scripts/deploy.ts --network besu-local
npx hardhat run scripts/seed-dev-data.ts --network besu-local
```

## Architecture overview

```
RootGovernance (single EOA in dev; Safe multisig in prod)
    │
    ├── OrganizationRegistry (UUPS)
    │     ─ approveOrg / suspendOrg by GOVERNANCE_ROLE
    │     ─ addMember / removeMember by per-org admin
    │
    ├── DIDRegistry (UUPS)
    │     ─ W3C DID Core 1.0 documents
    │     ─ User DIDs cryptographically bound to msg.sender via salted keccak
    │     ─ Org DIDs gated on approved-org membership
    │
    ├── SchemaRegistry (UUPS)
    │     ─ Only approved-and-active org members can register
    │
    ├── CredentialDefinitionRegistry (UUPS)
    │     ─ Binds schema → issuer pubkey → policy tier mask
    │
    ├── MerkleStateRegistry (UUPS)
    │     ─ dual keccak/Poseidon roots per credDef
    │     ─ Tier 1 consumeOneTime (nullifier-tracked)
    │     ─ Tier 2 verifyZKMembership (delegates to injected Halo2 verifier)
    │     ─ ReentrancyGuardTransient (EIP-1153)
    │     ─ 16-epoch recent-roots sliding window
    │
    └── Halo2VerifierRegistry (UUPS)
          ─ Indexes deployed Halo2-KZG verifier contracts by circuit version
```

All registries:

- UUPS proxies (EIP-1822) — proxy addresses are immutable, implementations swappable by `UPGRADER_ROLE`
- ERC-7201 namespaced storage — upgrade-safe; storage gaps reserved for future fields
- OpenZeppelin AccessControl — roles can be granted to a Safe multisig at any time
- OpenZeppelin Pausable — emergency stop on each registry independently
- Constructor disables initializers; only the proxy invokes `initialize()`

## Two-tier credential gating

| | Tier 1 (one-time-use) | Tier 2 (Groth16 SNARK) |
|---|---|---|
| Hash function | keccak256 (EVM native) | Poseidon over BN254 Fr (SNARK-friendly) |
| Tree depth | 24 (16M slots) | 24 |
| Reveals credId? | Yes per use, but each is burn-after-use | No |
| On-chain verify gas | ~20–30k | ~300–400k |
| Off-chain verify gas | n/a | 0 (verifier runs locally) |
| Per-presentation correlation | None — each credId is single-use | None — fresh randomness per proof |

Holders use Tier 1 when their wallet address is already public (typical on-chain contract gating); Tier 2 when they need cryptographic unlinkability (off-chain presentations to relying parties, anonymous voting, etc.).

## File layout

```
kanonv2/
  contracts/                      Solidity sources
    interfaces/                   Pure interfaces (one per registry + IHalo2Verifier)
    orgs/                         OrganizationRegistry
    did/                          DIDRegistry
    schemas/                      SchemaRegistry
    creddefs/                     CredentialDefinitionRegistry
    state/                        MerkleStateRegistry + MerkleProofLib
    verifiers/                    Halo2VerifierRegistry + Groth16Verifier
    test/mocks/                   MockHalo2Verifier + MockGatedContract
  test/                           Hardhat + chai test suite
    helpers/                      shared fixtures + canonical Merkle tree
    integration/                  end-to-end lifecycle tests
  scripts/                        deploy.ts, seed-dev-data.ts
  circom/                         Groth16 circuit (non_revocation.circom) + ceremony scripts
  sdk/                            TypeScript SDK monorepo
  docs/                           SECURITY.md, UPGRADE-GUIDE.md, OPERATIONS.md
  hardhat.config.ts
  package.json
```

## Documentation

- [SECURITY.md](docs/SECURITY.md) — threat model and security checklist
- [UPGRADE-GUIDE.md](docs/UPGRADE-GUIDE.md) — UUPS upgrade procedure with rollback drills
- [OPERATIONS.md](docs/OPERATIONS.md) — operational runbook
- [CEREMONY.md](docs/CEREMONY.md) — Groth16 powers-of-tau ceremony procedure
- [ZK-UNLINKABILITY-MODEL.md](docs/ZK-UNLINKABILITY-MODEL.md) — unlinkability model

## License

Apache-2.0.
