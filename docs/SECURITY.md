# Security

## Threat model

### Trusted roles

| Role | Capability | Implied trust |
|---|---|---|
| `DEFAULT_ADMIN_ROLE` (root) | Grant/revoke other roles; upgrade implementations | Must be a Safe multisig in prod |
| `GOVERNANCE_ROLE` | Approve, suspend, reactivate organizations | Single signer OK for dev; multisig for prod |
| `UPGRADER_ROLE` | Trigger UUPS upgrades on a specific registry | Held by root admin; can be separated for two-key control |
| `PAUSER_ROLE` | Pause/unpause individual registries | Held by root + SOC team |
| `CONFIG_ROLE` | Swap dependency-registry addresses (e.g., point DIDRegistry at a new OrgRegistry) | Held by root |
| Per-org admin | Add/remove org members, rotate org admin | Trusted at the org level only |
| Per-org member | Publish schemas, register credential definitions, sign credentials, update Merkle state | Trusted within the org |

### Adversary capabilities considered

- Anonymous attackers attempting to register DIDs for someone else
- Anonymous attackers attempting to register schemas / credDefs for non-approved orgs
- Compromised org member attempting to publish schemas as a different org
- Replay / double-spend attempts on Tier 1 one-time-use credentials
- Stale-root attacks (presenting against a root that's outside the recent-roots window)
- Attempts to call privileged functions through reentrancy
- Attempts to bypass `_authorizeUpgrade` via delegatecall
- Storage-collision attacks across UUPS upgrades

### Out of scope

- Compromise of the holder's private signing key (use HSM / secure enclave)
- Compromise of an issuer org's signing key (rotate keys, use HSM)
- Compromise of the RootGovernance multisig (use proper multisig hygiene)
- Off-chain DID resolution misuse (verifiers MUST validate JSON-LD against on-chain `schemaHash`)
- Front-running risks for the calldata-revealed credId (use a relayer / paymaster if it matters)

## Security checklist enforced in code

| Concern | Mitigation |
|---|---|
| Uninitialized implementations | `_disableInitializers()` in every implementation constructor |
| Storage collisions on upgrade | ERC-7201 namespaced slots; 50-slot gaps; OZ upgrades plugin checks in CI |
| Reentrancy on `consumeOneTime` | `ReentrancyGuardTransient` (EIP-1153) + checks-effects-interactions (nullifier set before any external call) |
| Double-spend of one-time credentials | Per-credDef nullifier mapping; `NullifierAlreadyUsed` revert |
| Stale root acceptance | 16-epoch sliding window in `recentKeccakRoots` / `recentPoseidonRoots` |
| Unbounded loops | `MAX_VERIFICATION_METHODS=16`, `MAX_SERVICES=16`, `MAX_RELATIONSHIP_REFS=16`, `MAX_BATCH_SIZE=256`, `MAX_ISSUER_PUBKEY_LENGTH=256` |
| Pause bypass | All write functions on every registry use `whenNotPaused` |
| Unauthorized upgrades | `_authorizeUpgrade` requires `UPGRADER_ROLE` |
| Role-bypass via direct impl call | `onlyProxy` enforced via UUPSUpgradeable's notDelegated checks |
| DID hijacking | User-DID handle must equal `keccak256("did:kanon:user:" || msg.sender || salt)` |
| Org-DID hijacking | Caller must be approved-org member; org must be active |
| Cross-org schema spoofing | `registerCredentialDefinition` checks caller is member of `schema.issuerOrg` |
| Empty-call/EOA-as-verifier | `setZkVerifier` calls `circuitVersion()` via `try/catch` to require contract conformance |
| Zero-address inputs | Explicit reverts on every external input that uses an address |
| Validator-array references | `_validateDocumentShape` checks every authentication / assertionMethod / etc. ref resolves to a declared verification method id |

## Known limitations

1. **Tier 1 credIds are public on-chain.** Each is single-use, but the credId itself appears in calldata. Holders requiring full unlinkability should use Tier 2.
2. **ZK verifier wiring is per credDef.** `MerkleStateRegistry.verifyZKMembership` returns `false` until an admin wires a registered verifier for that credDef via `setZkVerifier`. The Groth16 verifier contract for the non-revocation circuit ships with the contracts; an operator step picks it up.
3. **Holder Merkle path replication** happens off-chain by replaying chain events. Holders running ahead of a `RootsUpdated` event will get a stale path; the 16-epoch recent-roots window absorbs this lag for ~30 minutes at 2-second block times.
4. **No on-chain timelock on upgrades.** Adding one is straightforward via OZ `TimelockController` once the root admin moves to a multisig.

## Responsible disclosure

Report vulnerabilities privately to security@kanon.example (replace with real contact before production). Do not file public GitHub issues for security findings.

Severity guideline:

- **Critical**: any path that lets a non-controller alter a DID, lets a non-issuer-member mint or revoke credentials, lets an unauthorized address upgrade an implementation, or bypasses the nullifier check.
- **High**: any path that lets one org publish or modify another org's schemas / credDefs / Merkle state.
- **Medium**: any griefing path (e.g., unbounded gas, DOS via state pollution) or paths that violate the privacy properties documented in `README.md`.
- **Low**: bypasses of pause; gas anomalies that don't compromise correctness.

We will acknowledge within 72 hours and publish a fix coordination timeline.

## Dependencies and their audit status

- OpenZeppelin Contracts + Contracts-Upgradeable v5.6.1 — multiple audits
- `@zk-kit/imt.sol` v2.0.0-beta.12 — PSE + ABDK audits
- All cryptography (Merkle proof, Reentrancy, AccessControl, UUPS, Pausable) inherited from OZ
- Our original code: glue and lifecycle logic. We do not implement primitives.
