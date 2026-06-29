# kanonv2 Operations Runbook

Covers monitoring, alerting, incident response, and key custody for a production kanonv2 deployment.

---

## 1. Monitoring

### 1.1 Event-based metrics (Prometheus / BlockScout indexer)

Every state-changing function emits an event. The recommended scrape configuration tracks each event as a counter, with breakdowns by indexed topic.

```yaml
# prometheus.yml — kanonv2 scrape targets
scrape_configs:
  - job_name: kanonv2-events
    metrics_path: /metrics
    static_configs:
      - targets: ["kanonv2-event-exporter:9101"]

  - job_name: kanonv2-besu-rpc
    metrics_path: /metrics
    static_configs:
      - targets: ["besu-rpc-internal:9545"]
```

### 1.2 Key metrics

| Metric | Source | Alert if |
|---|---|---|
| `kanon_org_registered_total` | `OrgRegistered` event | sudden spike → flooding |
| `kanon_org_approvals_total` | `OrgApproved` event | unexpected non-timelock approval |
| `kanon_did_registered_total{scope=user\|org}` | `DIDRegistered` event | per-org rate exceeds policy |
| `kanon_schema_registered_total{orgId}` | `SchemaRegistered` event | new org publishes > 100/day |
| `kanon_credential_added_total{credDefId}` | `CredentialAdded` event | issuance volume baseline |
| `kanon_credential_revoked_total{credDefId}` | `CredentialRevoked` event | spike → possible compromise |
| `kanon_onetime_consumed_total{credDefId}` | `OneTimeConsumed` event | sustained > 100/s = capacity warning |
| `kanon_roots_updated_total{credDefId}` | `RootsUpdated` event | infrequent → frozen issuer; frequent → churn |
| `kanon_zk_verifier_set_total{credDefId}` | `ZkVerifierSet` event | any non-timelock origin = incident |
| `kanon_upgrade_total{contract}` | `Upgraded` event (UUPS) | every event = paging signal |
| `besu_block_height` | Besu Prometheus | chain stall |
| `besu_peers_connected_total` | Besu Prometheus | partition |
| `besu_qbft_round_changes_total` | Besu Prometheus | consensus failure |

### 1.3 Grafana dashboards

Spec follows (dashboard JSON to be provided in `docs/grafana/`):

- **Overview** — one chart per contract: write count, gas-per-tx, p95 latency
- **Org lifecycle** — orgs in each state (pending / active / suspended), top-10 issuance volume
- **Credential issuance / revocation** — added vs. revoked counts per credDef, root-update cadence
- **Upgrade audit log** — every `Upgraded` event timestamped with the new implementation address
- **Multisig activity** — every timelock schedule / execute call, surfaced with target contract + decoded calldata

### 1.4 Alerting rules

| Alert | Trigger | Severity | Action |
|---|---|---|---|
| ZkVerifierSet by non-timelock | `ZkVerifierSet` with `tx.from != timelock` | Critical | Pause registry, page on-call |
| Unexpected Upgraded event | Any `Upgraded` without matching scheduled timelock op | Critical | Pause, page security |
| Issuance volume anomaly | `rate(CredentialAdded[5m]) > 10x baseline` | High | Investigate org; consider rate limit |
| Revocation volume anomaly | `rate(CredentialRevoked[5m]) > 50x baseline` | High | Investigate org; possible key compromise |
| Block production stalled | `rate(besu_block_height[1m]) == 0` | Critical | QBFT consensus failure; investigate validators |
| `OneTimeConsumed` rate sustained | > 25/sec for 5 minutes | Medium | Capacity warning; consider block gas limit bump |
| Pause event | Any registry's `Paused` event | High | Verify it was an intended pause |

---

## 2. Key custody

### 2.1 Root admin (RootGovernance multisig)

- **Required hardware:** Hardware wallets (Ledger Nano X+ or Keystone) for every multisig signer
- **Threshold:** 4-of-7 (or similar; aligned with Safe industry norm)
- **Geographic distribution:** Signers in at least 3 timezones; no two co-located
- **Annual rotation:** Replace ≥ 1 signer per year for resilience against long-term compromise
- **Drill cadence:** Quarterly schedule-execute drill on a staging chain

### 2.2 Issuer keys (BLS12-381 EdDSA)

The issuer signs credentials with a BLS12-381 G2 key. Production custody options:

#### Option A — HSM (recommended for high-volume issuers)

- **Hardware:** YubiHSM 2, AWS CloudHSM (with custom BLS plugin), or Securosys Primus
- **Algorithm support:** Custom — most HSMs lack native BLS support; load BLS as a "raw EC" key
- **Quorum:** M-of-N with signing officers from different roles (engineer + compliance)
- **Audit logging:** Every signature operation logged with caller identity

#### Option B — Cloud KMS with sidecar (acceptable for mid-volume)

- **Architecture:** AWS KMS holds an Ed25519 wrapping key; BLS private key encrypted at rest, decrypted on the sidecar issuer service for signing
- **Trust assumption:** AWS KMS access policy + IAM roles + KMS key policy
- **Audit:** AWS CloudTrail logs every decrypt operation

#### Option C — Encrypted file with passphrase (dev/testing only)

- DO NOT use in production

### 2.3 Holder binding keys

- **Wallet:** mobile secure enclave (iOS Secure Enclave, Android StrongBox), browser WebAuthn-backed key derivation, or a hardware token (Yubikey)
- **Backup:** never write raw private keys to disk in plaintext. Use a passphrase-derived encryption scheme (Argon2id + ChaCha20Poly1305).
- **Loss recovery:** the holder loses ALL credentials in their pool if they lose the binding key. The issuer must re-issue. Holders should be educated to back up their seed phrase / passphrase.

---

## 3. Incident response

### 3.1 Severity matrix

| Severity | Description | Response time | Pager |
|---|---|---|---|
| **P0** | Unauthorized upgrade, root admin compromise, mass-issuance attack | < 15 min | All on-call + security lead + CEO |
| **P1** | Issuer key compromise, individual contract pause needed | < 1 hr | Security on-call + relevant team lead |
| **P2** | Member-level role compromise within a single org | < 4 hr | Security on-call |
| **P3** | Anomalous metric (volume, error rate) under investigation | < 1 day | On-call rotation |

### 3.2 Playbooks

#### 3.2.1 Root admin key compromise

```
1. (Within minutes) Safe signers issue an emergency PauseAll proposal.
2. Wait for timelock minDelay to elapse OR if there's no time, accept the loss
   of that period and move to step 3.
3. Once paused, the compromise vector is contained. No upgrades possible.
4. Deploy a new Safe multisig with fresh keys.
5. Schedule a `grantRole(DEFAULT_ADMIN_ROLE, newSafe)` followed by
   `revokeRole(DEFAULT_ADMIN_ROLE, oldSafe)` through the timelock.
6. Once delay passes, execute. Unpause.
7. Public post-mortem within 30 days.
```

#### 3.2.2 Issuer key compromise

```
1. Identify the compromised credDef via metric anomalies.
2. Org admin calls `MerkleStateRegistry.batchUpdate` to revoke ALL outstanding
   credentials issued by the compromised key (single tx if batch size ≤ 256;
   chained calls otherwise).
3. After 16 epochs (~30 min at 2-sec block times), stale presentations are
   automatically rejected because the old root falls out of the recent window.
4. Generate a fresh issuer key pair.
5. Deploy a new credDef pointing at the new pubkey (cannot mutate existing
   credDef.issuerPubKey).
6. Migrate holders to the new credDef (out-of-band notification + re-issuance).
```

#### 3.2.3 ZK verifier soundness bug

If a vulnerability in the Halo2 circuit allows forging proofs:

```
1. (P0) Pause MerkleStateRegistry across affected credDefs.
2. Tier 1 (one-time-use) continues to work; Tier 2 is suspended.
3. Develop and audit the fix in the Rust circuit.
4. Re-run trusted setup if the circuit shape changes (rare; usually a parameter
   tweak doesn't change the setup).
5. Deploy new Halo2VerifierV2 contract.
6. Per-credDef migration: `MerkleStateRegistry.setZkVerifier(credDefId, v2addr)`
   via the timelock.
7. Unpause.
```

#### 3.2.4 Chain stall (QBFT consensus failure)

```
1. Check validator pod logs for QBFT round-change events.
2. Confirm ≥ 3 of 4 validators are healthy (BFT-1 threshold).
3. If a validator is offline, restart its pod; re-sync from peers.
4. If multiple validators have diverged on a fork:
   a. STOP all but one validator
   b. Identify the canonical chain (longest by block number AND signed by the largest validator subset)
   c. Wipe diverging validators' PVCs
   d. Restart with the canonical chain's static-nodes.json
5. Resume issuance ops after net_peerCount > 0 on all validators.
```

### 3.3 Drills

Quarterly:
- Tabletop incident on each playbook
- Rollback drill on staging chain
- Multisig signer availability test

Annually:
- Full key rotation rehearsal
- Audit of disaster recovery procedures with external reviewer

---

## 4. Backup and recovery

### 4.1 Chain backup

QBFT consensus implies the chain state is replicated across ≥ 4 validator pods. PVC snapshots:

```
# Daily snapshot of each validator's RocksDB
kubectl exec besu-validator-0 -- tar czf /tmp/backup.tar.gz /data/database
kubectl cp besu-network/besu-validator-0:/tmp/backup.tar.gz \
          s3://kanonv2-chain-backups/$(date -u +%Y-%m-%d)/validator-0.tar.gz
```

Retention: 30 days hot in S3, 365 days cold in Glacier.

### 4.2 Deployment record backup

`deployments/<chainId>.json` and `deployments/<chainId>-production.json` are git-tracked. Additionally, the auto-generated `.openzeppelin/` files (storage layouts for upgrade safety) MUST be tracked.

### 4.3 Issuer state backup

Each issuer service should persist:
- The set of active leaves (so root reconstruction is fast)
- The set of pending revocations
- The off-chain credential ↔ holder address mapping

Backup cadence: every batchUpdate is the natural snapshot point; replicate to encrypted S3 within 5 minutes.

---

## 5. Performance baselines

### 5.1 Expected per-op gas (sampled from gas report)

| Operation | Gas |
|---|---|
| `OrganizationRegistry.registerOrg` | ~85k |
| `OrganizationRegistry.approveOrg` | ~60k |
| `DIDRegistry.registerDID` (small doc) | ~150k |
| `SchemaRegistry.registerSchema` | ~140k |
| `CredentialDefinitionRegistry.registerCredentialDefinition` | ~225k |
| `MerkleStateRegistry.initializeCredDefState` | ~150k |
| `MerkleStateRegistry.batchUpdate` (no leaves) | ~110k |
| `MerkleStateRegistry.batchUpdate` (10 added, 5 revoked) | ~250k |
| `MerkleStateRegistry.consumeOneTime` | ~80k |
| `MerkleStateRegistry.setZkVerifier` | ~100k |
| `KanonTimelock.schedule` | ~75k |
| `KanonTimelock.execute` (no-op) | ~60k |

### 5.2 Throughput at 50M block gas limit

- ~625 root updates per block (no leaves) → 312/sec
- ~200 root updates with 10 issuances each → 100/sec → 1k issuances per second
- ~620 Tier-1 consumes per block → 310/sec
- 1 SNARK verify per ~10–15 blocks

### 5.3 Block gas limit recommendation

Default: 50M (set in genesis).
Bump to 100M if sustained > 75% block utilization for one week.

---

## 6. Contact + escalation

| Role | Channel | Backup |
|---|---|---|
| On-call security | pager-duty:kanon-security | Slack #kanon-incidents |
| Multisig signer (1) | signer1@example.com | +1 555 0101 |
| Multisig signer (2) | signer2@example.com | +1 555 0102 |
| External auditor liaison | auditor@example.com | — |
| Hosting provider escalation | docker-desktop / k8s admin | — |

(Replace placeholders with real channels before production.)
