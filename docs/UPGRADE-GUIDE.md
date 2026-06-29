# Upgrade Guide

Every kanonv2 registry is a UUPS proxy. The proxy address never changes; the implementation can be swapped by an account holding `UPGRADER_ROLE`. This document covers the safe upgrade procedure and the rollback drill.

## Pre-upgrade checklist

1. ✅ Implementation contract changes compile with `npx hardhat compile` and pass full test suite
2. ✅ Storage layout is upgrade-safe (run `npx hardhat run scripts/storage-layout-check.ts`)
3. ✅ ERC-7201 namespaced storage slot for the registry is unchanged
4. ✅ Any new state variables are appended to the storage struct in the slots reserved by `__gap`
5. ✅ No existing state variable changed type, position, or removed
6. ✅ `_authorizeUpgrade` still gated by `UPGRADER_ROLE`
7. ✅ Constructor still calls `_disableInitializers()`
8. ✅ No new external constructor parameters (initialization happens once at proxy creation)
9. ✅ Pause the registry on a staging chain and rehearse the upgrade
10. ✅ Run the OZ upgrades plugin's `validateUpgrade` against current and new implementations:
    ```typescript
    import { upgrades } from "hardhat";
    await upgrades.validateUpgrade(proxyAddr, NewImplementationFactory, { kind: "uups" });
    ```

## Upgrade procedure

### From a script (testnet / dev chains)

```typescript
import { ethers, upgrades } from "hardhat";

const proxyAddr = "0x…"; // from deployments/<chainId>.json
const NewFactory = await ethers.getContractFactory("OrganizationRegistryV2");
const upgraded = await upgrades.upgradeProxy(proxyAddr, NewFactory, {
  kind: "uups",
  call: { fn: "reinitializerV2", args: [...] }, // optional, only if new initializer
});
console.log("Upgrade complete. New implementation:", await upgrades.erc1967.getImplementationAddress(proxyAddr));
```

### From a Safe multisig (production)

1. Deploy the new implementation contract (no proxy):
   ```
   npx hardhat run scripts/deploy-impl.ts --network besu-local
   ```
   Note the new implementation address.
2. Generate the `upgradeToAndCall(newImpl, initData)` calldata.
3. Open a Safe transaction with:
   - To: the proxy address
   - Value: 0
   - Data: the calldata from step 2
4. Collect signatures from multisig owners.
5. Execute the transaction.
6. Verify the upgrade landed: `await upgrades.erc1967.getImplementationAddress(proxyAddr)` matches step 1.

## Post-upgrade checks

1. Confirm state preservation by reading a known piece of pre-upgrade state and comparing.
2. Run a smoke-test transaction that exercises both old + new code paths.
3. Re-run a subset of the integration tests against the live chain.
4. Update the deployment record:
   ```
   deployments/<chainId>.json → implementations.<RegistryName>
   ```

## Rollback drill

If a regression is discovered post-upgrade:

1. Verify the previous implementation address from `deployments/<chainId>.json`.
2. Issue an `upgradeToAndCall` transaction pointing back to the previous implementation.
3. Verify the rollback landed.
4. Investigate the regression on a separate chain.

The OZ upgrades plugin enforces storage-layout compatibility on every `upgradeProxy` call, so rollback is safe by construction unless the rolled-forward version added new state — in that case, the new state survives on the old logic but isn't read, which is benign.

## Adding new state to a registry

To add a new field without breaking the storage layout:

1. In the storage struct, **append** the new field above `__gap`:
   ```solidity
   struct OrgStorage {
       mapping(uint256 => Organization) orgs;
       mapping(uint256 => mapping(address => bool)) members;
       uint256 nextOrgId;
       // ── NEW IN V2 ──
       mapping(uint256 => uint256) orgQuota;
       // ── end ──
       uint256[46] __gap; // was [47]; decrement by 1
   }
   ```
2. The OZ upgrades plugin will detect the change. Add an `@custom:oz-upgrades-from V1` annotation if needed.
3. Initialize the new field via a `reinitializerV2()` function called as part of the `upgradeToAndCall`.

## Versioning convention

- Each upgrade bumps a `VERSION` constant exposed by the registry: `string public constant VERSION = "1.1.0";`
- Deployment records track `implementations.<RegistryName>` so any version mismatch is detectable from chain alone.

## Validation hook for CI

Add to CI:

```
npx hardhat run scripts/validate-upgrades.ts
```

This script runs `upgrades.validateUpgrade` for every PR-introduced contract change and fails the build if storage layout breaks.

## Emergency pause

If a vulnerability is discovered post-deploy, the holder of `PAUSER_ROLE` can pause writes on any affected registry immediately:

```typescript
await registry.connect(pauser).pause();
```

Reads remain available. Once the upgrade lands, unpause:

```typescript
await registry.connect(pauser).unpause();
```

For multi-registry incidents, pause `MerkleStateRegistry` first (highest blast radius), then the upstream registries.
