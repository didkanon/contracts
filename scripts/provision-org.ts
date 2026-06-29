/**
 * Provision a new organization on the kanon `OrganizationRegistry`.
 *
 *   1. The signer calls `registerOrg(name, admin)`. The contract assigns a
 *      random bytes32 orgId, emits `OrgRegistered`, and makes `admin` the
 *      org's admin + first member.
 *   2. A signer with `GOVERNANCE_ROLE` calls `approveOrg(orgId)` to activate
 *      the org. In dev the operator key holds the role; in prod the timelock
 *      / multisig does it.
 *
 * Run:
 *
 *     # besu-ajna (loads BESU_AJNA_DEPLOYER_KEY from .env via shell `source`)
 *     ORG_NAME='DigiCred' npx hardhat run scripts/provision-org.ts --network besu-ajna
 *
 * Prints the new orgId on the last stdout line so a caller can capture it.
 */
import { ethers, network } from 'hardhat'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

interface Deployment {
  chainId: number
  addresses: { OrganizationRegistry: string; KanonAddressBook: string }
}

async function main(): Promise<void> {
  const orgName = process.env.ORG_NAME?.trim()
  if (!orgName) {
    throw new Error(
      'ORG_NAME env var is required. Example: ORG_NAME="DigiCred" npx hardhat run scripts/provision-org.ts --network besu-ajna'
    )
  }

  const chainId = Number(network.config.chainId ?? (await ethers.provider.getNetwork()).chainId)
  const deployPath = join(__dirname, '..', 'deployments', `${chainId}.json`)
  const deployment = JSON.parse(readFileSync(deployPath, 'utf8')) as Deployment

  const [signer] = await ethers.getSigners()
  const admin = await signer.getAddress()

  const orgRegistry = await ethers.getContractAt(
    'OrganizationRegistry',
    deployment.addresses.OrganizationRegistry,
    signer
  )

  console.error(`[provision-org] chain=${chainId} name="${orgName}" admin=${admin}`)
  console.error(`[provision-org] OrganizationRegistry=${deployment.addresses.OrganizationRegistry}`)

  // 1. registerOrg → contract assigns a random bytes32 orgId.
  const registerTx = await orgRegistry.registerOrg(orgName, admin)
  const registerReceipt = await registerTx.wait()
  if (!registerReceipt) throw new Error('[provision-org] no receipt for registerOrg')

  const registered = registerReceipt.logs
    .map((log) => {
      try {
        return orgRegistry.interface.parseLog({ topics: [...log.topics], data: log.data })
      } catch {
        return null
      }
    })
    .find((parsed) => parsed?.name === 'OrgRegistered')

  if (!registered) throw new Error('[provision-org] OrgRegistered event missing from receipt')
  const orgId = registered.args.orgId as string
  console.error(`[provision-org] registered: orgId=${orgId} (tx ${registerTx.hash})`)

  // 2. approveOrg → governance signer activates the org. In dev the operator
  //    holds GOVERNANCE_ROLE; this reverts in prod unless the signer has the role.
  const approveTx = await orgRegistry.approveOrg(orgId)
  await approveTx.wait()
  console.error(`[provision-org] approved (tx ${approveTx.hash})`)

  console.error('')
  console.error('=== ready to use ===')
  console.error(`  KANON_ISSUER_ORG_ID=${orgId}`)
  console.error(`  Issuer DID:        did:kanon:org:${orgId}`)
  console.error(`  Org admin/member:  ${admin}`)
  console.error('')

  // Last stdout line = orgId, for callers that capture it.
  // eslint-disable-next-line no-console
  console.log(orgId)
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(`[provision-org] failed: ${(err as Error).message}`)
  process.exit(1)
})
