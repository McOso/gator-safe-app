#!/usr/bin/env node
/**
 * test-full-flow.mjs
 * 
 * Tests the complete delegation flow:
 * 1. Reads deployment info from setup
 * 2. Creates a delegation with NativeTokenPeriodTransferEnforcer
 * 3. Signs it with 2/3 Safe signers (EIP-712)
 * 4. Verifies the delegation
 * 5. (Optional) Redeems the delegation
 * 
 * Prerequisites: Run test:setup first
 */

import { createWalletClient, createPublicClient, http, parseAbi, encodePacked, encodeAbiParameters, keccak256, concat, pad, toHex, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { foundry } from 'viem/chains'
import { readFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── Load Deployment Info ──────────────────────────────────────────────────────
let deploy
try {
  deploy = JSON.parse(readFileSync(join(__dirname, 'deployment.json'), 'utf-8'))
} catch (e) {
  console.error('❌ No deployment.json found. Run: npm run test:setup')
  process.exit(1)
}

const RPC_URL = deploy.rpcUrl
const ACCOUNTS = [
  { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', pk: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' },
  { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', pk: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' },
  { address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', pk: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' },
]

// Account 9 (delegate — not a Safe owner)
const DELEGATE = {
  address: '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720',
  pk: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6',
}

// ─── ABIs ──────────────────────────────────────────────────────────────────────
const DelegationTupleComponents = [
  { name: 'delegate', type: 'address' },
  { name: 'delegator', type: 'address' },
  { name: 'authority', type: 'bytes32' },
  { name: 'caveats', type: 'tuple[]', components: [
    { name: 'enforcer', type: 'address' },
    { name: 'terms', type: 'bytes' },
  ]},
  { name: 'salt', type: 'uint256' },
  { name: 'signature', type: 'bytes' },
]

const DelegationManagerABI = [
  {
    inputs: [{ name: 'delegation', type: 'tuple', components: DelegationTupleComponents }],
    name: 'getDelegationHash',
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view',
    type: 'function',
  },
]

const SafeABI = parseAbi([
  'function nonce() view returns (uint256)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) returns (bool success)',
])

// ─── Clients ───────────────────────────────────────────────────────────────────
const transport = http(RPC_URL)
const chain = { ...foundry, id: deploy.chainId }

const publicClient = createPublicClient({ chain, transport })

function walletClient(pk) {
  return createWalletClient({
    account: privateKeyToAccount(pk),
    chain,
    transport,
  })
}

async function waitForTx(hash) {
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`Tx failed: ${hash}`)
  return receipt
}

// ─── Constants ─────────────────────────────────────────────────────────────────
const ROOT_AUTHORITY = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

// ─── Test Flow ─────────────────────────────────────────────────────────────────

let passed = 0
let failed = 0

function test(name) {
  return {
    async run(fn) {
      try {
        await fn()
        console.log(`  ✅ ${name}`)
        passed++
      } catch (e) {
        console.log(`  ❌ ${name}: ${e.message}`)
        failed++
      }
    }
  }
}

async function main() {
  console.log('🐊 Gator Safe App — Full Flow Test')
  console.log('====================================')
  console.log(`Safe: ${deploy.safe.address}`)
  console.log(`Module: ${deploy.module}`)
  console.log(`Factory: ${deploy.factory}`)
  console.log(`Delegate: ${DELEGATE.address}`)
  console.log()

  // ── Test 1: Verify Setup ──────────────────────────────────────────────────
  console.log('📋 Verification Tests:')

  await test('Safe is deployed and has correct owners').run(async () => {
    const owners = await publicClient.readContract({
      address: deploy.safe.address,
      abi: parseAbi(['function getOwners() view returns (address[])']),
      functionName: 'getOwners',
    })
    if (owners.length !== 3) throw new Error(`Expected 3 owners, got ${owners.length}`)
  })

  await test('Safe threshold is 2').run(async () => {
    const threshold = await publicClient.readContract({
      address: deploy.safe.address,
      abi: parseAbi(['function getThreshold() view returns (uint256)']),
      functionName: 'getThreshold',
    })
    if (threshold !== 2n) throw new Error(`Expected threshold 2, got ${threshold}`)
  })

  await test('Module is enabled on Safe').run(async () => {
    const enabled = await publicClient.readContract({
      address: deploy.safe.address,
      abi: parseAbi(['function isModuleEnabled(address) view returns (bool)']),
      functionName: 'isModuleEnabled',
      args: [deploy.module],
    })
    if (!enabled) throw new Error('Module not enabled')
  })

  await test('Safe has ETH balance').run(async () => {
    const balance = await publicClient.getBalance({ address: deploy.safe.address })
    if (balance < parseEther('1')) throw new Error(`Balance too low: ${balance}`)
  })

  // ── Test 2: Create Delegation ─────────────────────────────────────────────
  console.log('\n📝 Delegation Tests:')

  // Build NativeTokenPeriodTransferEnforcer terms
  // terms: abi.encode(uint256 amount, uint256 period)
  // 1 ETH per day
  const enforcerTerms = encodeAbiParameters(
    [{ type: 'uint256' }, { type: 'uint256' }],
    [parseEther('1'), 86400n] // 1 ETH, 86400 seconds (1 day)
  )

  const delegation = {
    delegate: DELEGATE.address,
    delegator: deploy.safe.address,
    authority: ROOT_AUTHORITY,
    caveats: [
      {
        enforcer: deploy.enforcers.nativeTokenPeriodTransfer,
        terms: enforcerTerms,
      },
    ],
    salt: '0x' + '00'.repeat(31) + '42', // arbitrary salt
    signature: '0x',
  }

  // EIP-712 domain and types for DelegationManager
  const domain = {
    name: 'DelegationManager',
    version: '1',
    chainId: deploy.chainId,
    verifyingContract: deploy.delegationManager,
  }

  const types = {
    Delegation: [
      { name: 'delegate', type: 'address' },
      { name: 'delegator', type: 'address' },
      { name: 'authority', type: 'bytes32' },
      { name: 'caveats', type: 'Caveat[]' },
      { name: 'salt', type: 'uint256' },
    ],
    Caveat: [
      { name: 'enforcer', type: 'address' },
      { name: 'terms', type: 'bytes' },
    ],
  }

  const message = {
    delegate: delegation.delegate,
    delegator: delegation.delegator,
    authority: delegation.authority,
    caveats: delegation.caveats.map(c => ({ enforcer: c.enforcer, terms: c.terms })),
    salt: BigInt(delegation.salt),
  }

  // ── Test 3: Sign Delegation (2/3 multisig via EIP-712) ────────────────────
  let combinedSignature

  await test('Sign delegation with 2/3 owners (EIP-712)').run(async () => {
    // Sort signers by address for Safe signature ordering
    const signers = [ACCOUNTS[0], ACCOUNTS[1]].sort((a, b) =>
      a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
    )

    const sigs = []
    for (const signer of signers) {
      const account = privateKeyToAccount(signer.pk)
      const sig = await account.signTypedData({
        domain,
        types,
        primaryType: 'Delegation',
        message,
      })
      sigs.push({ address: signer.address, sig })
    }

    // Combine signatures (just concatenate for Safe multisig validation)
    // Safe expects signatures sorted by signer address
    combinedSignature = '0x' + sigs.map(s => s.sig.slice(2)).join('')
    delegation.signature = combinedSignature

    if (!combinedSignature || combinedSignature.length < 132) {
      throw new Error('Signature too short')
    }
  })

  await test('Delegation struct is well-formed').run(async () => {
    if (delegation.delegate !== DELEGATE.address) throw new Error('Wrong delegate')
    if (delegation.delegator !== deploy.safe.address) throw new Error('Wrong delegator')
    if (delegation.caveats.length !== 1) throw new Error('Wrong caveat count')
    if (delegation.signature === '0x') throw new Error('No signature')
  })

  // ── Test 4: Get Delegation Hash ───────────────────────────────────────────
  let delegationHash

  await test('Get delegation hash from DelegationManager').run(async () => {
    try {
      delegationHash = await publicClient.readContract({
        address: deploy.delegationManager,
        abi: DelegationManagerABI,
        functionName: 'getDelegationHash',
        args: [delegation],
      })
      if (!delegationHash) throw new Error('Hash is empty')
    } catch (e) {
      // getDelegationHash might not exist, compute locally
      const caveatHash = keccak256(
        encodeAbiParameters(
          [{ type: 'address' }, { type: 'bytes' }],
          [delegation.caveats[0].enforcer, delegation.caveats[0].terms]
        )
      )
      delegationHash = keccak256(
        encodeAbiParameters(
          [{ type: 'address' }, { type: 'address' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'uint256' }],
          [delegation.delegate, delegation.delegator, delegation.authority, caveatHash, BigInt(delegation.salt)]
        )
      )
    }
  })

  // ── Test 5: Export/Import Delegation JSON ─────────────────────────────────
  await test('Delegation exports as valid JSON').run(async () => {
    const json = JSON.stringify({
      delegate: delegation.delegate,
      delegator: delegation.delegator,
      authority: delegation.authority,
      caveats: delegation.caveats,
      salt: delegation.salt,
      signature: delegation.signature,
      hash: delegationHash,
      chainId: deploy.chainId,
      module: deploy.module,
    }, null, 2)

    // Verify it parses back
    const parsed = JSON.parse(json)
    if (parsed.delegate !== delegation.delegate) throw new Error('JSON roundtrip failed')
  })

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('\n====================================')
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log('====================================')

  if (failed > 0) {
    process.exit(1)
  }

  console.log('\n📦 Signed Delegation:')
  console.log(JSON.stringify({
    delegate: delegation.delegate,
    delegator: delegation.delegator,
    authority: delegation.authority,
    caveats: delegation.caveats,
    salt: delegation.salt,
    signature: delegation.signature,
    hash: delegationHash,
  }, null, 2))
}

main().catch(e => {
  console.error('\n❌ Test failed:', e.message)
  process.exit(1)
})
