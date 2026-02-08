#!/usr/bin/env node
/**
 * setup-local.mjs
 * 
 * Sets up the local Anvil environment:
 * 1. Creates a 2/3 Safe multisig using Safe SDK
 * 2. Deploys DeleGatorModuleFactory via forge
 * 3. Deploys DeleGatorModule for the Safe
 * 4. Enables the module on the Safe
 * 
 * Prerequisites: Anvil must be running (npm run test:anvil)
 */

import { createWalletClient, createPublicClient, http, parseAbi, encodeFunctionData, getContractAddress, encodeAbiParameters } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { foundry } from 'viem/chains'
import { execSync } from 'child_process'
import { writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── Config ────────────────────────────────────────────────────────────────────
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545'
const FOUNDRY_BIN = `${process.env.HOME}/.foundry/bin`
const DELEGATOR_MODULE_REPO = `${process.env.HOME}/projects/delegator-safe-module`

const DELEGATION_MANAGER = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3'

// Safe contracts on Base Sepolia (forked)
const SAFE_PROXY_FACTORY = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67'
const SAFE_SINGLETON_L2 = '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762'

// Anvil default accounts
const ACCOUNTS = [
  { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', pk: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' },
  { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', pk: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' },
  { address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', pk: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' },
]

// ─── ABIs ──────────────────────────────────────────────────────────────────────
const SafeProxyFactoryABI = parseAbi([
  'function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)',
  'event ProxyCreation(address indexed proxy, address singleton)',
])

const SafeABI = parseAbi([
  'function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function enableModule(address module)',
  'function isModuleEnabled(address module) view returns (bool)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) returns (bool success)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
])

const DeleGatorModuleFactoryABI = parseAbi([
  'function deploy(address _safe, bytes32 _salt) returns (address module_, bool alreadyDeployed_)',
  'function predictAddress(address _safe, bytes32 _salt) view returns (address predicted_)',
  'function delegationManager() view returns (address)',
])

// ─── Clients ───────────────────────────────────────────────────────────────────
const transport = http(RPC_URL)

const publicClient = createPublicClient({
  chain: { ...foundry, id: 84532 }, // forked Base Sepolia chain ID
  transport,
})

function walletClient(pk) {
  return createWalletClient({
    account: privateKeyToAccount(pk),
    chain: { ...foundry, id: 84532 },
    transport,
  })
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

async function waitForTx(hash) {
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`Tx failed: ${hash}`)
  return receipt
}

/**
 * Execute a Safe transaction with 2/3 multisig approval
 */
async function execSafeTx(safeAddress, to, value, data) {
  const nonce = await publicClient.readContract({
    address: safeAddress, abi: SafeABI, functionName: 'nonce'
  })

  const txHash = await publicClient.readContract({
    address: safeAddress, abi: SafeABI, functionName: 'getTransactionHash',
    args: [to, value, data, 0, 0n, 0n, 0n, '0x0000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000', nonce]
  })

  // Collect signatures from first 2 signers (threshold=2)
  // Safe requires signatures sorted by signer address (ascending)
  const signers = [ACCOUNTS[0], ACCOUNTS[1]].sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
  )

  let signatures = '0x'
  for (const signer of signers) {
    const account = privateKeyToAccount(signer.pk)
    const sig = await account.signMessage({ message: { raw: txHash } })
    // eth_sign signature: adjust v (+4 for eth_sign in Safe)
    const r = sig.slice(0, 66)
    const s = '0x' + sig.slice(66, 130)
    let v = parseInt(sig.slice(130, 132), 16)
    v += 4 // Safe's eth_sign convention
    signatures += r.slice(2) + s.slice(2) + v.toString(16).padStart(2, '0')
  }

  const client = walletClient(ACCOUNTS[0].pk)
  const hash = await client.writeContract({
    address: safeAddress,
    abi: SafeABI,
    functionName: 'execTransaction',
    args: [to, value, data, 0, 0n, 0n, 0n, '0x0000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000', signatures],
  })

  return waitForTx(hash)
}

// ─── Step 1: Create Safe ───────────────────────────────────────────────────────
async function createSafe() {
  console.log('\n📦 Step 1: Creating 2/3 Safe multisig...')

  const owners = ACCOUNTS.map(a => a.address)
  const threshold = 2

  const setupData = encodeFunctionData({
    abi: SafeABI,
    functionName: 'setup',
    args: [
      owners,
      BigInt(threshold),
      '0x0000000000000000000000000000000000000000', // to
      '0x',           // data
      '0x0000000000000000000000000000000000000000', // fallbackHandler
      '0x0000000000000000000000000000000000000000', // paymentToken
      0n,             // payment
      '0x0000000000000000000000000000000000000000', // paymentReceiver
    ],
  })

  const saltNonce = BigInt(Date.now())
  const client = walletClient(ACCOUNTS[0].pk)

  const hash = await client.writeContract({
    address: SAFE_PROXY_FACTORY,
    abi: SafeProxyFactoryABI,
    functionName: 'createProxyWithNonce',
    args: [SAFE_SINGLETON_L2, setupData, saltNonce],
  })

  const receipt = await waitForTx(hash)

  // Parse ProxyCreation event to get Safe address
  // The proxy address is in the logs
  let safeAddress = null
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() === SAFE_PROXY_FACTORY.toLowerCase()) {
      // ProxyCreation event topic
      safeAddress = '0x' + log.topics[1].slice(26)
      break
    }
  }

  if (!safeAddress) {
    // Fallback: the Safe address should be the contract created
    // Look for the first contract creation in internal txs
    // Or just decode from logs
    throw new Error('Could not find Safe address in logs')
  }

  // Verify
  const actualOwners = await publicClient.readContract({
    address: safeAddress, abi: SafeABI, functionName: 'getOwners'
  })
  const actualThreshold = await publicClient.readContract({
    address: safeAddress, abi: SafeABI, functionName: 'getThreshold'
  })

  console.log(`  ✅ Safe deployed: ${safeAddress}`)
  console.log(`  Owners: ${actualOwners.join(', ')}`)
  console.log(`  Threshold: ${actualThreshold}/${actualOwners.length}`)

  return safeAddress
}

// ─── Step 2: Deploy DeleGatorModuleFactory ─────────────────────────────────────
function deployFactory() {
  console.log('\n🏭 Step 2: Deploying DeleGatorModuleFactory...')

  const cmd = [
    `${FOUNDRY_BIN}/forge`, 'script',
    'script/DeployDeleGatorModule.s.sol',
    '--rpc-url', RPC_URL,
    '--broadcast',
    '--skip-simulation',
  ].join(' ')

  try {
    const output = execSync(cmd, {
      cwd: DELEGATOR_MODULE_REPO,
      env: {
        ...process.env,
        DELEGATION_MANAGER,
        SAFE_ADDRESS: '0x0000000000000000000000000000000000000001', // dummy, we just want the factory
        DEPLOYER_PRIVATE_KEY: ACCOUNTS[0].pk, // with 0x prefix
        SALT: 'test-salt',
      },
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    // Parse factory address from output
    const match = output.match(/DeleGatorModuleFactory at:\s+(0x[0-9a-fA-F]{40})/)
      || output.match(/DeleGatorModuleFactory:\s+(0x[0-9a-fA-F]{40})/)
    if (match) {
      console.log(`  ✅ Factory deployed: ${match[1]}`)
      return match[1]
    }
  } catch (e) {
    // Try stderr too
    const stderr = e.stderr?.toString() || ''
    const stdout = e.stdout?.toString() || ''
    const combined = stdout + stderr
    const match = combined.match(/DeleGatorModuleFactory at:\s+(0x[0-9a-fA-F]{40})/)
      || combined.match(/DeleGatorModuleFactory:\s+(0x[0-9a-fA-F]{40})/)
    if (match) {
      console.log(`  ✅ Factory deployed: ${match[1]}`)
      return match[1]
    }
    console.error('  Forge output:', combined.slice(-500))
  }

  // Fallback: deploy factory directly via viem
  console.log('  ⚠️  Forge deploy failed, deploying factory via bytecode...')
  return null
}

async function deployFactoryDirect() {
  console.log('\n🏭 Step 2 (fallback): Deploying DeleGatorModuleFactory via forge create...')

  try {
    const cmd = [
      `${FOUNDRY_BIN}/forge`, 'create',
      'src/DeleGatorModuleFactory.sol:DeleGatorModuleFactory',
      '--rpc-url', RPC_URL,
      '--private-key', ACCOUNTS[0].pk,
      '--constructor-args', DELEGATION_MANAGER,
      '--broadcast',
    ].join(' ')

    const output = execSync(cmd, {
      cwd: DELEGATOR_MODULE_REPO,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    const match = output.match(/Deployed to:\s+(0x[0-9a-fA-F]{40})/)
    if (match) {
      console.log(`  ✅ Factory deployed: ${match[1]}`)
      return match[1]
    }
    throw new Error('Could not parse address from forge create output')
  } catch (e) {
    const combined = (e.stdout || '') + (e.stderr || '')
    const match = combined.match(/Deployed to:\s+(0x[0-9a-fA-F]{40})/)
    if (match) {
      console.log(`  ✅ Factory deployed: ${match[1]}`)
      return match[1]
    }
    console.error('  ❌ Failed to deploy factory:', combined.slice(-300))
    throw new Error('Factory deployment failed')
  }
}

// ─── Step 3: Deploy Module ─────────────────────────────────────────────────────
async function deployModule(factoryAddress, safeAddress) {
  console.log('\n🧩 Step 3: Deploying DeleGatorModule for Safe...')

  const salt = '0x0000000000000000000000000000000000000000000000000000000000000001'

  // Predict address first
  const predicted = await publicClient.readContract({
    address: factoryAddress,
    abi: DeleGatorModuleFactoryABI,
    functionName: 'predictAddress',
    args: [safeAddress, salt],
  })
  console.log(`  Predicted module address: ${predicted}`)

  // Deploy via factory
  const client = walletClient(ACCOUNTS[0].pk)
  const hash = await client.writeContract({
    address: factoryAddress,
    abi: DeleGatorModuleFactoryABI,
    functionName: 'deploy',
    args: [safeAddress, salt],
  })
  await waitForTx(hash)
  console.log(`  ✅ Module deployed: ${predicted}`)

  return predicted
}

// ─── Step 4: Enable Module on Safe ─────────────────────────────────────────────
async function enableModule(safeAddress, moduleAddress) {
  console.log('\n🔓 Step 4: Enabling module on Safe (2/3 multisig tx)...')

  const data = encodeFunctionData({
    abi: SafeABI,
    functionName: 'enableModule',
    args: [moduleAddress],
  })

  await execSafeTx(safeAddress, safeAddress, 0n, data)

  // Verify
  const enabled = await publicClient.readContract({
    address: safeAddress, abi: SafeABI, functionName: 'isModuleEnabled',
    args: [moduleAddress],
  })

  if (enabled) {
    console.log(`  ✅ Module enabled on Safe!`)
  } else {
    throw new Error('Module not enabled after tx')
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('🐊 Gator Safe App — Local Test Setup')
  console.log('=====================================')
  console.log(`RPC: ${RPC_URL}`)

  // Check Anvil is running
  try {
    const blockNum = await publicClient.getBlockNumber()
    console.log(`Anvil block: ${blockNum}`)
  } catch (e) {
    console.error('❌ Cannot connect to Anvil. Start it first: npm run test:anvil')
    process.exit(1)
  }

  // Step 1: Create Safe
  const safeAddress = await createSafe()

  // Fund the Safe with some ETH
  const funder = walletClient(ACCOUNTS[0].pk)
  const fundHash = await funder.sendTransaction({
    to: safeAddress,
    value: 10000000000000000000n, // 10 ETH
  })
  await waitForTx(fundHash)
  console.log('  💰 Funded Safe with 10 ETH')

  // Step 2: Deploy Factory
  let factoryAddress = deployFactory()
  if (!factoryAddress) {
    factoryAddress = await deployFactoryDirect()
  }

  // Step 3: Deploy Module
  const moduleAddress = await deployModule(factoryAddress, safeAddress)

  // Step 4: Enable Module
  await enableModule(safeAddress, moduleAddress)

  // Save deployment info
  const deployInfo = {
    rpcUrl: RPC_URL,
    chainId: 84532,
    safe: {
      address: safeAddress,
      owners: ACCOUNTS.map(a => a.address),
      threshold: 2,
    },
    factory: factoryAddress,
    module: moduleAddress,
    delegationManager: DELEGATION_MANAGER,
    enforcers: {
      nativeTokenPeriodTransfer: '0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9',
      erc20PeriodTransfer: '0x474e3Ae7E169e940607cC624Da8A15Eb120139aB',
      valueLte: '0x92Bf12322527cAA612fd31a0e810472BBB106A8F',
      timestamp: '0x1046bb45C8d673d4ea75321280DB34899413c069',
      allowedTargets: '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB',
      allowedMethods: '0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5',
      limitedCalls: '0x04658B29F6b82ed55274221a06Fc97D318E25416',
    },
    accounts: ACCOUNTS.map(a => ({ address: a.address })),
    timestamp: new Date().toISOString(),
  }

  const outPath = join(__dirname, 'deployment.json')
  writeFileSync(outPath, JSON.stringify(deployInfo, null, 2))
  console.log(`\n📄 Deployment info saved to ${outPath}`)
  console.log('\n✅ Setup complete! Run: npm run test:flow')
}

main().catch(e => {
  console.error('\n❌ Setup failed:', e.message)
  process.exit(1)
})
