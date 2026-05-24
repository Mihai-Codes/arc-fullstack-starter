/**
 * x402 + Session Keys — Runnable Simulation Demo Script
 * ========================================================
 * 
 * Run with: npx ts-node scripts/x402_full_demo.ts
 * 
 * This script simulates the entire x402 + Session Key lifecycle in a 
 * localized story format. It demonstrates how session keys completely 
 * bypass wallet popups after a single one-time setup.
 */

import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { getAddress } from 'viem'

// Mock addresses
const USER_WALLET_ADDRESS = '0x1111111111111111111111111111111111111111'
const MOCK_TREASURY_ADDRESS = '0x8888888888888888888888888888888888888888'
const USDC_CONTRACT_ADDRESS = '0x0000000000000000000000000000000000000000'

// ─── RUNNING THE DEMO STORY ──────────────────────────────────────────────────

async function runDemo() {
  console.log('═══════════════════════════════════')
  console.log('x402 + Session Keys — Full Demo')
  console.log('Arc Testnet (Chain ID: 5042002)')
  console.log('═══════════════════════════════════\n')

  // --- STEP 1 ---
  console.log('STEP 1: Generate ephemeral session keypair')
  const privateKey = generatePrivateKey()
  const sessionAccount = privateKeyToAccount(privateKey)
  console.log(`Session key address: ${sessionAccount.address}`)
  console.log('(This key will live in sessionStorage and sign micropayments)\n')

  // --- STEP 2 ---
  console.log('STEP 2: Simulate user approving the session')
  const sessionConfig = {
    maxAmountUsdc: 5.0, // 5 USDC total spending cap
    expirySeconds: 86400, // 24 hours
    allowedContracts: [MOCK_TREASURY_ADDRESS],
    nonce: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  }
  console.log(`Configuring spending budget: ${sessionConfig.maxAmountUsdc} USDC`)
  console.log('User signed EIP-712 authorization mapping ✓')
  console.log('User sent 5.0 USDC to fund the session key address ✓\n')

  // --- STEP 3 ---
  console.log('STEP 3: Request a resource (will get 402)')
  const requiredAmountAtomic = '1000' // 0.001 USDC
  const requiredAmountUsdc = Number(requiredAmountAtomic) / 1e6
  console.log(`Client attempts: GET /api/thesis/1`)
  console.log(`Server responds: HTTP 402 Payment Required`)
  console.log(`Payment required: ${requiredAmountUsdc} USDC (${requiredAmountAtomic} atomic units)`)
  console.log(`Pay to: ${MOCK_TREASURY_ADDRESS}\n`)

  // --- STEP 4 ---
  console.log('STEP 4: Build EIP-3009 authorization')
  const transferAuth = {
    from: sessionAccount.address,
    to: getAddress(MOCK_TREASURY_ADDRESS),
    value: BigInt(requiredAmountAtomic),
    validAfter: BigInt(0),
    validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
    nonce: '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' as `0x${string}`,
  }
  console.log('EIP-712 domain constructed:')
  console.log('  name: USD Coin    ← critical: NOT "USDC"')
  console.log('  version: 2')
  console.log('  chainId: 5042002\n')

  // --- STEP 5 ---
  console.log('STEP 5: Sign with session key (not user wallet)')
  const domain = {
    name: 'USD Coin',
    version: '2',
    chainId: 5042002,
    verifyingContract: USDC_CONTRACT_ADDRESS as `0x${string}`,
  }
  const types = {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  } as const

  const signature = await sessionAccount.signTypedData({
    domain,
    types,
    primaryType: 'TransferWithAuthorization',
    message: transferAuth,
  })

  console.log(`Signature: ${signature.substring(0, 30)}...`)
  console.log('Signed securely in-memory by session key! ✓\n')

  // --- STEP 6 ---
  console.log('STEP 6: Encode PAYMENT-SIGNATURE header')
  const payload = {
    x402Version: 1,
    scheme: 'exact',
    network: 'arc-testnet-5042002',
    payload: {
      signature,
      from: transferAuth.from,
      to: transferAuth.to,
      value: transferAuth.value.toString(),
      validAfter: transferAuth.validAfter.toString(),
      validBefore: transferAuth.validBefore.toString(),
      nonce: transferAuth.nonce,
    },
  }
  const encodedHeader = Buffer.from(JSON.stringify(payload)).toString('base64')
  console.log(`PAYMENT-SIGNATURE: ${encodedHeader.substring(0, 45)}...\n`)

  // --- STEP 7 ---
  console.log('STEP 7: Retry request with payment')
  console.log('Server verified EIP-3009 signature match ✓')
  console.log('Server successfully settled USDC on-chain ✓')
  console.log('Server responded: HTTP 200 OK')
  console.log('Resource unlocked ✓\n')

  // --- STEP 8 ---
  console.log('STEP 8: Budget accounting')
  const spentUsdc = requiredAmountUsdc
  const remainingBudget = sessionConfig.maxAmountUsdc - spentUsdc
  console.log(`Session budget used: ${spentUsdc} / ${sessionConfig.maxAmountUsdc} USDC`)
  console.log(`Remaining: ${remainingBudget} USDC\n`)

  console.log('═══════════════════════════════════')
  console.log('Demo complete. No wallet popup required.')
  console.log('The user approved once. The rest was silent.')
  console.log('═══════════════════════════════════')
}

runDemo().catch(console.error)
