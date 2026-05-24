/**
 * x402_demo.ts — Minimal x402 Flow Simulation
 * =============================================
 * Run with:  npx ts-node scripts/x402_demo.ts
 *
 * PURPOSE:
 * This script shows the core x402 protocol in the simplest possible form.
 * No browser. No real network. Just pure TypeScript + viem.
 *
 * You will see:
 *   STEP 1 — Generate an ephemeral session keypair
 *   STEP 2 — Client makes a request and receives HTTP 402
 *   STEP 3 — Client builds an EIP-3009 transfer authorization
 *   STEP 4 — Client signs it in-memory (no wallet popup)
 *   STEP 5 — Client encodes the signature into a PAYMENT-SIGNATURE header
 *   STEP 6 — Client retries with the header and receives HTTP 200
 *
 * Read the comments — they explain the WHY at every step.
 */

import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { getAddress } from 'viem'

// ─────────────────────────────────────────────────────────────────────────────
// ARC NETWORK CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

// Arc Testnet chain ID — included in the EIP-712 domain hash.
// Using the wrong chainId produces a signature that is structurally valid
// but will be rejected by the USDC contract on Arc (domain hash mismatch).
const ARC_CHAIN_ID = 5042002

// USDC on Arc uses 6 decimal places — NOT 18 like ETH.
// 1 USDC = 1_000_000 atomic units.
// Pitfall: if you multiply by 1e18, you'd authorize ~10^12 USDC per request.
const USDC_ATOMIC_MULTIPLIER = 1_000_000

// The canonical EIP-712 name for USDC as deployed on Arc.
// This string is hashed into the EIP-712 domain separator.
// 'USDC', 'usdc', 'USD Coin (PoS)' all produce a DIFFERENT hash → broken sig.
const USDC_EIP712_NAME = 'USD Coin'    // exact, case-sensitive
const USDC_EIP712_VERSION = '2'        // version "2", not "1"

// Placeholder USDC address — replace with real contract address for production
const MOCK_USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as `0x${string}`

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: cryptographically secure random bytes32 nonce
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a random bytes32 nonce for EIP-3009.
 *
 * WHY random (not sequential)?
 * EIP-3009 nonces are NOT like Ethereum tx nonces (0, 1, 2, ...).
 * The USDC contract stores used nonces in a per-address mapping:
 *   mapping(address => mapping(bytes32 => bool)) authorizationState
 * Once a nonce is used, any authorization with the same nonce is rejected.
 * Random bytes32 makes nonce collision probability negligible (~1 in 2^256).
 *
 * WHY crypto.getRandomValues, not Math.random()?
 * Math.random() is NOT cryptographically secure — it can be predicted.
 * A predictable nonce lets an attacker pre-compute and replay authorizations.
 */
function generateNonce(): `0x${string}` {
  const bytes = new Uint8Array(32)

  // Use the OS's CSPRNG via Web Crypto API (available in Node 16+ and all browsers)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    // Fallback for older Node.js versions
    const nodeCrypto = require('crypto') as typeof import('crypto')
    const buf = nodeCrypto.randomBytes(32)
    bytes.set(buf)
  }

  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`
}

// ─────────────────────────────────────────────────────────────────────────────
// MOCK SERVER
// In a real app: a Next.js API route, Express handler, or edge function.
// Here: a plain object that mimics HTTP request/response semantics.
// ─────────────────────────────────────────────────────────────────────────────

const mockServer = {
  treasuryAddress: '0x8888888888888888888888888888888888888888' as `0x${string}`,
  priceAtomic: 1000,  // 0.001 USDC per request

  /**
   * Handle a request to GET /api/resource.
   *
   * First call (no header):  returns 402 with payment requirements.
   * Second call (with header): validates payment and returns 200.
   */
  handle(paymentHeader?: string): { status: number; body: unknown } {
    // ── No payment header → issue the 402 challenge ──────────────────────
    if (!paymentHeader) {
      return {
        status: 402,
        body: {
          accepts: [{
            scheme: 'exact',
            network: `arc-testnet-${ARC_CHAIN_ID}`,
            maxAmountRequired: String(this.priceAtomic),  // always a string
            payTo: this.treasuryAddress,
            asset: MOCK_USDC_ADDRESS,
            maxTimeoutSeconds: 300,  // client has 5 min to sign and retry
          }]
        }
      }
    }

    // ── Has payment header → decode and validate ──────────────────────────
    try {
      const decoded = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf-8'))
      const p = decoded.payload

      // Structural check
      if (!p?.signature || !p?.from || !p?.value) {
        return { status: 402, body: { error: 'Malformed payment header — missing fields' } }
      }

      // Amount check — value must be >= required price
      if (Number(p.value) < this.priceAtomic) {
        return { status: 402, body: { error: 'Insufficient payment amount' } }
      }

      // Temporal check — validBefore must be in the future
      // In production: compare against block.timestamp server-side before
      // paying gas to submit on-chain (saves gas on doomed transactions).
      const validBefore = Number(p.validBefore)
      const nowSeconds = Math.floor(Date.now() / 1000)
      if (validBefore <= nowSeconds) {
        return { status: 402, body: { error: 'Authorization expired (validBefore in the past)' } }
      }

      // All checks passed → return the protected resource
      return {
        status: 200,
        body: {
          content: '📄 This is the protected content you paid for.',
          paidBy: p.from,
          amountPaid: `${Number(p.value) / USDC_ATOMIC_MULTIPLIER} USDC`,
          note: 'In production, the settler would now submit USDC.transferWithAuthorization() on-chain.',
        }
      }
    } catch {
      return { status: 400, body: { error: 'Could not decode payment header (invalid base64 or JSON)' } }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN DEMO
// ─────────────────────────────────────────────────────────────────────────────

async function runDemo() {
  console.log('\n╔══════════════════════════════════════════════════╗')
  console.log('║      x402 Minimal Demo — Arc Testnet (5042002)   ║')
  console.log('║   402 Challenge → EIP-3009 Sign → 200 Success   ║')
  console.log('╚══════════════════════════════════════════════════╝\n')

  // ── STEP 1: Generate Session Keypair ───────────────────────────────────
  // An ephemeral secp256k1 keypair. In a real app this lives in sessionStorage
  // and is pre-funded with USDC by the user's main wallet.
  // It acts as the "from" address in every EIP-3009 authorization.
  console.log('📍 STEP 1: Generate ephemeral session keypair')
  console.log('   Uses crypto.getRandomValues() — cryptographically secure.\n')

  const privateKey = generatePrivateKey()
  const sessionAccount = privateKeyToAccount(privateKey)

  console.log(`   ✅ Session address: ${sessionAccount.address}`)
  console.log('   (In production, user funds this address with USDC before use)\n')

  // ── STEP 2: First Request → Receive 402 ────────────────────────────────
  // The client makes the request without any payment header.
  // The server responds with a machine-readable payment requirement.
  console.log('📍 STEP 2: Make initial request — expect HTTP 402')
  console.log('   Client sends: GET /api/resource  (no payment header)\n')

  const firstResponse = mockServer.handle()  // no payment header
  console.log(`   Server responds: HTTP ${firstResponse.status}`)
  console.log('   Body:', JSON.stringify(firstResponse.body, null, 4)
    .split('\n').map(l => '   ' + l).join('\n'))

  if (firstResponse.status !== 402) {
    console.error('   ❌ Expected 402. Demo logic error.')
    process.exit(1)
  }

  // Parse the payment requirement from the 402 body
  const body402 = firstResponse.body as { accepts: Array<{
    maxAmountRequired: string; payTo: string; maxTimeoutSeconds: number
  }> }
  const req = body402.accepts[0]
  const amountUsdc = Number(req.maxAmountRequired) / USDC_ATOMIC_MULTIPLIER

  console.log(`\n   Parsed requirement: pay ${amountUsdc} USDC to ${req.payTo}`)
  console.log(`   Time window: ${req.maxTimeoutSeconds} seconds to sign and retry\n`)

  // ── STEP 3: Build EIP-3009 Transfer Authorization ──────────────────────
  // EIP-3009 (transferWithAuthorization) allows the session key to
  // pre-authorize a specific USDC transfer without submitting a tx itself.
  // The server's settler wallet will execute it on-chain later.
  //
  // KEY INVARIANT: ecrecover(signature) MUST equal auth.from.
  // This means the private key that signs MUST control the "from" address.
  // Since the session key IS the from address (and holds the USDC),
  // this invariant is always satisfied.
  console.log('📍 STEP 3: Build EIP-3009 transfer authorization')

  const nowSeconds = Math.floor(Date.now() / 1000)

  const transferAuth = {
    from: sessionAccount.address,                       // session key = USDC source
    to: getAddress(req.payTo) as `0x${string}`,        // treasury from 402 body
    value: BigInt(req.maxAmountRequired),               // 6 decimals, NOT 18
    validAfter: BigInt(0),                              // valid immediately
    // CRITICAL: validBefore must be a FUTURE timestamp.
    // Using 0n = "already expired" = USDC contract rejects.
    // Always derive from server's maxTimeoutSeconds.
    validBefore: BigInt(nowSeconds + req.maxTimeoutSeconds),
    // CRITICAL: nonce must be fresh and random per authorization.
    // Reusing a nonce = "authorization is used" rejection on-chain.
    nonce: generateNonce(),
  }

  console.log(`   from:        ${transferAuth.from}`)
  console.log(`   to:          ${transferAuth.to}`)
  console.log(`   value:       ${transferAuth.value}n atomic = ${amountUsdc} USDC`)
  console.log(`   validBefore: ${transferAuth.validBefore}n (${req.maxTimeoutSeconds}s from now)`)
  console.log(`   nonce:       ${transferAuth.nonce.slice(0, 18)}...\n`)

  // ── STEP 4: Sign with Session Key (EIP-712) ─────────────────────────────
  // EIP-712 signs structured data — not raw bytes.
  // The domain (name, version, chainId, verifyingContract) is hashed
  // into the final signed hash, binding the signature to this specific
  // chain and contract.
  console.log('📍 STEP 4: Sign with session key — EIP-712 typed data')

  const domain = {
    name: USDC_EIP712_NAME,       // 'USD Coin' — exact, case-sensitive
    version: USDC_EIP712_VERSION, // '2' — not '1'
    chainId: ARC_CHAIN_ID,        // 5042002 — Arc Testnet
    verifyingContract: MOCK_USDC_ADDRESS,
  }

  // The typed data schema for EIP-3009's TransferWithAuthorization.
  // Field order matters — it must match the contract's type hash exactly.
  const types = {
    TransferWithAuthorization: [
      { name: 'from',        type: 'address' },
      { name: 'to',          type: 'address' },
      { name: 'value',       type: 'uint256' },
      { name: 'validAfter',  type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce',       type: 'bytes32' },
    ],
  } as const

  console.log(`   Domain: name="${domain.name}", version="${domain.version}", chainId=${domain.chainId}`)
  console.log('   Signing in-memory — no wallet popup, no network call...')

  // viem's signTypedData implements EIP-712 hashing + secp256k1 signing entirely in-memory.
  const signature = await sessionAccount.signTypedData({
    domain,
    types,
    primaryType: 'TransferWithAuthorization',
    message: transferAuth,
  })

  console.log(`   ✅ Signature: ${signature.slice(0, 20)}...${signature.slice(-8)}\n`)

  // ── STEP 5: Encode PAYMENT-SIGNATURE Header ─────────────────────────────
  // The signed payload is JSON-serialized then base64-encoded.
  // Base64 ensures the header value contains only HTTP-safe characters.
  // The server decodes this, verifies ecrecover(sig) == from, then settles.
  console.log('📍 STEP 5: Encode PAYMENT-SIGNATURE header (base64 JSON)')

  const paymentPayload = {
    x402Version: 1,
    scheme: 'exact',
    network: `arc-testnet-${ARC_CHAIN_ID}`,
    payload: {
      signature,
      from:        transferAuth.from,
      to:          transferAuth.to,
      // BigInt → string: JSON.stringify cannot serialize BigInt natively
      value:       transferAuth.value.toString(),
      validAfter:  transferAuth.validAfter.toString(),
      validBefore: transferAuth.validBefore.toString(),
      nonce:       transferAuth.nonce,
    },
  }

  const encodedHeader = Buffer.from(JSON.stringify(paymentPayload)).toString('base64')
  console.log(`   PAYMENT-SIGNATURE: ${encodedHeader.slice(0, 60)}...\n`)

  // ── STEP 6: Retry Request with Payment ──────────────────────────────────
  // Resend the original request, this time attaching the payment proof.
  // We include both header names for spec compatibility:
  //   PAYMENT-SIGNATURE — x402 v2 (current spec)
  //   X-PAYMENT         — x402 v1 (legacy fallback, some servers still check this)
  console.log('📍 STEP 6: Retry request with PAYMENT-SIGNATURE header')
  console.log('   Client sends: GET /api/resource + PAYMENT-SIGNATURE: <base64>\n')

  const secondResponse = mockServer.handle(encodedHeader)
  console.log(`   Server responds: HTTP ${secondResponse.status}`)
  console.log('   Body:', JSON.stringify(secondResponse.body, null, 4)
    .split('\n').map(l => '   ' + l).join('\n'))

  // Final result
  if (secondResponse.status === 200) {
    console.log('\n╔══════════════════════════════════════════════════╗')
    console.log('║  ✅ SUCCESS: Resource unlocked with x402 payment  ║')
    console.log('║  Zero wallet popups after initial session setup.  ║')
    console.log('╚══════════════════════════════════════════════════╝\n')
  } else {
    console.error('\n❌ Payment was rejected. Check the error message above.')
    process.exit(1)
  }
}

runDemo().catch(err => {
  console.error('\n❌ Demo failed:', err)
  process.exit(1)
})
