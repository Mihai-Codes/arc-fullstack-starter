/**
 * x402Server.example.ts
 * =====================
 * Server-side x402 payment middleware for Next.js App Router.
 *
 * WHAT THIS FILE TEACHES:
 * -----------------------
 *   • How to gate any API route behind x402 micropayments
 *   • The server half of the x402 challenge-response handshake
 *   • How to verify an EIP-3009 signature without submitting it
 *   • How to settle payment on-chain via transferWithAuthorization
 *   • The x402 v2 response format (PAYMENT-REQUIRED header + JSON body)
 *   • Off-chain nonce dedup for replay protection (no database required)
 *
 * THE TWO HALVES OF x402:
 *   The client (x402Client.example.ts) handles:  request → 402 → sign → retry
 *   This file handles:                           402 response → verify → settle → 200
 *
 *   Together they form the complete payment loop:
 *
 *   ┌──────────┐  GET /api/premium   ┌──────────────┐
 *   │  Client  │ ──────────────────► │  withX402()  │
 *   │          │ ◄── 402 + accepts ── │  middleware   │
 *   │          │                     └──────┬───────┘
 *   │          │  GET + PAYMENT-SIGNATURE   │
 *   │          │ ──────────────────────────►│
 *   │          │ ◄── 200 + resource ────────│
 *   └──────────┘                           │
 *                                     verify → settle on Arc
 *
 * USAGE IN NEXT.JS APP ROUTER:
 *   // app/api/premium/route.ts
 *   import { withX402 } from '@/lib/x402Server.example'
 *
 *   export const GET = withX402({
 *     resource: '/api/premium',
 *     priceUsdc: 0.001,
 *     description: 'Premium data access',
 *     treasuryAddress: '0xYOUR_TREASURY',
 *     rpcUrl: process.env.ARC_RPC_URL!,
 *     usdcAddress: '0xUSDC_ADDRESS',
 *     settlerPrivateKey: '0xSETTLER_KEY',
 *   }, async (req) => {
 *     return Response.json({ data: 'premium content' })
 *   })
 *
 * x402 v2 SPEC COMPLIANCE:
 *   This implementation follows the x402-foundation/x402 specification v2:
 *   - 402 response body: { x402Version: 2, resource: {...}, accepts: [...] }
 *   - PAYMENT-REQUIRED header: base64-encoded PaymentRequired object
 *   - PAYMENT-SIGNATURE header: client's signed payment payload
 *   - PAYMENT-RESPONSE header: settlement confirmation (tx hash)
 *
 *   Ref: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md
 *   Ref: https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  recoverTypedDataAddress,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import {
  decodePaymentHeader,
  buildTransferAuthorizationMessage,
  type SignedAuthorization,
} from './eip3009.example'

// ─────────────────────────────────────────────────────────────────────────────
// ARC TESTNET CHAIN DEFINITION
// ─────────────────────────────────────────────────────────────────────────────
//
// Defined inline to avoid importing from a chains.ts that might use
// NEXT_PUBLIC_ env vars unavailable in server context (Next.js API routes
// run in Node.js, not the browser).
//
// Why not just hardcode the chain ID? viem's writeContract needs a full
// chain object to construct the JSON-RPC call correctly.

const arcTestnet = {
  id: 5042002,
  name: 'Arc Testnet',
  nativeCurrency: {
    name: 'USDC',
    symbol: 'USDC',
    decimals: 6, // USDC has 6 decimals — NOT 18 (see docs/X402_SESSION_KEYS.md pitfall #1)
  },
  rpcUrls: {
    default: {
      http: ['https://rpc.testnet.arc.network'],
    },
  },
} as const

// ─────────────────────────────────────────────────────────────────────────────
// USDC ABI (MINIMAL — transferWithAuthorization ONLY)
// ─────────────────────────────────────────────────────────────────────────────
//
// This is the ONLY on-chain function the settler wallet calls.
// The signature (v, r, s) was created by the client's session key,
// and the USDC contract verifies it matches the `from` address.
//
// Why inline instead of importing from an ABI file?
// DRY applies to logic, not data. This 9-field ABI is:
//   - Self-contained (no external file to track)
//   - Impossible to get out of sync with the contract
//   - Small enough that a separate file adds more cognitive load than value
//
// Full function signature:
//   transferWithAuthorization(
//     address from,      — who is sending USDC
//     address to,        — who receives USDC (treasury)
//     uint256 value,     — amount in 6-decimal units
//     uint256 validAfter, — earliest valid time (usually 0)
//     uint256 validBefore, — latest valid time (timeout)
//     bytes32 nonce,     — unique nonce (prevents replay)
//     uint8 v,           — signature recovery param
//     bytes32 r,         — ECDSA r component
//     bytes32 s          — ECDSA s component
//   )

const USDC_ABI = [
  {
    name: 'transferWithAuthorization',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
      { name: 'v', type: 'uint8' },
      { name: 'r', type: 'bytes32' },
      { name: 's', type: 'bytes32' },
    ],
    outputs: [],
  },
] as const

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Configuration for a single x402-protected route.
 *
 * Each route defines its own price and treasury. This lets you have
 * different endpoints at different price points:
 *   /api/quote       → priceUsdc: 0.001  (cheap)
 *   /api/full-analysis → priceUsdc: 0.05  (expensive)
 */
export type X402ServerConfig = {
  /** The API route path being protected (e.g. '/api/premium') */
  resource: string
  /** Price in human-readable USDC (e.g. 0.001 = $0.001) */
  priceUsdc: number
  /** Human-readable description shown to client in 402 response */
  description: string
  /** Treasury address where payments are received */
  treasuryAddress: string
  /** Arc Testnet RPC URL for on-chain settlement */
  rpcUrl: string
  /** USDC contract address on Arc */
  usdcAddress: string
  /** Private key of the settler wallet (calls transferWithAuthorization) */
  settlerPrivateKey: string
  /**
   * Whether to submit the EIP-3009 authorization on-chain.
   *
   * For demo/prototype use: set to false to verify the signature without
   * settling on-chain. The payment is "verified offchain" and the resource
   * is returned, but no USDC actually moves.
   *
   * For production: leave as true (or omit — defaults to true).
   */
  settleOnChain?: boolean
}

// ─────────────────────────────────────────────────────────────────────────────
// REPLAY PROTECTION (in-memory, no database)
// ─────────────────────────────────────────────────────────────────────────────
//
// Why a Map instead of a database?
//
// For a starter kit, simplicity wins. An in-memory Map:
//   - Requires zero infrastructure (no PostgreSQL, no Prisma, no Redis)
//   - Is instantly understandable to any developer
//   - Demonstrates the concept without hiding it behind an ORM
//
// TRADE-OFF: In-memory Maps reset on serverless cold starts (Vercel, AWS Lambda).
// In production, you'd persist used nonces to a database (see rosetta-alpha's
// Prisma-based implementation for a real example).
//
// For a single-server deployment (Docker, VPS), the Map persists for the
// lifetime of the process — sufficient for most use cases.

const usedNonces = new Map<string, number>() // nonce → expiryTimestamp (ms)

/**
 * Check if a nonce has already been used in an off-chain-only payment.
 *
 * Returns false for on-chain settlement (the USDC contract tracks nonces).
 * Only needed when settleOnChain=false.
 */
function isNonceUsed(nonce: string): boolean {
  const expiry = usedNonces.get(nonce)
  if (!expiry) return false

  // Clean up expired entries to prevent memory leak
  if (Date.now() > expiry) {
    usedNonces.delete(nonce)
    return false
  }

  return true
}

/**
 * Mark a nonce as used with a TTL based on the authorization's validBefore.
 *
 * The TTL is min(validBefore - now, 5 minutes). We cap at 5 minutes because:
 *   - After validBefore, the authorization is expired anyway
 *   - Capping prevents unbounded memory growth from long-lived nonces
 */
function markNonceUsed(nonce: string, validBeforeMs: number): void {
  const ttl = Math.min(validBeforeMs - Date.now(), 5 * 60 * 1000)
  if (ttl > 0) {
    usedNonces.set(nonce, Date.now() + ttl)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wrap a Next.js App Router route handler with x402 payment gating.
 *
 * This is the main export. It returns a new handler that:
 *   1. Checks for payment header (PAYMENT-SIGNATURE or X-PAYMENT)
 *   2. If missing → returns 402 with payment requirements
 *   3. If present → decodes, verifies, and settles the payment
 *   4. If settlement succeeds → calls your actual route handler
 *
 * DESIGN PATTERN: Higher-Order Function (HOF)
 *   Your handler doesn't know about x402. The middleware wraps it.
 *   This is the same pattern as Express middleware, Next.js middleware,
 *   or React's HOC pattern — separation of concerns.
 *
 * @param config   Payment configuration for this route
 * @param handler  Your actual route handler (called after successful payment)
 * @returns        A new route handler with x402 payment gating
 */
export function withX402(
  config: X402ServerConfig,
  handler: (req: Request) => Promise<Response>
): (req: Request) => Promise<Response> {
  return async (req: Request): Promise<Response> => {
    // ── Step 1: Check for payment header ──────────────────────────────────
    //
    // x402 v2 spec: canonical header is PAYMENT-SIGNATURE
    // x402 v1 (legacy): header was X-PAYMENT
    //
    // We check both for backwards compatibility. Many deployed servers
    // and clients still use X-PAYMENT. The client sends both headers
    // (see x402Client.example.ts step 8), so this covers all cases.
    const paymentHeader =
      req.headers.get('PAYMENT-SIGNATURE') ||
      req.headers.get('payment-signature') ||
      req.headers.get('X-PAYMENT') ||
      req.headers.get('x-payment')

    // ── Step 2: No payment → return 402 with requirements ────────────────
    //
    // This is the "challenge" in the x402 handshake.
    // The response tells the client exactly what payment is required.
    if (!paymentHeader) {
      return buildPaymentRequiredResponse(config)
    }

    // ── Step 3: Decode the payment header ─────────────────────────────────
    //
    // The header is base64-encoded JSON containing the signed authorization.
    // If decoding fails, the header is malformed — reject immediately.
    let signedAuth: SignedAuthorization
    try {
      signedAuth = decodePaymentHeader(paymentHeader)
    } catch {
      return new Response(
        JSON.stringify({
          error: 'Invalid payment header',
          detail: 'Could not decode PAYMENT-SIGNATURE header. Expected base64-encoded JSON.',
          code: 'INVALID_PAYMENT_HEADER',
        }),
        {
          status: 402,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    // ── Step 4: Verify the payment ────────────────────────────────────────
    //
    // Verification checks four things WITHOUT submitting on-chain:
    //   (a) validBefore > now (not expired)
    //   (b) value >= required amount (paying enough)
    //   (c) to === treasuryAddress (paying the right recipient)
    //   (d) ecrecover(signature) === from (valid EIP-3009 signature)
    //
    // These are the same checks the USDC contract performs on-chain,
    // but done server-side to fail fast before paying gas.
    const verification = await verifyPayment(signedAuth, config)
    if (!verification.valid) {
      console.warn(`[x402] Verification failed: ${verification.reason}`)
      return new Response(
        JSON.stringify({
          error: 'Payment verification failed',
          detail: verification.reason,
          code: 'PAYMENT_VERIFICATION_FAILED',
        }),
        {
          status: 402,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    // ── Step 5: Settle the payment ────────────────────────────────────────
    //
    // Settlement executes the transferWithAuthorization on-chain.
    // The settler wallet pays the gas (USDC on Arc — no ETH needed).
    //
    // When settleOnChain=false (demo mode), we skip settlement but still
    // check the in-memory nonce dedup to prevent replay attacks.
    let txHash = 'verified-offchain'
    if (config.settleOnChain !== false) {
      try {
        txHash = await settlePayment(signedAuth, config)
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown settlement error'
        console.error(`[x402] Settlement failed: ${message}`)
        return new Response(
          JSON.stringify({
            error: 'Payment settlement failed',
            detail: 'Settlement transaction failed on-chain',
            code: 'SETTLEMENT_FAILED',
          }),
          {
            status: 402,
            headers: { 'Content-Type': 'application/json' },
          }
        )
      }
    } else {
      // Off-chain only: check nonce dedup to prevent replay
      const nonceHex = signedAuth.nonce.toLowerCase()
      if (isNonceUsed(nonceHex)) {
        return new Response(
          JSON.stringify({
            error: 'Payment already used',
            detail: 'This payment has already been redeemed',
            code: 'PAYMENT_REPLAY_DETECTED',
          }),
          {
            status: 402,
            headers: { 'Content-Type': 'application/json' },
          }
        )
      }
      markNonceUsed(nonceHex, Number(signedAuth.validBefore) * 1000)
    }

    // ── Step 6: Payment valid — call the actual handler ───────────────────
    //
    // The handler doesn't know about x402. It just returns a normal Response.
    // We clone the response to add payment confirmation headers.
    const response = await handler(req)

    // Add x402 settlement proof headers to the response.
    // Clients can use these to verify the payment was settled.
    const headers = new Headers(response.headers)
    headers.set('X-PAYMENT-RESPONSE', txHash)
    headers.set('X-PAYMENT-TX-HASH', txHash)

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT REQUIRED RESPONSE (402)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the 402 response that tells the client how to pay.
 *
 * x402 v2 format:
 *   Body: { x402Version: 2, resource: {...}, accepts: [...] }
 *   Header: PAYMENT-REQUIRED = base64(body)
 *
 * The client reads this, picks a compatible payment option, signs
 * an EIP-3009 authorization, and retries with the PAYMENT-SIGNATURE header.
 *
 * WHY BOTH body AND header?
 *   - The JSON body is for human-readable debugging (curl, browser devtools)
 *   - The base64 header is the spec-compliant machine-readable format
 *   - x402 v2 clients read the header; older clients read the body
 */
function buildPaymentRequiredResponse(config: X402ServerConfig): Response {
  const body = {
    x402Version: 2,
    resource: {
      url: config.resource,
      description: config.description,
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: 'exact',
        // CAIP-2 network identifier for Arc Testnet
        // Ref: https://github.com/ChainAgnostic/namespaces/blob/main/CAIPs/caip-2.md
        network: 'eip155:5042002',
        // Amount in atomic units (6 decimals for USDC)
        // priceUsdc=0.001 → "1000", priceUsdc=5.0 → "5000000"
        amount: String(Math.round(config.priceUsdc * 1e6)),
        // USDC contract address on Arc Testnet
        asset: config.usdcAddress,
        payTo: config.treasuryAddress,
        maxTimeoutSeconds: 300, // 5 minutes to submit payment
        extra: {
          // EIP-712 domain info — helps the client build the correct signature
          // These MUST match the USDC contract's domain separator:
          //   name: 'USD Coin' (NOT 'USDC' — see docs/X402_SESSION_KEYS.md pitfall #3)
          //   version: '2'
          name: 'USD Coin',
          version: '2',
        },
      },
    ],
  }

  return new Response(JSON.stringify(body), {
    status: 402,
    statusText: 'Payment Required',
    headers: {
      'Content-Type': 'application/json',
      // x402 v2: PAYMENT-REQUIRED header is the canonical machine-readable format
      'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(body)).toString('base64'),
    },
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a signed payment authorization without executing it on-chain.
 *
 * This is the server's "pre-flight check" — catching invalid payments
 * before paying gas for a doomed transaction.
 *
 * Checks performed:
 *   (a) validBefore > now       — authorization not expired
 *   (b) value >= required       — paying enough
 *   (c) to === treasuryAddress  — paying the right recipient
 *   (d) ecrecover(sig) === from — valid EIP-3009 signature
 *
 * CHECK (d) IS THE CRITICAL ONE:
 *   The USDC contract requires ecrecover(signature) == authorization.from.
 *   If the session key that signed doesn't match the `from` address,
 *   the on-chain call reverts. We check this server-side to fail fast.
 *
 * @returns { valid: true, signer } or { valid: false, reason }
 */
async function verifyPayment(
  signedAuth: SignedAuthorization,
  config: X402ServerConfig
): Promise<{ valid: boolean; reason?: string; signer?: `0x${string}` }> {
  // ── Check (a): Not expired ──────────────────────────────────────────────
  const nowSeconds = BigInt(Math.floor(Date.now() / 1000))
  if (signedAuth.validBefore <= nowSeconds) {
    return {
      valid: false,
      reason: `Payment authorization expired. validBefore=${signedAuth.validBefore}, now=${nowSeconds}`,
    }
  }

  // ── Check (b): Sufficient amount ────────────────────────────────────────
  const requiredAmount = BigInt(Math.round(config.priceUsdc * 1e6))
  if (signedAuth.value < requiredAmount) {
    return {
      valid: false,
      reason: `Insufficient payment. Required: ${requiredAmount}, received: ${signedAuth.value}`,
    }
  }

  // ── Check (c): Correct recipient ────────────────────────────────────────
  if (signedAuth.to.toLowerCase() !== config.treasuryAddress.toLowerCase()) {
    return {
      valid: false,
      reason: `Wrong recipient. Expected: ${config.treasuryAddress}, got: ${signedAuth.to}`,
    }
  }

  // ── Check (d): Recover and verify signer from EIP-712 signature ─────────
  //
  // CRYPTOGRAPHIC CONCEPT:
  //   EIP-712 signatures are over structured data (domain + types + message).
  //   The `recoverTypedDataAddress` function performs ecrecover on the hash
  //   of the typed data, returning the address that produced the signature.
  //
  //   If the recovered address doesn't match `authorization.from`, the
  //   signature was produced by a different key — either a forger or a
  //   domain mismatch (wrong chainId, wrong USDC contract address, etc.)
  try {
    const typedData = buildTransferAuthorizationMessage(
      {
        from: signedAuth.from,
        to: signedAuth.to,
        value: signedAuth.value,
        validAfter: signedAuth.validAfter,
        validBefore: signedAuth.validBefore,
        nonce: signedAuth.nonce,
      },
      config.usdcAddress
    )

    const recoveredAddress = await recoverTypedDataAddress({
      domain: typedData.domain,
      types: typedData.types,
      primaryType: typedData.primaryType,
      message: typedData.message,
      signature: signedAuth.signature,
    })

    if (!recoveredAddress) {
      return { valid: false, reason: 'Could not recover signer from signature' }
    }

    // EIP-3009 invariant: ecrecover(sig) MUST equal authorization.from
    if (recoveredAddress.toLowerCase() !== signedAuth.from.toLowerCase()) {
      return {
        valid: false,
        reason: `Signer mismatch. Recovered: ${recoveredAddress}, expected (from): ${signedAuth.from}. ` +
          `EIP-3009 requires the signer to be the 'from' address.`,
      }
    }

    return { valid: true, signer: recoveredAddress }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Signature verification error'
    return { valid: false, reason: `Signature verification failed: ${message}` }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ON-CHAIN SETTLEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute transferWithAuthorization on Arc to settle the payment.
 *
 * This is where the actual USDC transfer happens:
 *   1. The settler wallet (server-controlled) submits the transaction
 *   2. The USDC contract verifies the EIP-712 signature matches `from`
 *   3. If valid, USDC moves from `from` to `to`
 *   4. The settler pays the gas (USDC on Arc — no ETH needed)
 *
 * THE SETTLER WALLET:
 *   - Needs a small USDC balance for gas on Arc (~0.01 USDC is plenty)
 *   - Holds the private key in settlerPrivateKey config
 *   - Does NOT hold the user's USDC (the user funds the session key)
 *   - Signs transactions but never controls user funds
 *
 * @param signedAuth  The verified signed authorization
 * @param config      Server config with RPC URL and settler key
 * @returns           Transaction hash of the settlement
 */
async function settlePayment(
  signedAuth: SignedAuthorization,
  config: X402ServerConfig
): Promise<string> {
  const chain = {
    ...arcTestnet,
    rpcUrls: {
      default: { http: [config.rpcUrl] },
    },
  }

  // Public client: read-only, used to wait for transaction receipt
  const publicClient = createPublicClient({
    chain,
    transport: http(config.rpcUrl),
  })

  // Wallet client: signs and submits the transaction
  const settlerAccount = privateKeyToAccount(config.settlerPrivateKey as `0x${string}`)
  const walletClient = createWalletClient({
    account: settlerAccount,
    chain,
    transport: http(config.rpcUrl),
  })

  // Execute transferWithAuthorization on the USDC contract
  //
  // This is the EIP-3009 call that moves USDC using the signed authorization.
  // The settler wallet submits the tx, but the authorization came from the
  // session key. The USDC contract verifies the signature matches `from`.
  const txHash = await walletClient.writeContract({
    address: config.usdcAddress as `0x${string}`,
    abi: USDC_ABI,
    functionName: 'transferWithAuthorization',
    args: [
      signedAuth.from,          // from: session key that holds USDC
      signedAuth.to,            // to: treasury address
      signedAuth.value,         // value: amount in 6-decimal units
      signedAuth.validAfter,    // validAfter: earliest valid time
      signedAuth.validBefore,   // validBefore: latest valid time
      signedAuth.nonce,         // nonce: unique bytes32
      signedAuth.v,             // v: signature recovery param
      signedAuth.r,             // r: ECDSA r component
      signedAuth.s,             // s: ECDSA s component
    ],
  })

  // Wait for 1 block confirmation before returning.
  // This ensures the payment is settled before the client receives the resource.
  // On Arc (~1s block time), this adds minimal latency.
  await publicClient.waitForTransactionReceipt({
    hash: txHash,
    confirmations: 1,
  })

  return txHash
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

export { USDC_ABI }
export type { SignedAuthorization }

/**
 * Reset the in-memory nonce dedup store.
 * Exported for testing only — not needed in production.
 */
export function _resetNonceStore(): void {
  usedNonces.clear()
}
