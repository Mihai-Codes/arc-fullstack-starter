/**
 * x402Client.example.ts
 * =====================
 * A simplified, heavily-annotated x402 fetch wrapper.
 *
 * WHAT THIS FILE TEACHES:
 * -----------------------
 *   • What HTTP 402 "Payment Required" means and how to handle it
 *   • The challenge-response pattern: request → 402 → pay → retry
 *   • How to parse a machine-readable payment requirement from JSON
 *   • How to build, sign, and attach a payment header before retrying
 *   • Why we need two header names (PAYMENT-SIGNATURE + X-PAYMENT)
 *   • A typed error taxonomy so callers handle payment failures precisely
 *
 * USAGE EXAMPLE:
 * --------------
 * ```typescript
 * import { createX402Client, X402SessionRequired } from './x402Client.example'
 *
 * // Instantiate once at app startup (or in a React context provider).
 * const x402 = createX402Client({
 *   usdcAddress: process.env.NEXT_PUBLIC_USDC_ARC_ADDRESS!
 * })
 *
 * // Use exactly like window.fetch — the 402 dance is transparent.
 * try {
 *   const response = await x402.fetch('/api/thesis/abc123')
 *   const data = await response.json()
 * } catch (err) {
 *   if (err instanceof X402SessionRequired) {
 *     // No active session key — prompt user to approve one.
 *     showSessionApprovalModal(err.requirement)
 *   }
 * }
 * ```
 *
 * SIMPLIFIED vs PRODUCTION:
 *   This file intentionally omits retry logic, multi-scheme selection,
 *   and telemetry to keep the core x402 flow visible. The production
 *   version in rosetta-alpha adds those layers on top.
 */

import { loadSessionKey, hasSessionBudget, recordSpend, generateNonce } from './sessionKey.example'
import { signTransferAuthorization, encodePaymentHeader, type TransferAuthorization } from './eip3009.example'

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Configuration passed when creating the x402 client.
 *
 * Only the USDC contract address is needed here — everything else
 * (amount, recipient, timeout) is negotiated dynamically from each
 * server's 402 response. This makes the client chain-agnostic.
 */
export type X402ClientConfig = {
  usdcAddress: string   // USDC contract address on Arc (6 decimals)
}

/**
 * The machine-readable payment requirement inside a 402 response body.
 *
 * Design principle: The server is an "auction house" — it publishes
 * what it accepts and the client decides whether to pay. Neither party
 * needs to know each other in advance. Any x402 client can pay any
 * x402 server as long as they agree on the scheme.
 */
export type PaymentRequirement = {
  scheme: string               // e.g. "exact" — pay this exact amount
  network: string              // e.g. "arc-testnet-5042002"
  maxAmountRequired: string    // USDC atomic units as string, e.g. "1000" = $0.001
  payTo: string                // treasury wallet that receives payment
  maxTimeoutSeconds: number    // validBefore must be within this window
  asset: string                // USDC contract address (validate this matches your config)
}

// ─────────────────────────────────────────────────────────────────────────────
// CUSTOM ERRORS
// Typed errors let callers handle payment failures precisely, not generically.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Thrown when no active session key exists in sessionStorage.
 *
 * Why a typed error? The caller needs to distinguish between:
 *   (a) "no session key" → show approval UI
 *   (b) "insufficient budget" → show top-up UI
 *   (c) "payment rejected" → show retry/error UI
 *
 * Contains the requirement so the UI can display the exact cost:
 * "Approve up to $0.05 USDC to continue reading."
 */
export class X402SessionRequired extends Error {
  constructor(public requirement: PaymentRequirement) {
    super('x402: No active session key. User must approve one first.')
    this.name = 'X402SessionRequired'
  }
}

/**
 * Thrown when a session key exists but has insufficient remaining budget.
 *
 * This is recoverable — the user can create a new session key with a
 * higher budget. Contains both amounts so the UI can be specific:
 * "You need $0.001 but only $0.0003 remains in this session."
 */
export class X402InsufficientBudget extends Error {
  constructor(public required: number, public available: number) {
    super(
      `x402: Insufficient budget. ` +
      `Need ${required} USDC, only ${available} USDC remaining in session.`
    )
    this.name = 'X402InsufficientBudget'
  }
}

/**
 * Thrown when the server rejects the payment we submitted.
 *
 * Common causes:
 *   - Wrong EIP-712 domain name ('USDC' instead of 'USD Coin')
 *   - Nonce already used (replay attempt detected)
 *   - validBefore already passed by the time server settled
 *   - Signature from wrong key (session key doesn't match 'from')
 */
export class X402PaymentFailed extends Error {
  constructor(public status: number) {
    super(`x402: Server rejected payment (HTTP ${status}). Check signature and domain.`)
    this.name = 'X402PaymentFailed'
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create an x402-aware fetch wrapper.
 *
 * Design pattern: "Decorator"
 * Wraps native fetch with transparent payment handling. Callers use the
 * same API as window.fetch — they don't need to know the 402 handshake
 * is happening underneath.
 *
 * @param config  Global configuration (USDC contract address)
 * @returns       Object with a `fetch` method that handles 402 automatically
 */
export function createX402Client(config: X402ClientConfig) {

  // Capture native fetch before any potential override.
  // This prevents infinite recursion if this wrapper replaces globalThis.fetch.
  const nativeFetch = globalThis.fetch

  return {

    /**
     * Drop-in replacement for fetch() that handles x402 transparently.
     *
     * The full flow:
     *   1. Make the original request (may return 402)
     *   2. If 402: parse payment requirements from response body
     *   3. Load session key from sessionStorage
     *   4. Check budget: will this exceed the session spending cap?
     *   5. Build an EIP-3009 transfer authorization
     *   6. Sign it with the session key's private key (in-memory, no popup)
     *   7. Encode the signature into a base64 HTTP header
     *   8. Retry the original request with PAYMENT-SIGNATURE header
     *   9. On success, decrement the session budget by the paid amount
     *
     * @param url      Target URL (same signature as native fetch)
     * @param options  Fetch options: method, headers, body (same as native fetch)
     */
    async fetch(url: string, options?: RequestInit): Promise<Response> {

      // ── Step 1: Initial Request ────────────────────────────────────────
      // Make the call exactly as the caller intended.
      // If the server doesn't require payment, we return immediately.
      // This wrapper adds ZERO overhead on non-x402 endpoints.
      const initialResponse = await nativeFetch(url, options)

      // Fast path: anything other than 402 → return as-is.
      // This includes 200 (success), 401 (auth), 403 (forbidden), etc.
      if (initialResponse.status !== 402) {
        return initialResponse
      }

      // ── Step 2: Parse the 402 Challenge ───────────────────────────────
      // The server's 402 body is machine-readable JSON describing exactly
      // what payment it requires. This is the "challenge" in the handshake.
      //
      // `accepts` is an array: the server may accept multiple payment
      // schemes or networks. We take the first one (simplification).
      // A production client would find the best matching scheme.
      const body = await initialResponse.json() as { accepts?: PaymentRequirement[] }
      const requirement = body.accepts?.[0]

      if (!requirement) {
        // Malformed 402: server returned the status but no requirements.
        // This is a server-side bug — we can't proceed without knowing what to pay.
        throw new Error('x402: Server returned 402 with no payment requirements in body.')
      }

      // ── Step 3: Load the Session Key ──────────────────────────────────
      // The session key is an ephemeral wallet stored in sessionStorage.
      // It holds pre-funded USDC and signs EIP-3009 authorizations silently.
      // loadSessionKey() returns null if: no key, key expired, or budget exhausted.
      const sessionKey = loadSessionKey()

      if (!sessionKey) {
        // Throw X402SessionRequired (not a generic Error) so callers can
        // detect this specific case and show the approval UI.
        throw new X402SessionRequired(requirement)
      }

      // ── Step 4: Budget Check ──────────────────────────────────────────
      // Convert the server's atomic units to a human-readable USDC float.
      // CRITICAL: USDC has 6 decimals on Arc. Divide by 1_000_000, NOT 1e18.
      // Using 1e18 here would accept payments ~10^12x larger than intended.
      const amountUsdc = Number(requirement.maxAmountRequired) / 1_000_000

      if (!hasSessionBudget(amountUsdc)) {
        const available = sessionKey.config.maxAmountUsdc - sessionKey.spentUsdc
        throw new X402InsufficientBudget(amountUsdc, available)
      }

      // ── Step 5: Build EIP-3009 Transfer Authorization ─────────────────
      // We construct the parameters for a transferWithAuthorization call.
      // This is NOT a transaction — it's a signed message. The server's
      // settler wallet will submit the actual on-chain transaction.
      //
      // KEY CONSTRAINT (EIP-3009 spec):
      //   ecrecover(signature) MUST equal auth.from
      // The private key that signs must control the 'from' address.
      // Since the session key IS the 'from' address (and holds the USDC),
      // this constraint is always satisfied in our architecture.
      const transferAuth: TransferAuthorization = {
        from: sessionKey.address,                       // session key = USDC source
        to: requirement.payTo as `0x${string}`,         // treasury from the 402 body
        value: BigInt(requirement.maxAmountRequired),   // atomic units (6 decimals)
        validAfter: BigInt(0),                          // valid immediately after signing
        // validBefore: DERIVE from server's timeout — never hardcode or use 0.
        // The USDC contract checks block.timestamp < validBefore on-chain.
        // Using 0n = "already expired" = immediate rejection.
        validBefore: BigInt(
          Math.floor(Date.now() / 1000) + requirement.maxTimeoutSeconds
        ),
        // nonce: cryptographically random bytes32 per authorization.
        // The USDC contract rejects any auth whose nonce was already used.
        // This prevents replay attacks: a captured header cannot be reused.
        nonce: generateNonce(),
      }

      // ── Step 6: Sign the Authorization ────────────────────────────────
      // The session key signs the EIP-712 typed data in-memory.
      // This produces a 65-byte secp256k1 ECDSA signature.
      // No wallet popup. No network call. Completes in ~1ms.
      const signed = await signTransferAuthorization(
        transferAuth,
        sessionKey,
        config.usdcAddress
      )

      // ── Step 7: Encode Payment Header ─────────────────────────────────
      // Serialize the signed authorization as JSON, then base64-encode it.
      // Base64 is required because HTTP headers cannot contain raw binary
      // or arbitrary special characters.
      const headerValue = encodePaymentHeader(signed)

      // ── Step 8: Retry with Payment ────────────────────────────────────
      // Re-send the original request with the payment proof attached.
      // We include two header names for backwards compatibility:
      //   PAYMENT-SIGNATURE — x402 v2 spec (current standard)
      //   X-PAYMENT         — x402 v1 spec (legacy fallback)
      // Some deployed servers still check X-PAYMENT; including both
      // ensures compatibility without extra round-trips.
      const paidResponse = await nativeFetch(url, {
        ...options,
        headers: {
          ...options?.headers,
          'PAYMENT-SIGNATURE': headerValue,  // x402 v2 primary header
          'X-PAYMENT': headerValue,          // x402 v1 fallback header
        }
      })

      // ── Step 9: Accounting + Return ───────────────────────────────────
      if (paidResponse.status >= 200 && paidResponse.status < 300) {
        // Payment accepted and resource returned.
        // Decrement the session budget so we don't overspend.
        // This runs client-side as a soft cap; the server enforces
        // the hard cap by rejecting invalid/expired authorizations.
        recordSpend(amountUsdc)
        return paidResponse
      }

      // Payment was rejected. Throw typed error with the status code.
      // Debugging guide:
      //   402 on retry  → signature invalid (wrong domain? wrong key?)
      //   402 on retry  → nonce already used (replay detected)
      //   402 on retry  → validBefore already passed
      //   500           → settler failed to submit on-chain
      throw new X402PaymentFailed(paidResponse.status)
    }

  }
}
