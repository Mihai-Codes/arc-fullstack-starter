/**
 * sessionKey.example.ts
 * ======================
 * Simplified, heavily-annotated session key implementation.
 *
 * WHAT THIS FILE TEACHES:
 * -----------------------
 *   • Why session keys exist (the wallet-popup problem at scale)
 *   • How to generate a cryptographically secure ephemeral keypair
 *   • The EIP-712 typed data structure for session key authorization
 *   • Why sessionStorage is used instead of localStorage
 *   • How to enforce spending limits and expiry purely in client code
 *   • How to revoke a session key instantly if compromised
 *
 * DESIGN PHILOSOPHY:
 *   Every function in this file is pure or near-pure:
 *   - generateSessionKey()      — pure (no side effects)
 *   - buildSessionAuthMessage() — pure (no side effects)
 *   - saveSessionKey()          — only writes to sessionStorage
 *   - loadSessionKey()          — only reads from sessionStorage
 *   - revokeSessionKey()        — only deletes from sessionStorage
 *   - hasSessionBudget()        — pure check (no writes)
 *   - recordSpend()             — only updates sessionStorage
 *   - generateNonce()           — pure (uses CSPRNG)
 *
 *   This makes the logic easy to test, reason about, and extract
 *   into any framework (React, Vue, vanilla JS, Node.js agents).
 */

import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import type { TypedDataDomain } from 'viem'

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The constraints that a user authorizes for a session key.
 *
 * Concept: This is the "grant" — the set of permissions the user is willing
 * to delegate. Signing this with their main wallet is the ONE required popup.
 * Everything else happens automatically within these bounds.
 */
export type SessionKeyConfig = {
  maxAmountUsdc: number        // total USDC this session can spend, e.g. 5.0
  expirySeconds: number        // lifetime in seconds, e.g. 86400 = 24 hours
  allowedContracts: string[]   // which contract addresses this key can pay
  nonce: string                // random bytes32 hex — prevents replay of the auth itself
}

/**
 * The complete session key artifact stored in sessionStorage.
 *
 * Contains both the sensitive key material (privateKey) and the
 * authorization proof (authorizationSig) that the user signed.
 *
 * Security note: privateKey is stored in sessionStorage, not memory.
 * In a high-security app, you could store it only in memory (a JS closure)
 * and clear it on any navigation event. sessionStorage is a pragmatic
 * balance between security and UX (survives page refreshes within the tab).
 */
export type SessionKey = {
  privateKey: `0x${string}`    // ephemeral secp256k1 private key — keep secret
  address: `0x${string}`       // derived public address — safe to share
  config: SessionKeyConfig     // the spending constraints
  userAddress: `0x${string}`   // the real wallet that authorized this session
  authorizationSig: string     // EIP-712 signature from the user's main wallet
  spentUsdc: number            // running spend total for budget enforcement
  createdAt: number            // unix timestamp (ms) for expiry calculation
}

// Storage key in sessionStorage.
// Using a specific prefix avoids collisions with other app keys.
const STORAGE_KEY = 'x402_session_key'

// ─────────────────────────────────────────────────────────────────────────────
// EIP-712 DOMAIN & TYPES FOR SESSION KEY AUTHORIZATION
// ─────────────────────────────────────────────────────────────────────────────
//
// EIP-712 signs structured data, not raw bytes.
// The domain binds the signature to a specific app + chain,
// preventing a session key authorized for your app from
// being replayed on a different app or a different chain.

const SESSION_AUTH_DOMAIN: TypedDataDomain = {
  name: 'Your App Name',   // replace with your application's name
  version: '1',
  chainId: 5042002,        // Arc Testnet — hardcoded to prevent cross-chain replay
}

// The structured types that define the session key authorization message.
// These must match exactly what your smart contract (if any) or
// server-side verifier expects. Field names and types are both
// included in the EIP-712 type hash.
const SESSION_AUTH_TYPES = {
  SessionKeyAuthorization: [
    { name: 'sessionAddress',   type: 'address' },  // the ephemeral key's address
    { name: 'maxAmountUsdc',    type: 'string'  },  // budget as human-readable string
    { name: 'expiryTimestamp',  type: 'uint256' },  // absolute unix timestamp
    { name: 'nonce',            type: 'bytes32' },  // anti-replay nonce
    { name: 'allowedContracts', type: 'bytes'   },  // packed addresses
  ],
} as const

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a fresh ephemeral secp256k1 keypair.
 *
 * CRYPTOGRAPHIC CONCEPT:
 * secp256k1 is the elliptic curve used by Bitcoin and Ethereum.
 * A private key is a 256-bit integer in the range [1, n-1] where n
 * is the curve's order (~2^256). The public key (and thus the address)
 * is derived deterministically from the private key via point multiplication.
 *
 * viem's generatePrivateKey() uses crypto.getRandomValues() internally —
 * the OS's cryptographically secure pseudo-random number generator (CSPRNG).
 * This is NEVER predictable, unlike Math.random() which is seeded and
 * therefore reproducible by an attacker who knows the seed.
 *
 * @returns privateKey + derived address (safe to share as the "from" address)
 */
export function generateSessionKey(): { privateKey: `0x${string}`; address: `0x${string}` } {
  // generatePrivateKey() samples uniformly from [1, secp256k1.n - 1]
  // using the OS CSPRNG. Retry logic handles the astronomically rare
  // case where the sampled value is 0 or >= n.
  const privateKey = generatePrivateKey()

  // privateKeyToAccount derives the public key via secp256k1 point multiplication,
  // then takes the last 20 bytes of the keccak256 hash to produce the address.
  const account = privateKeyToAccount(privateKey)

  return {
    privateKey,
    address: account.address,
  }
}

/**
 * Build the EIP-712 typed data for the user's main wallet to sign.
 *
 * CRYPTOGRAPHIC CONCEPT:
 * EIP-712 structured data signing prevents two classes of attacks:
 *   1. Phishing: The wallet shows the human-readable field names and
 *      values, not raw hex bytes. Users can see exactly what they sign.
 *   2. Cross-context replay: The domain (name, chainId) is included in
 *      the hash, so a signature for your app cannot be used on
 *      a different app or chain.
 *
 * The produced typed data object is passed directly to wagmi's
 * useSignTypedData hook (or viem's walletClient.signTypedData).
 *
 * @param userAddress     The main wallet address (grants the permission)
 * @param sessionAddress  The ephemeral session key address (receives the permission)
 * @param config          The spending constraints to encode in the signature
 */
export function buildSessionAuthMessage(
  userAddress: string,
  sessionAddress: string,
  config: SessionKeyConfig
) {
  // Budget: convert float USDC to 6-decimal atomic string.
  // We store as a string so it's human-readable in the wallet popup:
  // "maxAmountUsdc: 5000000" is clearer than "5000000n".
  // Note: Math.round avoids floating-point imprecision (0.1 + 0.2 !== 0.3).
  const maxAmountUsdcString = String(Math.round(config.maxAmountUsdc * 1_000_000))

  // Expiry: convert relative seconds to absolute unix timestamp.
  // Absolute timestamps are unambiguous — there's no "relative to what?" question.
  const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + config.expirySeconds)

  // allowedContracts: pack addresses into a single bytes field.
  // This avoids a dynamic array type (which has more complex EIP-712 encoding).
  // Each address is 20 bytes; strip '0x', lowercase, left-pad to 40 hex chars.
  const allowedContractsBytes = ('0x' +
    config.allowedContracts
      .map(addr => addr.replace('0x', '').toLowerCase().padStart(40, '0'))
      .join('')) as `0x${string}`

  return {
    domain: SESSION_AUTH_DOMAIN,
    types: SESSION_AUTH_TYPES,
    primaryType: 'SessionKeyAuthorization' as const,
    message: {
      sessionAddress: sessionAddress as `0x${string}`,
      maxAmountUsdc: maxAmountUsdcString,
      expiryTimestamp,
      nonce: config.nonce as `0x${string}`,
      allowedContracts: allowedContractsBytes,
    },
  }
}

/**
 * Persist the session key to sessionStorage.
 *
 * WHY sessionStorage and not localStorage?
 *
 *   localStorage: persists across tabs AND browser restarts.
 *     If an XSS attack occurs, the private key survives indefinitely.
 *     If the user forgets to log out, the key is exposed forever.
 *
 *   sessionStorage: cleared automatically when the tab closes.
 *     An XSS attack only lasts as long as the tab is open.
 *     The user's session is naturally bounded by their browser session.
 *
 * Trade-off: opening the same site in a new tab requires a new session key.
 * This is acceptable because the setup cost is just a single wallet click.
 *
 * WHY not in-memory only (a JS closure)?
 *   In-memory would be cleared on page refresh, requiring the user to
 *   re-approve on every navigation. sessionStorage survives refreshes
 *   within the same tab, giving a better UX while preserving the
 *   tab-close security guarantee.
 */
export function saveSessionKey(key: SessionKey): void {
  // Guard: sessionStorage is not available in Node.js / SSR contexts.
  if (typeof window === 'undefined') return
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(key))
}

/**
 * Load and validate the session key from sessionStorage.
 *
 * Performs two validity checks before returning:
 *   1. Temporal: is the key within its expiry window?
 *   2. Budget: is there remaining spending capacity?
 *
 * Returns null (not throws) for missing/invalid keys so callers
 * can use a simple null check: `if (!loadSessionKey()) showSetupUI()`
 */
export function loadSessionKey(): SessionKey | null {
  if (typeof window === 'undefined') return null

  const stored = sessionStorage.getItem(STORAGE_KEY)
  if (!stored) return null

  try {
    const key: SessionKey = JSON.parse(stored)

    // Expiry check: createdAt (ms) + expirySeconds (s → ms) vs now (ms)
    const expiresAt = key.createdAt + key.config.expirySeconds * 1000
    if (Date.now() >= expiresAt) {
      // Key has expired — clean it up so we don't accumulate stale state.
      revokeSessionKey()
      return null
    }

    // Budget check: has the user spent everything they authorized?
    if (key.spentUsdc >= key.config.maxAmountUsdc) {
      revokeSessionKey()
      return null
    }

    return key
  } catch {
    // Corrupted storage entry — revoke and return null.
    revokeSessionKey()
    return null
  }
}

/**
 * Immediately delete the session key from storage.
 *
 * REVOCATION SEMANTICS:
 * This is instant and requires no on-chain transaction.
 * After this call, no new EIP-3009 signatures can be generated.
 *
 * The session key's remaining USDC balance is still on-chain.
 * To recover it, the user would need to sign a new transferWithAuthorization
 * from the session key's private key (which they no longer have access to
 * after revocation). This is a known trade-off.
 *
 * For a higher-security implementation, save the private key long enough
 * to drain the balance before revoking. This demo keeps it simple.
 */
export function revokeSessionKey(): void {
  if (typeof window === 'undefined') return
  sessionStorage.removeItem(STORAGE_KEY)
}

/**
 * Check if the current session has enough budget for a payment.
 *
 * Returns false if: no session key, key expired, or spending this amount
 * would exceed the authorized maximum.
 *
 * This is a non-mutating check — it does NOT decrement the budget.
 * Call recordSpend() after a SUCCESSFUL payment to update the budget.
 *
 * @param amountUsdc  The amount to check, in human-readable USDC (e.g. 0.001)
 */
export function hasSessionBudget(amountUsdc: number): boolean {
  const key = loadSessionKey()
  if (!key) return false

  // Check that spending this amount won't exceed the authorized maximum.
  // We compare the SUM (spent + this payment) against the cap,
  // not just the remaining balance, to avoid floating-point edge cases.
  return (key.spentUsdc + amountUsdc) <= key.config.maxAmountUsdc
}

/**
 * Record a successful payment against the session budget.
 *
 * IMPORTANT: Only call this after the server confirms the payment
 * was accepted (HTTP 2xx). Recording spend before confirmation could
 * result in the budget being depleted even if the payment failed.
 *
 * KNOWN LIMITATION (floating-point arithmetic):
 * We store spentUsdc as a JS `number` (IEEE 754 double-precision float).
 * For most micropayment use cases (6 decimal USDC values) this is fine,
 * but floating-point addition is not exact:
 *   0.1 + 0.2 === 0.30000000000000004  // NOT 0.3
 *
 * For a production-grade implementation, track budget in BigInt atomic
 * units (integers, no precision loss) and only convert to `number` for display:
 *   spentAtomic += BigInt(amountAtomic)   // ✅ exact
 *   display = Number(spentAtomic) / 1_000_000  // only for UI
 *
 * This simplified version uses `number` to keep the code readable for learning.
 *
 * @param amountUsdc  The amount that was successfully paid (human-readable USDC)
 */
export function recordSpend(amountUsdc: number): void {
  const key = loadSessionKey()
  if (!key) return

  // Increment the spent counter and persist back to sessionStorage.
  // The next call to loadSessionKey() will see the updated budget.
  key.spentUsdc += amountUsdc
  saveSessionKey(key)
}

/**
 * Generate a cryptographically random bytes32 nonce.
 *
 * CRYPTOGRAPHIC CONCEPT:
 * A nonce (Number used ONCE) prevents replay attacks.
 * In EIP-3009, once an authorization with a specific nonce is consumed,
 * the USDC contract rejects any future authorization with the same nonce.
 *
 * WHY 32 bytes?
 * 32 bytes = 256 bits of entropy = ~1.16 × 10^77 possible values.
 * The probability of two randomly generated nonces colliding is
 * negligible (~birthday problem with 2^128 draws needed for 50% collision).
 *
 * WHY crypto.getRandomValues and not Math.random()?
 * Math.random() uses a deterministic PRNG (pseudo-random, not truly random).
 * Its output can be predicted if an attacker knows the PRNG state.
 * crypto.getRandomValues() uses the OS's hardware entropy source (CSPRNG).
 * It is unpredictable by design.
 */
export function generateNonce(): `0x${string}` {
  const bytes = new Uint8Array(32)

  // Web Crypto API: available in all modern browsers and Node.js 15+.
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    // Fallback for older Node.js (< 15) in server-side rendering contexts.
    const nodeCrypto = require('crypto') as typeof import('crypto')
    const buf = nodeCrypto.randomBytes(32)
    bytes.set(buf)
  }

  // Convert byte array to 0x-prefixed hex string.
  // Each byte becomes 2 hex characters; padStart ensures leading zeros
  // are preserved (e.g., byte value 5 becomes '05', not '5').
  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}` as `0x${string}`
}
