/**
 * SESSION KEYS — THE CONCEPT
 * 
 * Problem: crypto wallets require user approval for 
 * every transaction. For nanopayments ($0.001 per 
 * thesis read), this is unusable — nobody will click
 * "Approve" 50 times per session.
 * 
 * Solution: generate a temporary keypair (session key)
 * and ask the user to sign ONE authorization message
 * that says "this session key can spend up to X USDC
 * on my behalf for the next Y hours."
 * 
 * After that, all micropayments are signed silently
 * by the session key — no wallet popups.
 * 
 * Security: session keys are stored in sessionStorage
 * (cleared when tab closes), have strict spending limits,
 * have expiry timestamps, and can be revoked instantly.
 */

import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import type { TypedDataDomain } from 'viem'

// ─── TYPES & CONFIGS ────────────────────────────────────────────────────────

/**
 * Configuration that restricts the session key's privileges.
 * This is signed by the user's main wallet.
 */
export type SessionKeyConfig = {
  maxAmountUsdc: number        // e.g. 5.0 — max USDC this session can spend total
  expirySeconds: number        // e.g. 86400 — 24 hours
  allowedContracts: string[]   // contract addresses this key can pay
  nonce: string                // random bytes32 hex to prevent replay
}

/**
 * The complete session key artifact.
 * Contains the private key itself, the config, and the user's signature.
 */
export type SessionKey = {
  privateKey: `0x${string}`   // ephemeral private key
  address: `0x${string}`      // derived public address
  config: SessionKeyConfig
  userAddress: `0x${string}`  // the real wallet that authorized it
  authorizationSig: string     // EIP-712 sig from real wallet
  spentUsdc: number            // running total spent this session
  createdAt: number            // unix timestamp (ms)
}

const STORAGE_KEY = 'rosetta_session_key'

// ─── EIP-712 DOMAIN & TYPES ─────────────────────────────────────────────────

const SESSION_AUTH_DOMAIN: TypedDataDomain = {
  name: 'Rosetta Alpha',
  version: '1',
  chainId: 5042002, // Arc Testnet
}

const SESSION_AUTH_TYPES = {
  SessionKeyAuthorization: [
    { name: 'sessionAddress', type: 'address' },
    { name: 'maxAmountUsdc', type: 'string' },
    { name: 'expiryTimestamp', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'allowedContracts', type: 'bytes' },
  ],
} as const

// ─── IMPLEMENTATION ──────────────────────────────────────────────────────────

/**
 * Generate a fresh ephemeral secp256k1 keypair.
 * 
 * Cryptographic principle: Uses high-entropy secure random values (crypto.getRandomValues)
 * to generate a private key, preventing predictable key creation.
 * 
 * @returns An object with the private key and derived address
 * @example
 * const { privateKey, address } = generateSessionKey()
 */
export function generateSessionKey(): { privateKey: `0x${string}`; address: `0x${string}` } {
  // Generate private key securely using viem's secure random generation
  const privateKey = generatePrivateKey()
  const account = privateKeyToAccount(privateKey)

  return {
    privateKey,
    address: account.address,
  }
}

/**
 * Build the EIP-712 typed data for the user's main wallet to sign.
 * 
 * Concept: Translates human-readable conditions (budget, expiry) into 
 * structured typed data conforming to EIP-712.
 * 
 * @param userAddress - The user's main wallet address
 * @param sessionAddress - The ephemeral session key public address
 * @param config - The spending constraints
 * @returns Complete EIP-712 typed data object ready for use with useSignTypedData
 */
export function buildSessionAuthMessage(
  userAddress: string,
  sessionAddress: string,
  config: SessionKeyConfig
) {
  // Convert budget to 6 decimal atomic units (USDC decimals)
  const maxAmountUsdcString = String(Math.round(config.maxAmountUsdc * 1e6))
  const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + config.expirySeconds)

  // Compact array of addresses into a packed bytes hex string
  const allowedContractsBytes = ('0x' +
    config.allowedContracts
      .map((addr) => addr.replace('0x', '').toLowerCase().padStart(40, '0'))
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
 * Persist the active session key to sessionStorage.
 * 
 * Concept: sessionStorage is used instead of localStorage so keys 
 * are automatically wiped when the user closes their browser tab.
 */
export function saveSessionKey(key: SessionKey): void {
  if (typeof window === 'undefined') return
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(key))
}

/**
 * Load and validate the session key from sessionStorage.
 * 
 * Concept: Returns null if no key exists, or if it is expired/exhausted.
 */
export function loadSessionKey(): SessionKey | null {
  if (typeof window === 'undefined') return null

  const stored = sessionStorage.getItem(STORAGE_KEY)
  if (!stored) return null

  try {
    const key: SessionKey = JSON.parse(stored)

    // Check expiry
    const expiresAt = key.createdAt + key.config.expirySeconds * 1000
    if (Date.now() >= expiresAt) {
      revokeSessionKey()
      return null
    }

    // Check budget
    if (key.spentUsdc >= key.config.maxAmountUsdc) {
      revokeSessionKey()
      return null
    }

    return key
  } catch {
    revokeSessionKey()
    return null
  }
}

/**
 * Clear the session key from storage.
 */
export function revokeSessionKey(): void {
  if (typeof window === 'undefined') return
  sessionStorage.removeItem(STORAGE_KEY)
}

/**
 * Check if the active session key has enough remaining budget.
 */
export function hasSessionBudget(amountUsdc: number): boolean {
  const key = loadSessionKey()
  if (!key) return false

  return key.spentUsdc + amountUsdc <= key.config.maxAmountUsdc
}

/**
 * Record a successful payment against the session's budget.
 */
export function recordSpend(amountUsdc: number): void {
  const key = loadSessionKey()
  if (!key) return

  key.spentUsdc += amountUsdc
  saveSessionKey(key)
}

/**
 * Generate a cryptographically random bytes32 nonce.
 */
export function generateNonce(): `0x${string}` {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return ('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')) as `0x${string}`
}
