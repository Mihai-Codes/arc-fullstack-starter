/**
 * session-key.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests for session key generation, persistence, and lifecycle management.
 *
 * Environment: jsdom (set via vitest.config.ts) — required for sessionStorage.
 *
 * WHAT THIS TESTS:
 *   - Cryptographic uniqueness of generated keypairs
 *   - Correct key format (Ethereum address + 32-byte private key)
 *   - CSPRNG usage (never Math.random)
 *   - sessionStorage round-trip (save → load)
 *   - Expiry enforcement
 *   - Budget enforcement
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'
import {
  generateSessionKey,
  saveSessionKey,
  loadSessionKey,
  revokeSessionKey,
  hasSessionBudget,
} from '../frontend/src/lib/sessionKey.example'
import type { SessionKey } from '../frontend/src/lib/sessionKey.example'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeSessionKey(overrides: Partial<SessionKey> = {}): SessionKey {
  const { privateKey, address } = generateSessionKey()
  return {
    privateKey,
    address,
    config: {
      maxAmountUsdc: 5,
      expirySeconds: 86400,
      allowedContracts: ['0x1234567890123456789012345678901234567890'],
      nonce: '0xabcdef',
    },
    userAddress: '0x0000000000000000000000000000000000000001' as `0x${string}`,
    authorizationSig: '0xsig',
    spentUsdc: 0,
    createdAt: Date.now(),
    ...overrides,
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  // Clear sessionStorage before each test to prevent state leakage
  if (typeof window !== 'undefined') {
    sessionStorage.clear()
  }
})

// ─── Key generation ───────────────────────────────────────────────────────────

describe('generateSessionKey', () => {
  test('generates unique keypairs', () => {
    const key1 = generateSessionKey()
    const key2 = generateSessionKey()
    expect(key1.privateKey).not.toBe(key2.privateKey)
    expect(key1.address).not.toBe(key2.address)
  })

  test('generated address is valid Ethereum address', () => {
    const { address } = generateSessionKey()
    // EIP-55: 0x prefix + 40 hex chars (case-insensitive)
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/)
  })

  test('private key is valid 32-byte hex', () => {
    const { privateKey } = generateSessionKey()
    // 0x prefix + 64 hex chars = 32 bytes = 256 bits (secp256k1 key size)
    expect(privateKey).toMatch(/^0x[0-9a-fA-F]{64}$/)
  })

  test('does not use Math.random — uses CSPRNG', () => {
    // Math.random() is a deterministic PRNG seeded from a small entropy pool.
    // An attacker who knows the JS engine's PRNG state can predict future values.
    // generateSessionKey() must use crypto.getRandomValues() (the OS CSPRNG) instead.
    const spy = vi.spyOn(Math, 'random')
    generateSessionKey()
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })

  test('returns address derived from private key (deterministic derivation)', () => {
    // Given the same private key, privateKeyToAccount always produces the same address.
    // This verifies internal consistency (address matches private key).
    const { privateKey, address } = generateSessionKey()
    const { privateKeyToAccount } = require('viem/accounts')
    const account = privateKeyToAccount(privateKey)
    expect(account.address.toLowerCase()).toBe(address.toLowerCase())
  })
})

// ─── Save / Load round-trip ───────────────────────────────────────────────────

describe('saveSessionKey + loadSessionKey', () => {
  test('save and load round-trips correctly', () => {
    const key = makeSessionKey({ config: { maxAmountUsdc: 5, expirySeconds: 86400, allowedContracts: ['0x1234'], nonce: '0xabcd' } })
    saveSessionKey(key)
    const loaded = loadSessionKey()
    expect(loaded?.address).toBe(key.address)
    expect(loaded?.config.maxAmountUsdc).toBe(5)
  })

  test('private key survives round-trip intact', () => {
    const key = makeSessionKey()
    saveSessionKey(key)
    const loaded = loadSessionKey()
    expect(loaded?.privateKey).toBe(key.privateKey)
  })

  test('returns null when sessionStorage is empty', () => {
    expect(loadSessionKey()).toBeNull()
  })

  test('returns null for corrupted storage entry', () => {
    sessionStorage.setItem('x402_session_key', 'not-valid-json{{{')
    expect(loadSessionKey()).toBeNull()
  })

  test('cleans up corrupted entry on load', () => {
    sessionStorage.setItem('x402_session_key', 'corrupt')
    loadSessionKey()
    expect(sessionStorage.getItem('x402_session_key')).toBeNull()
  })
})

// ─── Expiry enforcement ───────────────────────────────────────────────────────

describe('expiry enforcement', () => {
  test('expired session key returns null on load', () => {
    const key = makeSessionKey({
      config: { maxAmountUsdc: 5, expirySeconds: 1, allowedContracts: [], nonce: '0x' },
      createdAt: Date.now() - 2000, // created 2s ago, expires after 1s → already expired
    })
    saveSessionKey(key)
    const loaded = loadSessionKey()
    expect(loaded).toBeNull()
  })

  test('expired key is removed from sessionStorage on load', () => {
    const key = makeSessionKey({
      config: { maxAmountUsdc: 5, expirySeconds: 1, allowedContracts: [], nonce: '0x' },
      createdAt: Date.now() - 2000,
    })
    saveSessionKey(key)
    loadSessionKey()
    expect(sessionStorage.getItem('x402_session_key')).toBeNull()
  })

  test('non-expired key is returned successfully', () => {
    const key = makeSessionKey({
      config: { maxAmountUsdc: 5, expirySeconds: 86400, allowedContracts: [], nonce: '0x' },
      createdAt: Date.now(),
    })
    saveSessionKey(key)
    expect(loadSessionKey()).not.toBeNull()
  })
})

// ─── Budget enforcement ───────────────────────────────────────────────────────

describe('hasSessionBudget', () => {
  test('returns false when no session key exists', () => {
    expect(hasSessionBudget(0.5)).toBe(false)
  })

  test('budget check works correctly near boundary', () => {
    const key = makeSessionKey({ spentUsdc: 4.5, config: { maxAmountUsdc: 5, expirySeconds: 86400, allowedContracts: [], nonce: '0x' } })
    saveSessionKey(key)
    expect(hasSessionBudget(0.4)).toBe(true)   // 4.5 + 0.4 = 4.9 ≤ 5
    expect(hasSessionBudget(0.5)).toBe(true)   // 4.5 + 0.5 = 5.0 ≤ 5 (at limit)
    expect(hasSessionBudget(0.6)).toBe(false)  // 4.5 + 0.6 = 5.1 > 5
  })

  test('returns false when budget is fully spent', () => {
    const key = makeSessionKey({ spentUsdc: 5.0, config: { maxAmountUsdc: 5, expirySeconds: 86400, allowedContracts: [], nonce: '0x' } })
    saveSessionKey(key)
    // Budget check should trigger revocation
    expect(hasSessionBudget(0.001)).toBe(false)
  })

  test('hasSessionBudget is non-mutating (does not decrement)', () => {
    const key = makeSessionKey({ spentUsdc: 1.0, config: { maxAmountUsdc: 5, expirySeconds: 86400, allowedContracts: [], nonce: '0x' } })
    saveSessionKey(key)
    hasSessionBudget(0.5)
    hasSessionBudget(0.5)
    const loaded = loadSessionKey()
    // spentUsdc must still be 1.0 — hasSessionBudget must not mutate
    expect(loaded?.spentUsdc).toBe(1.0)
  })
})

// ─── Revocation ───────────────────────────────────────────────────────────────

describe('revokeSessionKey', () => {
  test('removes key from sessionStorage', () => {
    saveSessionKey(makeSessionKey())
    expect(loadSessionKey()).not.toBeNull()
    revokeSessionKey()
    expect(loadSessionKey()).toBeNull()
  })

  test('is idempotent (safe to call when no key exists)', () => {
    expect(() => revokeSessionKey()).not.toThrow()
    expect(() => revokeSessionKey()).not.toThrow()
  })
})
