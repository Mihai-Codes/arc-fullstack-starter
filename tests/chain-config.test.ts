/**
 * chain-config.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests that the Arc Testnet chain config is correct.
 *
 * WHY THESE TESTS MATTER:
 *   The chain config is the single most copy-paste-error-prone file in any
 *   Web3 starter kit. A wrong chain ID silently routes transactions to the
 *   wrong network; a wrong decimal count corrupts every USDC value display.
 *
 *   These tests are intentionally minimal and fast (no network calls) —
 *   they are pure config validation. Run them in CI before deploying.
 */

import { describe, test, expect } from 'vitest'
import { arcTestnet } from '../frontend/src/lib/wagmi'

describe('Arc Testnet Chain Config', () => {
  test('chain ID is correct', () => {
    expect(arcTestnet.id).toBe(5042002)
  })

  test('native currency is USDC with 6 decimals', () => {
    expect(arcTestnet.nativeCurrency.symbol).toBe('USDC')
    expect(arcTestnet.nativeCurrency.decimals).toBe(6)
    // THIS IS THE CRITICAL TEST — 18 would be wrong and silently corrupt all balances
    expect(arcTestnet.nativeCurrency.decimals).not.toBe(18)
  })

  test('has all fields required for wallet_addEthereumChain', () => {
    // These fields are required by the EIP-3085 wallet_addEthereumChain spec
    expect(arcTestnet.name).toBeDefined()
    expect(arcTestnet.rpcUrls.default.http).toBeDefined()
    expect(arcTestnet.rpcUrls.default.http.length).toBeGreaterThan(0)
    expect(arcTestnet.blockExplorers?.default.url).toBeDefined()
    expect(arcTestnet.testnet).toBe(true)
  })

  test('RPC URL format is valid', () => {
    const rpcUrl = arcTestnet.rpcUrls.default.http[0]
    expect(rpcUrl).toMatch(/^https?:\/\//)
  })

  test('block explorer points to arcscan', () => {
    const explorerUrl = arcTestnet.blockExplorers?.default.url
    expect(explorerUrl).toContain('arcscan')
  })

  test('native currency name is USD Coin (required for EIP-712 domain)', () => {
    // The nativeCurrency name must match USDC's EIP-712 domain name.
    // If you use 'USDC' here it DOES NOT break the chain config, but
    // it's a common source of confusion — keep it consistent with eip3009.example.ts
    expect(arcTestnet.nativeCurrency.name).toBe('USD Coin')
  })
})
