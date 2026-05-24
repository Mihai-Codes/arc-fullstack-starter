/**
 * eip3009.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests for EIP-712 message building for EIP-3009 transferWithAuthorization.
 *
 * Scope: Pure message construction — no signing (signing requires a real
 * private key and async runtime, tested separately via integration tests).
 *
 * WHY THESE TESTS MATTER:
 *   EIP-712 domain fields must match EXACTLY what the USDC contract expects.
 *   A single wrong character in `name` or a wrong `version` means every
 *   signature will be invalid — the contract will silently reject them.
 *
 *   "USD Coin" vs "USDC": the USDC contract on Arc uses "USD Coin".
 *   Developers copy-pasting from Ethereum mainnet tutorials often use "USDC"
 *   and spend hours debugging why signatures fail. This test catches that.
 */

import { describe, test, expect } from 'vitest'
import { buildTransferAuthorizationMessage } from '../frontend/src/lib/eip3009.example'
import type { TransferAuthorization } from '../frontend/src/lib/eip3009.example'

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const MOCK_USDC_ADDRESS = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'

const MOCK_AUTH: TransferAuthorization = {
  from: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as `0x${string}`,
  to:   '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as `0x${string}`,
  value: 500000n,                                    // 0.5 USDC (6 decimals)
  validAfter: 0n,
  validBefore: BigInt(Math.floor(Date.now() / 1000) + 300), // 5 min window
  nonce: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab' as `0x${string}`,
}

// ─── Domain tests ─────────────────────────────────────────────────────────────

describe('EIP-712 domain', () => {
  test('builds correct EIP-712 domain', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.domain.name).toBe('USD Coin')
    expect(msg.domain.version).toBe('2')
    expect(msg.domain.chainId).toBe(5042002)
    expect(msg.domain.verifyingContract).toBe(MOCK_USDC_ADDRESS)
  })

  test('domain name is "USD Coin" not "USDC"', () => {
    // CRITICAL: wrong name breaks signature verification on Arc.
    // The USDC contract verifies the domain hash includes the exact name bytes.
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.domain.name).toBe('USD Coin')
    expect(msg.domain.name).not.toBe('USDC')
    expect(msg.domain.name).not.toBe('USDCoin')
    expect(msg.domain.name).not.toBe('usd coin') // case-sensitive
  })

  test('version is "2" not "1"', () => {
    // USDC on most EVM chains (including Arc) uses version "2".
    // Using "1" produces a different domain separator hash → invalid sig.
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.domain.version).toBe('2')
    expect(msg.domain.version).not.toBe('1')
  })

  test('chainId is Arc Testnet (5042002)', () => {
    // The domain chainId prevents cross-chain replay attacks.
    // A signature produced for Arc cannot be replayed on Ethereum mainnet (chainId 1).
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.domain.chainId).toBe(5042002)
    expect(msg.domain.chainId).not.toBe(1)    // not mainnet
    expect(msg.domain.chainId).not.toBe(137)  // not Polygon
  })

  test('verifyingContract matches the USDC address passed in', () => {
    // The verifyingContract binds the signature to a specific token contract.
    // Using a different USDC address (e.g., a fake) would produce a valid sig
    // for that fake contract, not the real one.
    const customUsdcAddress = '0x1111111111111111111111111111111111111111'
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, customUsdcAddress)
    expect(msg.domain.verifyingContract).toBe(customUsdcAddress)
  })
})

// ─── Type structure tests ─────────────────────────────────────────────────────

describe('EIP-712 types', () => {
  test('primaryType is TransferWithAuthorization', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.primaryType).toBe('TransferWithAuthorization')
  })

  test('includes all required type fields', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    const typeFields = msg.types.TransferWithAuthorization.map((f: { name: string; type: string }) => f.name)

    // All 6 fields are required by the EIP-3009 spec
    expect(typeFields).toContain('from')
    expect(typeFields).toContain('to')
    expect(typeFields).toContain('value')
    expect(typeFields).toContain('validAfter')
    expect(typeFields).toContain('validBefore')
    expect(typeFields).toContain('nonce')
  })

  test('type fields have correct Solidity types', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    const typeMap = Object.fromEntries(
      msg.types.TransferWithAuthorization.map((f: { name: string; type: string }) => [f.name, f.type])
    )

    expect(typeMap['from']).toBe('address')
    expect(typeMap['to']).toBe('address')
    expect(typeMap['value']).toBe('uint256')
    expect(typeMap['validAfter']).toBe('uint256')
    expect(typeMap['validBefore']).toBe('uint256')
    expect(typeMap['nonce']).toBe('bytes32')
  })

  test('has exactly 6 type fields (no extra/missing)', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.types.TransferWithAuthorization).toHaveLength(6)
  })
})

// ─── Message value tests ──────────────────────────────────────────────────────

describe('EIP-712 message values', () => {
  test('value is passed through as bigint (not number)', () => {
    // Solidity uint256 requires bigint — JS number loses precision above 2^53
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(typeof msg.message.value).toBe('bigint')
  })

  test('value matches input exactly', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.message.value).toBe(500000n)
  })

  test('from and to addresses are passed through', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.message.from).toBe(MOCK_AUTH.from)
    expect(msg.message.to).toBe(MOCK_AUTH.to)
  })

  test('nonce is passed through unchanged', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.message.nonce).toBe(MOCK_AUTH.nonce)
  })

  test('validAfter and validBefore are bigints', () => {
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(typeof msg.message.validAfter).toBe('bigint')
    expect(typeof msg.message.validBefore).toBe('bigint')
  })

  test('validBefore is in the future for fresh authorization', () => {
    const now = BigInt(Math.floor(Date.now() / 1000))
    const msg = buildTransferAuthorizationMessage(MOCK_AUTH, MOCK_USDC_ADDRESS)
    expect(msg.message.validBefore).toBeGreaterThan(now)
  })

  test('large values (uint256 range) are preserved as bigint', () => {
    const largeValueAuth: TransferAuthorization = {
      ...MOCK_AUTH,
      value: 1_000_000_000_000n, // 1M USDC (extreme edge case)
    }
    const msg = buildTransferAuthorizationMessage(largeValueAuth, MOCK_USDC_ADDRESS)
    expect(msg.message.value).toBe(1_000_000_000_000n)
    expect(typeof msg.message.value).toBe('bigint')
  })
})
