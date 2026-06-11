/**
 * x402Server.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests for the x402 server middleware.
 *
 * WHAT THIS TESTS:
 *   - Returns 402 with correct x402 v2 body when no payment header
 *   - PAYMENT-REQUIRED header is base64-encoded
 *   - Decodes PAYMENT-SIGNATURE header (v2 canonical)
 *   - Decodes X-PAYMENT header (v1 fallback)
 *   - Returns 402 for invalid/malformed payment headers
 *   - Calls the handler after successful verification
 *   - Returns PAYMENT-RESPONSE header with tx hash
 *   - Off-chain nonce dedup (settleOnChain=false)
 *   - Rejects replayed payments (same nonce)
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { recoverTypedDataAddress } from 'viem'
import { withX402, _resetNonceStore, type X402ServerConfig } from '../frontend/src/lib/x402Server.example'
import * as eip3009Lib from '../frontend/src/lib/eip3009.example'

// ─── Mocks ──────────────────────────────────────────────────────────────────

// Mock viem — we can't connect to Arc in unit tests
vi.mock('viem', () => ({
  createPublicClient: vi.fn(() => ({
    waitForTransactionReceipt: vi.fn(() => Promise.resolve({ status: 'success' })),
  })),
  createWalletClient: vi.fn(() => ({
    writeContract: vi.fn(() => Promise.resolve('0xtxhash123')),
  })),
  http: vi.fn(),
  recoverTypedDataAddress: vi.fn(() => Promise.resolve('0xuser')),
}))

vi.mock('viem/accounts', () => ({
  privateKeyToAccount: vi.fn(() => ({
    address: '0xsettler',
    signTypedData: vi.fn(),
  })),
}))

vi.mock('../frontend/src/lib/eip3009.example', () => ({
  decodePaymentHeader: vi.fn(),
  buildTransferAuthorizationMessage: vi.fn(() => ({
    domain: { name: 'USD Coin', version: '2', chainId: 5042002, verifyingContract: '0xusdc' },
    types: { TransferWithAuthorization: [] },
    primaryType: 'TransferWithAuthorization',
    message: {},
  })),
  ARC_TESTNET_CAIP2: 'eip155:5042002',
}))

// ─── Test Config ────────────────────────────────────────────────────────────

const TEST_CONFIG: X402ServerConfig = {
  resource: '/api/test',
  priceUsdc: 0.001,
  description: 'Test endpoint',
  treasuryAddress: '0xtreasury',
  rpcUrl: 'https://rpc.testnet.arc.network',
  usdcAddress: '0xusdc',
  settlerPrivateKey: '0xsettlerkey',
  settleOnChain: false, // off-chain for tests
}

const VALID_SIGNED_AUTH = {
  from: '0xuser',
  to: '0xtreasury',
  value: BigInt(1000), // 0.001 USDC in atomic units
  validAfter: BigInt(0),
  validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
  nonce: '0xnonce123',
  v: 27,
  r: '0xr' as `0x${string}`,
  s: '0xs' as `0x${string}`,
  signature: '0xsignature' as `0x${string}`,
}

// ─── Helper ─────────────────────────────────────────────────────────────────

function makeRequest(headers: Record<string, string> = {}): Request {
  return new Request('http://localhost/api/test', { headers })
}

// ─── Test Suite ─────────────────────────────────────────────────────────────

describe('withX402', () => {
  const handler = vi.fn(async () => Response.json({ data: 'premium content' }))

  beforeEach(() => {
    // mockClear() preserves vi.mock() factory implementations while resetting call state
    vi.mocked(handler).mockClear()
    vi.mocked(recoverTypedDataAddress).mockClear()
    vi.mocked(eip3009Lib.decodePaymentHeader).mockClear()
    // Clear the in-memory nonce dedup store between tests
    _resetNonceStore()
  })

  // ── 402 Response Format ────────────────────────────────────────────────

  test('returns 402 when no payment header is present', async () => {
    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest())

    expect(response.status).toBe(402)
    expect(handler).not.toHaveBeenCalled()
  })

  test('402 body contains x402Version 2 and accepts array', async () => {
    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest())
    const body = await response.json()

    expect(body.x402Version).toBe(2)
    expect(body.accepts).toBeDefined()
    expect(body.accepts.length).toBe(1)
    expect(body.accepts[0].scheme).toBe('exact')
    expect(body.accepts[0].network).toBe('eip155:5042002')
    // x402 v2 spec: extra.assetTransferMethod defaults to "eip3009"
    expect(body.accepts[0].extra.assetTransferMethod).toBe('eip3009')
    // x402 v2 spec: extensions field should be present
    expect(body.extensions).toEqual({})
  })

  test('402 amount matches priceUsdc in atomic units', async () => {
    const config = { ...TEST_CONFIG, priceUsdc: 0.05 } // 5 cents
    const wrapped = withX402(config, handler)
    const response = await wrapped(makeRequest())
    const body = await response.json()

    // 0.05 * 1e6 = 50000
    expect(body.accepts[0].amount).toBe('50000')
  })

  test('PAYMENT-REQUIRED header is base64-encoded', async () => {
    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest())
    const header = response.headers.get('PAYMENT-REQUIRED')

    expect(header).toBeDefined()

    // Decode and verify it matches the body
    const decoded = JSON.parse(Buffer.from(header!, 'base64').toString())
    expect(decoded.x402Version).toBe(2)
    expect(decoded.accepts[0].scheme).toBe('exact')
  })

  test('resource in 402 body matches config', async () => {
    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest())
    const body = await response.json()

    expect(body.resource.url).toBe('/api/test')
    expect(body.resource.description).toBe('Test endpoint')
  })

  // ── Header Decoding ────────────────────────────────────────────────────

  test('decodes PAYMENT-SIGNATURE header (v2 canonical)', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'base64encodedpayment',
    }))

    expect(eip3009Lib.decodePaymentHeader).toHaveBeenCalledWith('base64encodedpayment')
    expect(response.status).toBe(200)
  })

  test('decodes X-PAYMENT header (v1 fallback)', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'X-PAYMENT': 'base64encodedpayment',
    }))

    expect(eip3009Lib.decodePaymentHeader).toHaveBeenCalledWith('base64encodedpayment')
    expect(response.status).toBe(200)
  })

  test('returns 400 for malformed payment header', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockImplementationOnce(() => {
      throw new Error('invalid base64')
    })

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'not-valid-base64',
    }))

    // x402 v2 spec: malformed payment → HTTP 400 (Invalid Payment)
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.code).toBe('INVALID_PAYLOAD')
  })

  // ── Payment Verification ───────────────────────────────────────────────

  test('rejects expired payment authorization', async () => {
    const expiredAuth = {
      ...VALID_SIGNED_AUTH,
      validBefore: BigInt(Math.floor(Date.now() / 1000) - 100), // expired 100s ago
    }
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(expiredAuth as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'base64',
    }))

    // x402 v2 spec: invalid payment authorization → HTTP 400
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.code).toBe('PAYMENT_VERIFICATION_FAILED')
    expect(body.detail).toContain('expired')
  })

  test('rejects insufficient payment amount', async () => {
    const insufficientAuth = {
      ...VALID_SIGNED_AUTH,
      value: BigInt(100), // 0.0001 USDC — less than required 0.001
    }
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(insufficientAuth as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'base64',
    }))

    // x402 v2 spec: invalid payment authorization → HTTP 400
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.detail).toContain('Insufficient')
  })

  test('rejects wrong recipient', async () => {
    const wrongRecipientAuth = {
      ...VALID_SIGNED_AUTH,
      to: '0xwrongaddress',
    }
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(wrongRecipientAuth as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'base64',
    }))

    // x402 v2 spec: invalid payment authorization → HTTP 400
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.detail).toContain('Wrong recipient')
  })

  test('rejects signature when recovered address does not match from', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)
    vi.mocked(recoverTypedDataAddress).mockResolvedValueOnce('0xWRONGADDRESS')

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({
      'PAYMENT-SIGNATURE': 'base64',
    }))

    // x402 v2 spec: invalid payment authorization → HTTP 400
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.detail).toContain('Signer mismatch')
  })

  // ── Handler Execution ──────────────────────────────────────────────────

  test('calls handler after successful verification', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))

    expect(handler).toHaveBeenCalledOnce()
  })

  test('returns PAYMENT-RESPONSE header with settlement proof', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))

    // settleOnChain=false → txHash = 'verified-offchain'
    // x402 v2 spec SettlementResponse: { success, transaction, network, payer }
    const paymentResponseB64 = response.headers.get('PAYMENT-RESPONSE')
    expect(paymentResponseB64).toBeTruthy()
    const paymentResponse = JSON.parse(Buffer.from(paymentResponseB64!, 'base64').toString('utf-8'))
    expect(paymentResponse.success).toBe(true)
    expect(paymentResponse.transaction).toBe('verified-offchain')
    expect(paymentResponse.network).toBe('eip155:5042002')
    expect(paymentResponse.payer).toBe('0xuser')

    // Legacy header for backwards compatibility
    expect(response.headers.get('X-PAYMENT-TX-HASH')).toBe('verified-offchain')
  })

  test('returns handler response body', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const wrapped = withX402(TEST_CONFIG, handler)
    const response = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))
    const body = await response.json()

    expect(body.data).toBe('premium content')
  })

  // ── Off-Chain Nonce Dedup ──────────────────────────────────────────────

  test('rejects replayed payment (same nonce)', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader)
      .mockReturnValueOnce(VALID_SIGNED_AUTH as any)
      .mockReturnValueOnce({ ...VALID_SIGNED_AUTH } as any) // same nonce

    const wrapped = withX402(TEST_CONFIG, handler)

    const res1 = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))
    expect(res1.status).toBe(200) // first use succeeds

    const res2 = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))
    expect(res2.status).toBe(402) // replay rejected
    const body = await res2.json()
    expect(body.code).toBe('PAYMENT_REPLAY_DETECTED')
  })

  test('accepts different nonces on consecutive requests', async () => {
    const auth1 = { ...VALID_SIGNED_AUTH, nonce: '0xnonce1' as `0x${string}` }
    const auth2 = { ...VALID_SIGNED_AUTH, nonce: '0xnonce2' as `0x${string}` }

    vi.mocked(eip3009Lib.decodePaymentHeader)
      .mockReturnValueOnce(auth1 as any)
      .mockReturnValueOnce(auth2 as any)

    const wrapped = withX402(TEST_CONFIG, handler)

    const res1 = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))
    expect(res1.status).toBe(200)

    const res2 = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))
    expect(res2.status).toBe(200)
  })

  // ── Config Variations ──────────────────────────────────────────────────

  test('settleOnChain=true would call on-chain settlement (mocked)', async () => {
    vi.mocked(eip3009Lib.decodePaymentHeader).mockReturnValueOnce(VALID_SIGNED_AUTH as any)

    const configOnChain = { ...TEST_CONFIG, settleOnChain: true }
    const wrapped = withX402(configOnChain, handler)
    const response = await wrapped(makeRequest({ 'PAYMENT-SIGNATURE': 'base64' }))

    // Handler should still be called (settlement is mocked)
    expect(handler).toHaveBeenCalledOnce()
    expect(response.status).toBe(200)
  })
})
