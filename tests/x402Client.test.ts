/**
 * x402Client.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tests for the x402 fetch wrapper.
 *
 * WHAT THIS TESTS:
 *   - Transparent passthrough of non-402 responses
 *   - Rejection of malformed 402 responses
 *   - Error throwing for missing session keys (X402SessionRequired)
 *   - Error throwing for insufficient budget (X402InsufficientBudget)
 *   - The full challenge-response retry loop
 *   - Header injection (PAYMENT-SIGNATURE & X-PAYMENT)
 *   - Spend recording on success
 *   - Error throwing if the retry is rejected (X402PaymentFailed)
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  createX402Client,
  X402SessionRequired,
  X402InsufficientBudget,
  X402PaymentFailed,
} from '../frontend/src/lib/x402Client.example'
import * as sessionKeyLib from '../frontend/src/lib/sessionKey.example'
import * as eip3009Lib from '../frontend/src/lib/eip3009.example'

// ─── Mocks ────────────────────────────────────────────────────────────────────

vi.mock('../frontend/src/lib/sessionKey.example', () => ({
  loadSessionKey: vi.fn(),
  hasSessionBudget: vi.fn(),
  recordSpend: vi.fn(),
  generateNonce: vi.fn(() => '0xmocknonce'),
}))

vi.mock('../frontend/src/lib/eip3009.example', () => ({
  signTransferAuthorization: vi.fn(() => Promise.resolve({ signature: '0xmocksignature' })),
  encodePaymentHeader: vi.fn(() => 'mock_base64_header_value'),
}))

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('createX402Client', () => {
  const config = { usdcAddress: '0xmockusdcaddress' }
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    // Intercept native fetch
    originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn()
  })

  afterEach(() => {
    // Restore native fetch and clear mocks
    globalThis.fetch = originalFetch
    vi.clearAllMocks()
  })

  test('passes through non-402 responses seamlessly', async () => {
    const mockResponse = new Response('ok', { status: 200 })
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(mockResponse)

    const client = createX402Client(config)
    const res = await client.fetch('https://api.example.com')

    expect(res.status).toBe(200)
    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
  })

  test('throws Error if 402 response has no requirements body', async () => {
    const mockResponse = new Response(JSON.stringify({}), { status: 402 })
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(mockResponse)

    const client = createX402Client(config)
    await expect(client.fetch('https://api.example.com')).rejects.toThrow(/no payment requirements/)
  })

  test('throws X402SessionRequired if no session key exists', async () => {
    const requirement = { maxAmountRequired: '1000', payTo: '0xtreasury', maxTimeoutSeconds: 60 }
    const mockResponse = new Response(JSON.stringify({ accepts: [requirement] }), { status: 402 })
    
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(mockResponse)
    vi.mocked(sessionKeyLib.loadSessionKey).mockReturnValueOnce(null)

    const client = createX402Client(config)
    await expect(client.fetch('https://api.example.com')).rejects.toThrow(X402SessionRequired)
  })

  test('throws X402InsufficientBudget if budget is exceeded', async () => {
    const requirement = { maxAmountRequired: '5000000', payTo: '0xtreasury', maxTimeoutSeconds: 60 }
    const mockResponse = new Response(JSON.stringify({ accepts: [requirement] }), { status: 402 })
    
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(mockResponse)

    vi.mocked(sessionKeyLib.loadSessionKey).mockReturnValueOnce({
      address: '0xuser',
      config: { maxAmountUsdc: 2 }, // 2 USDC cap
      spentUsdc: 0
    } as any)
    vi.mocked(sessionKeyLib.hasSessionBudget).mockReturnValueOnce(false)

    const client = createX402Client(config)
    // Attempting to spend 5 USDC when cap is 2
    await expect(client.fetch('https://api.example.com')).rejects.toThrow(X402InsufficientBudget)
  })

  test('successfully pays, attaches headers, retries request, and records spend', async () => {
    const requirement = { 
      maxAmountRequired: '1000000', // 1 USDC 
      payTo: '0xtreasury', 
      maxTimeoutSeconds: 60, 
      asset: '0xmockusdcaddress', 
      network: 'arc-testnet-5042002' 
    }
    const mock402 = new Response(JSON.stringify({ accepts: [requirement] }), { status: 402 })
    const mock200 = new Response('success', { status: 200 })

    vi.mocked(globalThis.fetch)
      .mockResolvedValueOnce(mock402)
      .mockResolvedValueOnce(mock200)

    vi.mocked(sessionKeyLib.loadSessionKey).mockReturnValueOnce({
      address: '0xuser',
      config: { maxAmountUsdc: 5 },
      spentUsdc: 0
    } as any)
    vi.mocked(sessionKeyLib.hasSessionBudget).mockReturnValueOnce(true)

    const client = createX402Client(config)
    const res = await client.fetch('https://api.example.com', { headers: { 'Authorization': 'Bearer token' }})

    expect(res.status).toBe(200)
    expect(globalThis.fetch).toHaveBeenCalledTimes(2)
    
    // Verify the second (retry) call contains the newly injected payment headers + original headers
    const retryCallArgs = vi.mocked(globalThis.fetch).mock.calls[1]
    const retryHeaders = retryCallArgs[1]?.headers as Record<string, string>
    
    expect(retryHeaders).toHaveProperty('PAYMENT-SIGNATURE', 'mock_base64_header_value')
    expect(retryHeaders).toHaveProperty('X-PAYMENT', 'mock_base64_header_value')
    expect(retryHeaders).toHaveProperty('Authorization', 'Bearer token')

    // Verify it correctly records the spend (1000000 atomic = 1 USDC)
    expect(sessionKeyLib.recordSpend).toHaveBeenCalledWith(1)
  })

  test('throws X402PaymentFailed if the retried request is also rejected', async () => {
    const requirement = { maxAmountRequired: '1000000', payTo: '0xtreasury', maxTimeoutSeconds: 60 }
    const mock402 = new Response(JSON.stringify({ accepts: [requirement] }), { status: 402 })
    const mock402Retry = new Response('still payment required', { status: 402 })

    vi.mocked(globalThis.fetch)
      .mockResolvedValueOnce(mock402)
      .mockResolvedValueOnce(mock402Retry)

    vi.mocked(sessionKeyLib.loadSessionKey).mockReturnValueOnce({
      address: '0xuser',
      config: { maxAmountUsdc: 5 },
      spentUsdc: 0
    } as any)
    vi.mocked(sessionKeyLib.hasSessionBudget).mockReturnValueOnce(true)

    const client = createX402Client(config)
    await expect(client.fetch('https://api.example.com')).rejects.toThrow(X402PaymentFailed)
  })
})
