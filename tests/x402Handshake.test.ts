/**
 * x402Handshake.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * End-to-end smoke test for the x402 v2 payment handshake.
 *
 * WHAT THIS TESTS:
 *   The full protocol flow in a single process, using real crypto (no mocks):
 *     1. Server returns 402 with PaymentRequired
 *     2. Client parses 402, signs authorization, builds PaymentPayload
 *     3. Server validates `accepted` field matches requirements
 *     4. Server verifies EIP-712 signature (ecrecover)
 *     5. Server returns PAYMENT-RESPONSE (SettlementResponse)
 *     6. Client parses PAYMENT-RESPONSE and verifies settlement proof
 *
 *   This is the closest we can get to a live integration test in CI
 *   without a real blockchain node. It proves the full crypto flow works.
 *
 * WHY THIS MATTERS:
 *   Unit tests mock individual functions. This test proves they work TOGETHER.
 *   If the encode format changes on one side but not the other, this test catches it.
 */

import { describe, test, expect, beforeAll } from 'vitest'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { encodePaymentHeader, decodeFullPaymentPayload } from '../frontend/src/lib/eip3009.example'
import { withX402, _resetNonceStore, type X402ServerConfig } from '../frontend/src/lib/x402Server.example'
import { ARC_TESTNET_CAIP2, X402_VERSION } from '../frontend/src/lib/x402Types'

// ─── viem mocks (only for settlement, not for signing) ──────────────────────

import { vi } from 'vitest'
vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return {
    ...actual,
    // Keep real ecrecover for signature verification
    createPublicClient: vi.fn(() => ({
      waitForTransactionReceipt: vi.fn(() => Promise.resolve({ status: 'success' })),
    })),
    createWalletClient: vi.fn(() => ({
      writeContract: vi.fn(() => Promise.resolve('0xtxhash123')),
    })),
    http: vi.fn(),
  }
})
vi.mock('viem/accounts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem/accounts')>()
  return actual // real privateKeyToAccount
})

// ─── Fixtures ───────────────────────────────────────────────────────────────

const USDC_ADDRESS = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' // USDC on Arc Testnet

let sessionKeyAddress: string
let sessionKeyPrivateKey: `0x${string}`

const SERVER_CONFIG: X402ServerConfig = {
  resource: '/api/premium-data',
  priceUsdc: 0.001, // $0.001 USDC = 1000 atomic units
  description: 'Premium data access',
  treasuryAddress: '0x1234567890abcdef1234567890abcdef12345678',
  rpcUrl: 'https://rpc.testnet.arc.network',
  usdcAddress: USDC_ADDRESS,
  settlerPrivateKey: '0xsettler',
  settleOnChain: false, // off-chain for test
}

// ─── Setup ──────────────────────────────────────────────────────────────────

beforeAll(() => {
  // Generate a real ephemeral keypair for the session key
  sessionKeyPrivateKey = generatePrivateKey()
  const account = privateKeyToAccount(sessionKeyPrivateKey)
  sessionKeyAddress = account.address
})

// ─── Test Suite ─────────────────────────────────────────────────────────────

describe('x402 v2 end-to-end handshake', () => {

  test('full flow: 402 → sign → validate accepted → verify signature → 200 + PAYMENT-RESPONSE', async () => {
    _resetNonceStore()

    // ── Step 1: Server returns 402 with PaymentRequired ────────────────
    const serverHandler = withX402(SERVER_CONFIG, async () =>
      Response.json({ data: 'premium content' })
    )

    const initialRequest = new Request('http://localhost/api/premium-data')
    const response402 = await serverHandler(initialRequest)

    expect(response402.status).toBe(402)

    // Parse the 402 response
    const body402 = await response402.json()
    expect(body402.x402Version).toBe(X402_VERSION)
    expect(body402.accepts).toHaveLength(1)

    const requirement = body402.accepts[0]
    expect(requirement.scheme).toBe('exact')
    expect(requirement.network).toBe(ARC_TESTNET_CAIP2)
    expect(requirement.amount).toBe('1000')
    expect(requirement.asset).toBe(USDC_ADDRESS)
    expect(requirement.payTo).toBe(SERVER_CONFIG.treasuryAddress)
    expect(requirement.extra.assetTransferMethod).toBe('eip3009')
    expect(requirement.extra.name).toBe('USD Coin')
    expect(requirement.extra.version).toBe('2')

    // Verify PAYMENT-REQUIRED header is present and base64-encoded
    const paymentRequiredHeader = response402.headers.get('PAYMENT-REQUIRED')
    expect(paymentRequiredHeader).toBeDefined()
    const decodedHeader = JSON.parse(Buffer.from(paymentRequiredHeader!, 'base64').toString())
    expect(decodedHeader.x402Version).toBe(X402_VERSION)
    expect(decodedHeader.accepts[0].scheme).toBe('exact')

    // ── Step 2: Client signs authorization and builds PaymentPayload ───
    // Simulate what the client does: sign an EIP-3009 authorization
    const { signTransferAuthorization } = await import('../frontend/src/lib/eip3009.example')
    const account = privateKeyToAccount(sessionKeyPrivateKey)

    const nowSeconds = Math.floor(Date.now() / 1000)
    const signed = await signTransferAuthorization(
      {
        from: sessionKeyAddress as `0x${string}`,
        to: requirement.payTo as `0x${string}`,
        value: BigInt(requirement.amount),
        validAfter: BigInt(0),
        validBefore: BigInt(nowSeconds + requirement.maxTimeoutSeconds),
        nonce: `0x${'00'.repeat(32).replace(/random/g, () => Math.random().toString(16).slice(2)).slice(0, 64)}`,
      },
      { address: sessionKeyAddress, privateKey: sessionKeyPrivateKey, config: { maxAmountUsdc: 10, expiresAt: Date.now() + 3600000 }, spentUsdc: 0 } as any,
      USDC_ADDRESS
    )

    // Encode the PaymentPayload
    const paymentHeader = encodePaymentHeader(signed, requirement, body402.resource)

    // Verify the encoded payload is valid base64
    expect(paymentHeader).toMatch(/^[A-Za-z0-9+/=]+$/)

    // Decode and verify structure
    const decoded = decodeFullPaymentPayload(paymentHeader)
    expect(decoded.x402Version).toBe(X402_VERSION)
    expect(decoded.accepted.scheme).toBe('exact')
    expect(decoded.accepted.network).toBe(ARC_TESTNET_CAIP2)
    expect(decoded.accepted.amount).toBe('1000')
    expect(decoded.payload.signature).toMatch(/^0x[0-9a-fA-F]{130}$/) // 65 bytes
    expect(decoded.payload.authorization.from).toBe(sessionKeyAddress)
    expect(decoded.payload.authorization.value).toBe('1000')
    expect(decoded.payload.authorization.nonce).toMatch(/^0x[0-9a-fA-F]{64}$/) // bytes32
    expect(decoded.resource?.url).toBe('/api/premium-data')

    // ── Step 3: Server validates accepted + verifies signature + 200 ───
    const paidRequest = new Request('http://localhost/api/premium-data', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    })

    const response200 = await serverHandler(paidRequest)

    expect(response200.status).toBe(200)

    // Verify PAYMENT-RESPONSE header (SettlementResponse)
    const paymentResponseB64 = response200.headers.get('PAYMENT-RESPONSE')
    expect(paymentResponseB64).toBeDefined()
    const paymentResponse = JSON.parse(Buffer.from(paymentResponseB64!, 'base64').toString())
    expect(paymentResponse.success).toBe(true)
    expect(paymentResponse.transaction).toBe('verified-offchain')
    expect(paymentResponse.network).toBe(ARC_TESTNET_CAIP2)
    expect(paymentResponse.payer).toBe(sessionKeyAddress)

    // Verify X-PAYMENT-TX-HASH legacy header
    expect(response200.headers.get('X-PAYMENT-TX-HASH')).toBe('verified-offchain')

    // Verify the handler was called and returned the resource
    const resource = await response200.json()
    expect(resource.data).toBe('premium content')
  })

  test('server rejects when accepted.amount mismatches', async () => {
    _resetNonceStore()

    const serverHandler = withX402(SERVER_CONFIG, async () =>
      Response.json({ data: 'should not reach' })
    )

    // Get the 402 requirement
    const response402 = await serverHandler(new Request('http://localhost/api/test'))
    const body402 = await response402.json()
    const requirement = body402.accepts[0]

    // Sign with correct authorization but tamper the accepted.amount
    const { signTransferAuthorization } = await import('../frontend/src/lib/eip3009.example')
    const signed = await signTransferAuthorization(
      {
        from: sessionKeyAddress as `0x${string}`,
        to: requirement.payTo as `0x${string}`,
        value: BigInt(requirement.amount),
        validAfter: BigInt(0),
        validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
        nonce: `0x${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`,
      },
      { address: sessionKeyAddress, privateKey: sessionKeyPrivateKey, config: { maxAmountUsdc: 10, expiresAt: Date.now() + 3600000 }, spentUsdc: 0 } as any,
      USDC_ADDRESS
    )

    // Tamper: change accepted.amount to wrong value
    const tamperedAccepted = { ...requirement, amount: '9999' }
    const paymentHeader = encodePaymentHeader(signed, tamperedAccepted, body402.resource)

    const paidRequest = new Request('http://localhost/api/test', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    })

    const response = await serverHandler(paidRequest)

    // Server should reject: amount mismatch
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.code).toBe('INVALID_PAYLOAD')
    expect(body.error).toBe('Payment amount mismatch')
    expect(body.detail).toContain('9999') // tampered amount
    expect(body.detail).toContain('1000') // expected amount
  })

  test('server rejects when accepted.network mismatches', async () => {
    _resetNonceStore()

    const serverHandler = withX402(SERVER_CONFIG, async () =>
      Response.json({ data: 'should not reach' })
    )

    const response402 = await serverHandler(new Request('http://localhost/api/test'))
    const body402 = await response402.json()
    const requirement = body402.accepts[0]

    const { signTransferAuthorization } = await import('../frontend/src/lib/eip3009.example')
    const signed = await signTransferAuthorization(
      {
        from: sessionKeyAddress as `0x${string}`,
        to: requirement.payTo as `0x${string}`,
        value: BigInt(requirement.amount),
        validAfter: BigInt(0),
        validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
        nonce: `0x${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`,
      },
      { address: sessionKeyAddress, privateKey: sessionKeyPrivateKey, config: { maxAmountUsdc: 10, expiresAt: Date.now() + 3600000 }, spentUsdc: 0 } as any,
      USDC_ADDRESS
    )

    // Tamper: change accepted.network
    const tamperedAccepted = { ...requirement, network: 'eip155:84532' }
    const paymentHeader = encodePaymentHeader(signed, tamperedAccepted, body402.resource)

    const paidRequest = new Request('http://localhost/api/test', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    })

    const response = await serverHandler(paidRequest)
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.code).toBe('INVALID_PAYLOAD')
    expect(body.error).toBe('Payment network mismatch')
    expect(body.detail).toContain('eip155:84532')
  })

  test('server rejects when accepted.payTo mismatches', async () => {
    _resetNonceStore()

    const serverHandler = withX402(SERVER_CONFIG, async () =>
      Response.json({ data: 'should not reach' })
    )

    const response402 = await serverHandler(new Request('http://localhost/api/test'))
    const body402 = await response402.json()
    const requirement = body402.accepts[0]

    const { signTransferAuthorization } = await import('../frontend/src/lib/eip3009.example')
    const signed = await signTransferAuthorization(
      {
        from: sessionKeyAddress as `0x${string}`,
        to: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as `0x${string}`, // different payTo
        value: BigInt(requirement.amount),
        validAfter: BigInt(0),
        validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
        nonce: `0x${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`,
      },
      { address: sessionKeyAddress, privateKey: sessionKeyPrivateKey, config: { maxAmountUsdc: 10, expiresAt: Date.now() + 3600000 }, spentUsdc: 0 } as any,
      USDC_ADDRESS
    )

    // Tamper: change accepted.payTo
    const tamperedAccepted = { ...requirement, payTo: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
    const paymentHeader = encodePaymentHeader(signed, tamperedAccepted, body402.resource)

    const paidRequest = new Request('http://localhost/api/test', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    })

    const response = await serverHandler(paidRequest)
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.code).toBe('INVALID_PAYLOAD')
    expect(body.error).toBe('Payment recipient mismatch')
    expect(body.detail).toContain('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
  })

  test('replay detection: second request with same nonce is rejected', async () => {
    _resetNonceStore()

    const serverHandler = withX402(SERVER_CONFIG, async () =>
      Response.json({ data: 'ok' })
    )

    const response402 = await serverHandler(new Request('http://localhost/api/test'))
    const body402 = await response402.json()
    const requirement = body402.accepts[0]

    const { signTransferAuthorization } = await import('../frontend/src/lib/eip3009.example')
    const fixedNonce = `0x${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`
    const signed = await signTransferAuthorization(
      {
        from: sessionKeyAddress as `0x${string}`,
        to: requirement.payTo as `0x${string}`,
        value: BigInt(requirement.amount),
        validAfter: BigInt(0),
        validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
        nonce: fixedNonce as `0x${string}`,
      },
      { address: sessionKeyAddress, privateKey: sessionKeyPrivateKey, config: { maxAmountUsdc: 10, expiresAt: Date.now() + 3600000 }, spentUsdc: 0 } as any,
      USDC_ADDRESS
    )

    const paymentHeader = encodePaymentHeader(signed, requirement, body402.resource)

    // First request succeeds
    const res1 = await serverHandler(new Request('http://localhost/api/test', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    }))
    expect(res1.status).toBe(200)

    // Second request with same nonce → replay detected
    const res2 = await serverHandler(new Request('http://localhost/api/test', {
      headers: { 'PAYMENT-SIGNATURE': paymentHeader },
    }))
    expect(res2.status).toBe(402)
    const body = await res2.json()
    expect(body.code).toBe('PAYMENT_REPLAY_DETECTED')
  })
})
