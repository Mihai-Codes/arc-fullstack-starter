/**
 * x402 — HTTP PAYMENT PROTOCOL
 * 
 * x402 extends HTTP with a payment layer. When a server
 * wants payment for a resource, it responds with 
 * HTTP 402 (Payment Required) and a machine-readable
 * description of what it costs and how to pay.
 * 
 * The client pays (using EIP-3009 + session key) and
 * retries the request with proof of payment in a header.
 * 
 * This enables:
 * - Pay-per-read APIs (0.001 USDC per thesis)
 * - Agent-to-agent payments (no human in the loop)
 * - Micropayments that would be uneconomical elsewhere
 *   (Arc's $0.01 fees make $0.001 payments viable)
 * 
 * The flow (visualized):
 * 
 * Client                    Server
 *   │                         │
 *   │── GET /api/thesis/1 ───►│
 *   │                         │
 *   │◄── 402 { amount, to } ──│  "Pay 0.001 USDC to 0xTreasury"
 *   │                         │
 *   │ [sign EIP-3009 auth]    │
 *   │                         │
 *   │── GET /api/thesis/1 ───►│
 *   │   X-PAYMENT: <sig>      │
 *   │                         │
 *   │◄── 200 { data } ────────│  "Here's your thesis"
 */

import { loadSessionKey, hasSessionBudget, recordSpend, generateNonce } from './sessionKey.example'
import { signTransferAuthorization, encodePaymentHeader, type TransferAuthorization } from './eip3009.example'

// ─── TYPES & CUSTOM ERRORS ──────────────────────────────────────────────────

export type X402ClientConfig = {
  usdcAddress: string
}

export type PaymentRequirement = {
  scheme: string
  network: string
  maxAmountRequired: string    // string representation of atomic units (e.g., "1000")
  payTo: string
  maxTimeoutSeconds: number
  asset: string
}

export class X402SessionRequired extends Error {
  constructor(public requirement: PaymentRequirement) {
    super('x402: No active session key available. User must authorize one.')
    this.name = 'X402SessionRequired'
  }
}

export class X402InsufficientBudget extends Error {
  constructor(public required: number, public available: number) {
    super(`x402: Insufficient session budget. Required: ${required} USDC, Available: ${available} USDC`)
    this.name = 'X402InsufficientBudget'
  }
}

export class X402PaymentFailed extends Error {
  constructor(public status: number) {
    super(`x402: Payment rejected by server with status ${status}`)
    this.name = 'X402PaymentFailed'
  }
}

// ─── IMPLEMENTATION ──────────────────────────────────────────────────────────

/**
 * Creates an instance of an x402-compliant fetch wrapper.
 * 
 * Concept: Wraps global fetch so any 402 "Payment Required" response automatically
 * triggers a background EIP-3009 payment using the active session key and retries the request.
 * 
 * @param config - Global configuration containing the USDC contract address
 * @returns An object with a customized, payment-aware fetch method
 */
export function createX402Client(config: X402ClientConfig) {
  const httpFetch = globalThis.fetch

  return {
    async fetch(url: string, options?: RequestInit): Promise<Response> {
      // Step 1: Make the initial request
      const response = await httpFetch(url, options)

      // If it's not a 402, return immediately as-is
      if (response.status !== 402) {
        return response
      }

      // Step 2: Extract payment requirements from the 402 JSON body
      const body = await response.json()
      const requirement: PaymentRequirement = body.accepts?.[0]
      if (!requirement) {
        throw new Error('x402: No accepts requirements found in 402 response.')
      }

      // Step 3: Load the ephemeral session key from sessionStorage
      const sessionKey = loadSessionKey()
      if (!sessionKey) {
        throw new X402SessionRequired(requirement)
      }

      // Step 4: Validate remaining budget
      const amountUsdc = Number(requirement.maxAmountRequired) / 1e6
      if (!hasSessionBudget(amountUsdc)) {
        const remaining = sessionKey.config.maxAmountUsdc - sessionKey.spentUsdc
        throw new X402InsufficientBudget(amountUsdc, remaining)
      }

      // Step 5: Build EIP-3009 parameters (sender is the session key address)
      const transferAuth: TransferAuthorization = {
        from: sessionKey.address,
        to: requirement.payTo as `0x${string}`,
        value: BigInt(requirement.maxAmountRequired),
        validAfter: BigInt(0),
        validBefore: BigInt(Math.floor(Date.now() / 1000) + requirement.maxTimeoutSeconds),
        nonce: generateNonce(),
      }

      // Step 6: Sign the authorization using the session key's private key
      const signed = await signTransferAuthorization(transferAuth, sessionKey, config.usdcAddress)

      // Step 7: Encode payload into a base64 header
      const headerValue = encodePaymentHeader(signed)

      // Step 8: Retry the request with the payment signature headers
      const retryResponse = await httpFetch(url, {
        ...options,
        headers: {
          ...options?.headers,
          'PAYMENT-SIGNATURE': headerValue,
          'X-PAYMENT': headerValue, // Fallback support for older specifications
        }
      })

      // Step 9: Accounting on success, otherwise throw
      if (retryResponse.status >= 200 && retryResponse.status < 300) {
        recordSpend(amountUsdc)
        return retryResponse
      }

      throw new X402PaymentFailed(retryResponse.status)
    }
  }
}

/**
 * USAGE EXAMPLE:
 * 
 * // 1. Create the client once
 * const x402 = createX402Client({ 
 *   usdcAddress: process.env.NEXT_PUBLIC_USDC_ARC_ADDRESS 
 * })
 * 
 * // 2. Use it like regular fetch
 * const response = await x402.fetch('/api/thesis/abc123')
 * const thesis = await response.json()
 * 
 * // That's it. The 402 → pay → retry happens automatically.
 * // If the session key doesn't exist, it throws 
 * // X402SessionRequired and you prompt the user to approve.
 */
