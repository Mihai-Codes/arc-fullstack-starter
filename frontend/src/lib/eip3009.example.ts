/**
 * EIP-3009 — USDC's NATIVE AUTHORIZATION STANDARD
 * 
 * ERC-20 tokens normally require two transactions to
 * transfer: approve() then transferFrom(). EIP-3009
 * collapses this into a single signed message called
 * transferWithAuthorization.
 * 
 * The signer says: "I authorize transferring X USDC
 * from my address to Y address, valid between 
 * timestamp A and timestamp B, with nonce Z."
 * 
 * Anyone can submit this authorization to the USDC
 * contract — the signature proves consent. This is
 * what makes x402 work: the server submits the 
 * user's authorization without the user needing to
 * broadcast a transaction themselves.
 * 
 * ARC-SPECIFIC: USDC on Arc uses EIP-712 domain:
 *   name: 'USD Coin'    ← NOT 'USDC' (breaks sig!)
 *   version: '2'
 *   chainId: 5042002
 * 
 * ❌ WRONG (breaks signature verification on Arc):
 * domain: { name: 'USDC', version: '1', chainId: 1 }
 * 
 * ✅ RIGHT:
 * domain: { name: 'USD Coin', version: '2', chainId: 5042002 }
 */

import { privateKeyToAccount } from 'viem/accounts'
import type { SessionKey } from './sessionKey.example'
import {
  ARC_TESTNET_CAIP2,
  SIGNATURE_HEX_LENGTH,
  NONCE_HEX_LENGTH,
  type PaymentRequirements,
  type ResourceInfo,
  type PaymentPayload,
} from './x402Types'

// Re-export the shared constant and types for backwards compatibility.
// New code should import from './x402Types' directly.
export { ARC_TESTNET_CAIP2 } from './x402Types'
export type { PaymentRequirements, ResourceInfo } from './x402Types'

export type TransferAuthorization = {
  from: `0x${string}`         // user's session key address
  to: `0x${string}`           // recipient (treasury)
  value: bigint               // amount in USDC atomic units (6 decimals)
  validAfter: bigint          // unix timestamp (usually 0)
  validBefore: bigint         // unix timestamp (now + timeout)
  nonce: `0x${string}`       // random bytes32
}

export type SignedAuthorization = TransferAuthorization & {
  v: number
  r: `0x${string}`
  s: `0x${string}`
  signature: `0x${string}`   // full 65-byte sig
}

const TRANSFER_WITH_AUTH_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const

// ─── IMPLEMENTATION ──────────────────────────────────────────────────────────

/**
 * Build the EIP-712 typed data structure required for an EIP-3009 transfer.
 * 
 * Concept: Builds the standardized EIP-712 packet that defines the transfer
 * constraints, verifying the token, domain, and verifying contract.
 * 
 * @param auth - The raw transfer parameters
 * @param usdcAddress - The address of the USDC contract on Arc
 * @returns Complete EIP-712 typed data structure
 */
export function buildTransferAuthorizationMessage(
  auth: TransferAuthorization,
  usdcAddress: string
) {
  return {
    domain: {
      name: 'USD Coin',           // USDC's canonical name on EVM
      version: '2',                // Version "2" is standard for USDC
      chainId: 5042002,            // Arc Testnet
      verifyingContract: usdcAddress as `0x${string}`,
    },
    types: TRANSFER_WITH_AUTH_TYPES,
    primaryType: 'TransferWithAuthorization' as const,
    message: {
      from: auth.from,
      to: auth.to,
      value: auth.value,
      validAfter: auth.validAfter,
      validBefore: auth.validBefore,
      nonce: auth.nonce,
    },
  }
}

/**
 * Sign an EIP-3009 transfer authorization using the session key's private key.
 * 
 * Cryptographic principle: The session key, holding the pre-funded USDC balance,
 * signs the message in-memory without prompting the user's primary wallet.
 * 
 * @param auth - Unsigned transfer details
 * @param sessionKey - Ephemeral session key with private key
 * @param usdcAddress - USDC contract address
 * @returns Fully signed authorization packet
 */
export async function signTransferAuthorization(
  auth: TransferAuthorization,
  sessionKey: SessionKey,
  usdcAddress: string
): Promise<SignedAuthorization> {
  const account = privateKeyToAccount(sessionKey.privateKey)
  const typedData = buildTransferAuthorizationMessage(auth, usdcAddress)

  // Sign typed data in-memory silently
  const signature = await account.signTypedData({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
  })

  // Extract ECDSA signature components r, s, v
  const r = `0x${signature.slice(2, 66)}` as `0x${string}`
  const s = `0x${signature.slice(66, 130)}` as `0x${string}`
  const v = parseInt(signature.slice(130, 132), 16)

  return {
    ...auth,
    v,
    r,
    s,
    signature,
  }
}

/**
 * Base64 encode the signed authorization for HTTP header transport.
 *
 * x402 v2 PaymentPayload structure:
 *   { x402Version, resource?, accepted, payload: { signature, authorization } }
 *
 * The `accepted` field echoes back the server's PaymentRequirements from the
 * 402 response, proving the client is paying the correct amount for the
 * correct resource on the correct network.
 */
export function encodePaymentHeader(
  signed: SignedAuthorization,
  /** The server's PaymentRequirements from the 402 response (echoed back) */
  accepted?: PaymentRequirements,
  /** The resource being paid for (optional, from the 402 response) */
  resource?: ResourceInfo
): string {
  const paymentPayload = {
    x402Version: 2,
    ...(resource ? { resource } : {}),
    accepted: accepted ?? {
      scheme: 'exact',
      network: ARC_TESTNET_CAIP2,
      amount: signed.value.toString(),
      asset: '', // caller must populate for spec compliance
      payTo: signed.to,
      maxTimeoutSeconds: 300,
      extra: {
        assetTransferMethod: 'eip3009',
        name: 'USD Coin',
        version: '2',
      },
    },
    payload: {
      signature: signed.signature,
      authorization: {
        from: signed.from,
        to: signed.to,
        value: signed.value.toString(),
        validAfter: signed.validAfter.toString(),
        validBefore: signed.validBefore.toString(),
        nonce: signed.nonce,
      },
    },
  }

  const jsonString = JSON.stringify(paymentPayload)

  if (typeof window !== 'undefined') {
    return btoa(jsonString)
  } else {
    return Buffer.from(jsonString).toString('base64')
  }
}

/**
 * Base64 decode an incoming payment header back into a SignedAuthorization.
 */
export function decodePaymentHeader(header: string): SignedAuthorization {
  let jsonString: string

  if (typeof window !== 'undefined') {
    jsonString = atob(header)
  } else {
    jsonString = Buffer.from(header, 'base64').toString('utf-8')
  }

  const parsed = JSON.parse(jsonString)
  const payload = parsed.payload

  if (!payload) {
    throw new Error('Payment header missing payload')
  }

  // x402 v2 spec uses nested authorization: payload.authorization.{from,to,...}
  // Legacy format uses flat: payload.{from,to,...}
  // Accept both for backwards compatibility.
  const auth = payload.authorization ?? payload

  // Validate required fields exist and have correct types
  const requiredFields = ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'] as const
  for (const field of requiredFields) {
    if (auth[field] === undefined || auth[field] === null) {
      throw new Error(`Payment header missing required field: ${field}`)
    }
  }
  if (payload.signature === undefined || payload.signature === null) {
    throw new Error('Payment header missing required field: signature')
  }

  // Validate address formats (must be 0x + 40 hex chars)
  const addrRegex = /^0x[0-9a-fA-F]{40}$/
  if (!addrRegex.test(auth.from)) throw new Error(`Invalid from address: ${auth.from}`)
  if (!addrRegex.test(auth.to)) throw new Error(`Invalid to address: ${auth.to}`)

  // Validate nonce format: must be 0x + 64 hex chars (bytes32)
  const nonceRegex = /^0x[0-9a-fA-F]{64}$/
  if (!nonceRegex.test(auth.nonce)) {
    throw new Error(
      `Invalid nonce: ${auth.nonce} (expected 0x + 64 hex chars, got ${auth.nonce.length} chars)`
    )
  }

  // Validate signature format: must be 0x + 130 hex chars (65 bytes = r + s + v)
  const sigRegex = /^0x[0-9a-fA-F]{130}$/
  if (!sigRegex.test(payload.signature)) {
    throw new Error(
      `Invalid signature: expected 0x + 130 hex chars (65 bytes), got ${payload.signature.length} chars`
    )
  }

  // Validate bigint fields are non-negative numbers
  const value = BigInt(auth.value)
  const validAfter = BigInt(auth.validAfter)
  const validBefore = BigInt(auth.validBefore)
  if (value < 0n) throw new Error(`Invalid value: ${auth.value} (must be non-negative)`)
  if (validAfter < 0n) throw new Error(`Invalid validAfter: ${auth.validAfter} (must be non-negative)`)
  if (validBefore < 0n) throw new Error(`Invalid validBefore: ${auth.validBefore} (must be non-negative)`)

  // x402 v2 spec: the Authorization object inside payload does NOT include
  // v, r, s — only the full 65-byte signature. Extract them here so callers
  // who access signedAuth.v / signedAuth.r / signedAuth.s (e.g. for
  // transferWithAuthorization on-chain call) get correct values.
  //
  // ECDSA signature layout: 0x + r(32 bytes) + s(32 bytes) + v(1 byte)
  //   r = hex chars 2..66   (32 bytes)
  //   s = hex chars 66..130 (32 bytes)
  //   v = hex chars 130..132 (1 byte, recovery param)
  const sig = payload.signature as string
  const r = `0x${sig.slice(2, 66)}` as `0x${string}`
  const s = `0x${sig.slice(66, 130)}` as `0x${string}`
  const v = parseInt(sig.slice(130, 132), 16)

  return {
    from: auth.from as `0x${string}`,
    to: auth.to as `0x${string}`,
    value,
    validAfter,
    validBefore,
    nonce: auth.nonce as `0x${string}`,
    v,
    r,
    s,
    signature: sig as `0x${string}`,
  }
}

/**
 * Decode a PAYMENT-SIGNATURE header into the full PaymentPayload.
 *
 * Unlike `decodePaymentHeader` which extracts only the authorization,
 * this returns the complete PaymentPayload including `accepted`, `resource`,
 * and `extensions` — used by the server to validate the client's chosen
 * payment terms match what the server requires.
 *
 * @throws If the header is malformed or missing required fields
 */
export function decodeFullPaymentPayload(header: string): PaymentPayload {
  let jsonString: string

  if (typeof window !== 'undefined') {
    jsonString = atob(header)
  } else {
    jsonString = Buffer.from(header, 'base64').toString('utf-8')
  }

  const parsed = JSON.parse(jsonString)

  if (!parsed.payload) {
    throw new Error('Payment header missing payload')
  }
  if (!parsed.accepted) {
    throw new Error('Payment header missing accepted field (x402 v2 spec requires it)')
  }

  return parsed as PaymentPayload
}
