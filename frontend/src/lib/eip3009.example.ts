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

// ─── TYPES & CONFIGS ────────────────────────────────────────────────────────

/**
 * CAIP-2 network identifier for Arc Testnet.
 * Used in x402 PaymentPayload.network and PaymentRequired.accepts.network.
 * Ref: https://github.com/ChainAgnostic/namespaces/blob/main/CAIPs/caip-2.md
 */
export const ARC_TESTNET_CAIP2 = 'eip155:5042002' as const

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
 */
export function encodePaymentHeader(signed: SignedAuthorization): string {
  const paymentPayload = {
    x402Version: 2,
    // x402 v2 spec: PaymentPayload includes the resource being paid for
    // and the accepted payment terms — these echo back the server's 402 response
    // so the server can verify the client is paying for the correct resource.
    resource: undefined, // populated by the caller (x402Client) when available
    accepted: undefined, // populated by the caller (x402Client) when available
    scheme: 'exact',
    // CAIP-2 network identifier for Arc Testnet
    // Must match the server's 402 response (x402Server.example.ts line ~440)
    // Ref: https://github.com/ChainAgnostic/namespaces/blob/main/CAIPs/caip-2.md
    network: ARC_TESTNET_CAIP2,
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

  // Validate bigint fields are non-negative numbers
  const value = BigInt(auth.value)
  const validAfter = BigInt(auth.validAfter)
  const validBefore = BigInt(auth.validBefore)
  if (value < 0n) throw new Error(`Invalid value: ${auth.value} (must be non-negative)`)
  if (validAfter < 0n) throw new Error(`Invalid validAfter: ${auth.validAfter} (must be non-negative)`)
  if (validBefore < 0n) throw new Error(`Invalid validBefore: ${auth.validBefore} (must be non-negative)`)

  return {
    from: auth.from as `0x${string}`,
    to: auth.to as `0x${string}`,
    value,
    validAfter,
    validBefore,
    nonce: auth.nonce as `0x${string}`,
    // v, r, s are not part of the x402 v2 PaymentPayload spec.
    // The full 65-byte signature is sufficient for ecrecover.
    // These are kept as 0 defaults for backwards compatibility with
    // code that accesses signedAuth.v / signedAuth.r / signedAuth.s.
    v: auth.v ?? 0,
    r: (auth.r ?? '0x0000000000000000000000000000000000000000000000000000000000000000') as `0x${string}`,
    s: (auth.s ?? '0x0000000000000000000000000000000000000000000000000000000000000000') as `0x${string}`,
    signature: payload.signature as `0x${string}`,
  }
}
