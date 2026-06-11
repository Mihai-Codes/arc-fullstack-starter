/**
 * x402Types.ts
 * ============
 * Shared TypeScript types for the x402 v2 protocol.
 *
 * WHAT THIS FILE TEACHES:
 * -----------------------
 *   • The exact wire format of every x402 v2 message
 *   • How types are shared between client and server (DRY)
 *   • The relationship between PaymentRequired, PaymentPayload, and SettlementResponse
 *
 * WHY A SEPARATE FILE?
 *   The x402 spec defines types independently of transport and scheme.
 *   By extracting them here, both client and server import the SAME types,
 *   guaranteeing they agree on field names, types, and structure.
 *   If the spec changes, one file updates both sides.
 *
 * x402 v2 SPEC COMPLIANCE:
 *   These types mirror the exact schema from:
 *   https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md
 *
 *   Section 5.1: PaymentRequired
 *   Section 5.2: PaymentPayload
 *   Section 5.3: SettlementResponse
 *   Section 5.4: VerifyResponse
 */

// ─────────────────────────────────────────────────────────────────────────────
// RESOURCE INFO (Section 5.1.2 — ResourceInfo)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Describes the protected resource being paid for.
 *
 * `url` is the only required field. The rest are optional metadata
 * that helps clients display useful info (description, icon, tags).
 */
export type ResourceInfo = {
  /** URL of the protected resource (e.g. '/api/premium') */
  url: string
  /** Human-readable description of the resource */
  description?: string
  /** MIME type of the expected response */
  mimeType?: string
  /** Human-readable service name (printable ASCII, max 32 chars) */
  serviceName?: string
  /** Topical tags for discovery filtering (max 5 entries, each max 32 chars) */
  tags?: string[]
  /** Absolute URL to an icon (max 2048 chars) */
  iconUrl?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT REQUIREMENTS (Section 5.1.2 — PaymentRequirements)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A single payment option in the `accepts` array.
 *
 * The server advertises what it accepts; the client picks one.
 * Multiple entries allow the server to accept different schemes/networks.
 */
export type PaymentRequirements = {
  /** Payment scheme identifier (e.g. "exact", "upto", "batch-settlement") */
  scheme: string
  /** Blockchain network in CAIP-2 format (e.g. "eip155:5042002") */
  network: string
  /** Required payment amount in atomic token units */
  amount: string
  /** Token contract address or ISO 4217 currency code for fiat */
  asset: string
  /** Recipient wallet address or role constant (e.g. "merchant") */
  payTo: string
  /** Maximum time allowed for payment completion (seconds) */
  maxTimeoutSeconds: number
  /** Scheme-specific additional information */
  extra?: Record<string, unknown>
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT REQUIRED (Section 5.1.1 — PaymentRequired)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The 402 response body and PAYMENT-REQUIRED header content.
 *
 * Sent by the server when no valid payment is attached to a request.
 * The client reads this, picks a compatible `accepts` entry, signs
 * a PaymentPayload, and retries.
 */
export type PaymentRequired = {
  /** Protocol version (must be 2) */
  x402Version: 2
  /** Optional human-readable error message */
  error?: string
  /** Describes the protected resource */
  resource: ResourceInfo
  /** Array of acceptable payment options */
  accepts: PaymentRequirements[]
  /** Protocol extensions data */
  extensions?: Record<string, unknown>
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTHORIZATION (Section 6.1.2 — exact EVM)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * EIP-3009 authorization parameters inside the PaymentPayload.
 *
 * The client signs this off-chain; the server's settler wallet
 * submits it on-chain via transferWithAuthorization.
 */
export type Authorization = {
  /** Payer's wallet address */
  from: string
  /** Recipient's wallet address */
  to: string
  /** Payment amount in atomic units */
  value: string
  /** Unix timestamp when authorization becomes valid */
  validAfter: string
  /** Unix timestamp when authorization expires */
  validBefore: string
  /** 32-byte random nonce to prevent replay attacks */
  nonce: string
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT PAYLOAD (Section 5.2.1 — PaymentPayload)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The client's signed payment authorization.
 *
 * Sent in the PAYMENT-SIGNATURE header. Contains the signature
 * and authorization parameters for the exact EVM scheme.
 */
export type PaymentPayload = {
  /** Protocol version */
  x402Version: number
  /** Resource being paid for (optional, echoes the 402 resource) */
  resource?: ResourceInfo
  /** The PaymentRequirements chosen from the server's 402 response */
  accepted: PaymentRequirements
  /** Scheme-specific payment data */
  payload: {
    /** EIP-712 signature (65 bytes, hex-encoded) */
    signature: string
    /** EIP-3009 authorization parameters */
    authorization: Authorization
  }
  /** Protocol extensions data */
  extensions?: Record<string, unknown>
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTLEMENT RESPONSE (Section 5.3.1 — SettlementResponse)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Server's settlement confirmation.
 *
 * Sent in the PAYMENT-RESPONSE header after payment is settled.
 * The client can use this to verify the payment was processed.
 */
export type SettlementResponse = {
  /** Whether settlement succeeded */
  success: boolean
  /** Blockchain transaction hash (empty string if settlement failed) */
  transaction: string
  /** Blockchain network in CAIP-2 format */
  network: string
  /** Address of the payer's wallet */
  payer?: string
  /** Error reason if settlement failed */
  errorReason?: string
  /** The actual amount settled in atomic units */
  amount?: string
  /** Protocol extensions data */
  extensions?: Record<string, unknown>
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFY RESPONSE (Section 5.4.1 — VerifyResponse)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Facilitator's verification response.
 *
 * Returned by POST /verify. Tells the server whether the
 * client's payment authorization is valid.
 */
export type VerifyResponse = {
  /** Whether the payment authorization is valid */
  isValid: boolean
  /** Reason for invalidity (omitted if valid) */
  invalidReason?: string
  /** Address of the payer's wallet */
  payer?: string
  /** Scheme-specific additional data */
  extra?: Record<string, unknown>
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPPORTED RESPONSE (Section 7.3.1 — SupportedResponse)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Facilitator's supported schemes/networks response.
 *
 * Returned by GET /supported. Tells clients what the facilitator can handle.
 */
export type SupportedKind = {
  x402Version: number
  scheme: string
  network: string
  extra?: Record<string, unknown>
}

export type SupportedResponse = {
  /** Array of supported payment kind objects */
  kinds: SupportedKind[]
  /** Array of extension identifiers implemented */
  extensions: string[]
  /** Map of CAIP-2 patterns to signer addresses */
  signers: Record<string, string[]>
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATION CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/** Protocol version — all messages must declare this */
export const X402_VERSION = 2 as const

/** CAIP-2 network identifier for Arc Testnet */
export const ARC_TESTNET_CAIP2 = 'eip155:5042002' as const

/** ECDSA signature length in hex chars (0x + 130 hex = 65 bytes) */
export const SIGNATURE_HEX_LENGTH = 132 as const

/** Nonce length in hex chars (0x + 64 hex = 32 bytes) */
export const NONCE_HEX_LENGTH = 66 as const
