# x402 + EIP-3009 Session Keys on Arc
## A Complete Builder's Guide

> **Who is this for?** Developers building on Arc L1 who want frictionless micropayments, pay-per-use APIs, or autonomous agent-to-agent payment loops — without a wallet popup for every transaction.

---

## Table of Contents

1. [What is x402?](#1-what-is-x402)
2. [What are Session Keys?](#2-what-are-session-keys)
3. [Why the Combination Unlocks Agent Payments](#3-why-the-combination-unlocks-agent-payments)
4. [The Full Flow (ASCII Diagram)](#4-the-full-flow-ascii-diagram)
5. [Arc-Specific Pitfalls](#5-arc-specific-pitfalls)
6. [Production Considerations](#6-production-considerations)
7. [Quick Reference](#7-quick-reference)

---

## 1. What is x402?

### The HTTP 402 Status Code — A Standard That Lay Dormant for 30 Years

HTTP 1.0 (1996) defined status code `402 Payment Required` as reserved for future use. For three decades, it sat unused. The x402 protocol finally activates it.

**The core idea:** HTTP already has a well-understood challenge-response pattern. `401 Unauthorized` means "you need credentials — here's how to authenticate." x402 makes `402` mean the same thing for payments: "you need to pay — here's exactly what it costs and how to pay it."

```
Traditional auth challenge (401):
  Client → GET /api/resource
  Server ← 401 { "scheme": "Bearer", "realm": "login at /auth" }
  Client → GET /api/resource + Authorization: Bearer <token>
  Server ← 200 { data }

x402 payment challenge (402):
  Client → GET /api/resource
  Server ← 402 { "accepts": [{ "amount": "1000", "payTo": "0x..." }] }
  Client → GET /api/resource + PAYMENT-SIGNATURE: <base64-signed-auth>
  Server ← 200 { data }
```

### What the 402 Response Body Contains

```json
{
  "accepts": [
    {
      "scheme": "exact",
      "network": "arc-testnet-5042002",
      "maxAmountRequired": "1000",
      "payTo": "0x8888888888888888888888888888888888888888",
      "asset": "0xUSDC_CONTRACT_ADDRESS",
      "maxTimeoutSeconds": 300
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `scheme` | `"exact"` = pay exactly this amount |
| `network` | Chain identifier — `"arc-testnet-5042002"` for Arc Testnet |
| `maxAmountRequired` | Amount in **atomic units** (6 decimals). `"1000"` = $0.001 USDC |
| `payTo` | Recipient/treasury wallet address |
| `asset` | USDC contract address on Arc |
| `maxTimeoutSeconds` | `validBefore` must be within this many seconds of now |

### Why x402 Matters for AI Agents

Traditional APIs authenticate by identity ("who are you?"). x402 authenticates by payment ("did you pay?"):

- **No accounts required.** An AI agent can call any x402-gated API on first contact — no registration, no OAuth.
- **Programmable authorization.** Any software can evaluate a `402` and decide autonomously whether to pay.
- **Composable.** Any API becomes revenue-generating by adding a single middleware layer.

---

## 2. What are Session Keys?

### The Problem: Wallet Popups at Scale

Every wallet signature triggers a popup. For micropayments ($0.001 per article), a user reading 10 articles sees 10 popups. Completely unusable.

### The Solution: Delegate Signing Authority Once

A session key is a temporary, in-memory `secp256k1` keypair that the user authorizes once to act on their behalf within strict limits.

**Mental model:** A prepaid gift card.

1. The user "loads" USDC onto a fresh temporary address (the session key).
2. The user signs a message: "this temp address can spend up to 5 USDC in 24 hours."
3. All subsequent micropayments are signed silently by the session key.
4. When the tab closes, the key is wiped automatically.

### Session Key Properties

| Property | Value | Why |
|----------|-------|-----|
| **Storage** | `sessionStorage` only | Auto-cleared when tab closes; never `localStorage` |
| **Lifetime** | e.g. 24 hours | Limits blast radius if compromised |
| **Budget** | e.g. 5 USDC | Hard ceiling on financial exposure |
| **Scope** | Per allowed contract | Restricts what the key can pay |
| **Revocation** | Delete from sessionStorage | Instant, no on-chain transaction needed |

### The Ephemeral Wallet Pre-Funding Pattern

This is the key architectural insight that makes x402 + EIP-3009 work on Arc **without paymasters**:

```
Step 1: Generate temporary keypair
  privateKey    = generatePrivateKey()         // secure random
  sessionAddress = privateKeyToAccount(pk).address

Step 2: User sends USDC to the session address
  userWallet.transfer(USDC, sessionAddress, 5.0)
  // sessionAddress now holds 5 USDC — both budget AND gas

Step 3: For each payment, sign EIP-3009 as sessionAddress
  signature = sessionKey.signTypedData({
    from: sessionAddress,   // ← session key IS the "from"
    to: treasuryAddress,
    value: 1000n,           // 0.001 USDC in atomic units
    ...
  })

Step 4: Server settler submits auth on-chain
  USDC.transferWithAuthorization(from, to, value, ..., signature)
  // USDC moves: sessionAddress → treasuryAddress
```

**Critical EIP-3009 invariant:** `ecrecover(signature) MUST equal the 'from' address.`
The private key that signs must control the `from` address. Since the session key *is* the `from` address and holds the USDC, this always holds.

---

## 3. Why the Combination Unlocks Agent-to-Agent Payments

### The Agentic Payment Stack

```
┌─────────────────────────────────────────────┐
│               Application Layer             │
│   (AI agent, web app, API consumer)         │
├─────────────────────────────────────────────┤
│              x402 Protocol Layer            │
│   (HTTP 402 negotiation, header encoding)   │
├─────────────────────────────────────────────┤
│           EIP-3009 Authorization Layer      │
│   (typed data signing, meta-transactions)   │
├─────────────────────────────────────────────┤
│               Arc Network Layer             │
│   (USDC as native gas, EVM-compatible L1)   │
└─────────────────────────────────────────────┘
```

### Why Arc Makes This Uniquely Viable

On Ethereum, gas is paid in ETH. A fresh session key with only USDC can't submit transactions — hence paymasters are needed.

On Arc, **USDC is the native gas token.** Pre-funding a session key with USDC simultaneously:
1. Gives it a spending budget for x402 payments.
2. Gives it gas for any on-chain transactions it submits.
3. Eliminates the need for a paymaster contract entirely.

### Agent-to-Agent Payment Loop

```
AI Agent A (buyer)                    AI Agent B (seller)
      │                                       │
      │── POST /api/analyze ─────────────────►│
      │◄── 402 { amount: "5000", ... } ───────│  "$0.005 per call"
      │                                       │
      │  [no human involved]                  │
      │  [agent evaluates cost autonomously]  │
      │  [signs EIP-3009 with session key]    │
      │                                       │
      │── POST /api/analyze ─────────────────►│
      │   PAYMENT-SIGNATURE: <base64>         │
      │◄── 200 { result: ... } ───────────────│
      │                                       │
   Agents chain calls indefinitely.           │
   No human approval after initial setup.     │
```

---

## 4. The Full Flow (ASCII Diagram)

```
USER BROWSER / AI AGENT                             ARC NETWORK
──────────────────────────────────────────────────────────────────

[ONE-TIME SETUP — user approves once per session]

User Wallet              Session Key (ephemeral)     USDC Contract
    │                          │                          │
    │  1. generatePrivateKey() │                          │
    │ ─────────────────────────►                          │
    │     sessionAddress=0xSK  │                          │
    │                          │                          │
    │  2. transfer(SK, 5 USDC) │                          │
    │ ──────────────────────────────────────────────────► │
    │     SK now holds 5 USDC  │         funded ✓         │
    │                          │                          │
    │  3. signTypedData(        │                          │
    │       SessionKeyAuth{     │                          │
    │         maxAmount: 5 USDC,│                          │
    │         expiry: 24h })    │                          │
    │ ──────────────────────────► stored in sessionStorage │
    │     authorizationSig ✓   │                          │

[PER-REQUEST — silent, no popups after setup]

x402 Client              Protected API              Settler Wallet
    │                         │                          │
    │── GET /api/resource ───►│                          │
    │◄── 402 {                │                          │
    │     amount: "1000",     │                          │
    │     payTo: 0xTREAS,     │                          │
    │     timeout: 300        │                          │
    │   }                     │                          │
    │                         │                          │
    │ [build EIP-3009 auth]   │                          │
    │   from: sessionKey.addr │                          │
    │   to: 0xTREAS           │                          │
    │   value: 1000n          │                          │
    │   validBefore: now+300  │  ← NEVER use 0 or past   │
    │   nonce: randomBytes32  │  ← NEVER reuse           │
    │                         │                          │
    │ [sign in-memory,        │                          │
    │  no popup, ~1ms]        │                          │
    │                         │                          │
    │── GET /api/resource ───►│                          │
    │   PAYMENT-SIGNATURE: b64│                          │
    │                         │ [decode + verify sig]    │
    │                         │ [check validBefore > now]│
    │                         │── submitTx ─────────────►│
    │                         │   USDC.transferWith       │
    │                         │   Authorization(...)      │
    │◄── 200 { data } ────────│◄──── settled on-chain ───│
    │                         │                          │
    │ [recordSpend(0.001)]    │                          │
    │ [budget: 4.999 USDC]    │                          │
```

---

## 5. Arc-Specific Pitfalls

These mistakes silently break signature verification on Arc. All are real footguns.

---

### ❌ Pitfall 1: Using 18 Decimals Instead of 6

```typescript
// ❌ WRONG: ETH-style 18 decimals — sends 10^12 USDC per request
const amount = parseUnits('1', 18)   // → 1_000_000_000_000_000_000n

// ✅ CORRECT: USDC has 6 decimals
const amount = parseUnits('0.001', 6)               // → 1000n
// Or manually:
const amount = BigInt(Math.round(0.001 * 1_000_000)) // → 1000n
```

**Rule:** On Arc, $1 USDC = `1_000_000` atomic units. Always `× 1_000_000`, never `× 1e18`.

---

### ❌ Pitfall 2: Forgetting validBefore (or Setting It to 0)

```typescript
// ❌ WRONG: USDC contract rejects with "authorization is expired"
const auth = { validAfter: 0n, validBefore: 0n, ... }

// ✅ CORRECT: derive from the server's maxTimeoutSeconds
const validBefore = BigInt(
  Math.floor(Date.now() / 1000) + requirement.maxTimeoutSeconds
)
```

**Rule:** Always derive `validBefore` from the server's `maxTimeoutSeconds`. Never hardcode. Never use `0`.

---

### ❌ Pitfall 3: Wrong EIP-712 Domain Name for USDC

```typescript
// ❌ ALL WRONG — one character off = completely different hash = garbage ecrecover
domain: { name: 'USDC', ... }
domain: { name: 'USD Coin (PoS)', ... }
domain: { name: 'usdc', ... }    // case-sensitive!

// ✅ CORRECT
domain: {
  name: 'USD Coin',       // exact canonical name, case-sensitive
  version: '2',           // version "2", not "1"
  chainId: 5042002,       // Arc Testnet chain ID
  verifyingContract: USDC_ADDRESS,
}
```

**Rule:** EIP-712 includes the domain in the signed hash. One character difference = wrong hash = ecrecover returns a garbage address = signature rejected. Verify by reading `USDC.DOMAIN_SEPARATOR()` from the contract.

---

### ❌ Pitfall 4: Assuming You Need a Paymaster

```typescript
// ❌ UNNECESSARY on Arc — adds complexity you don't need
const paymasterData = await getPaymasterData(sessionKeyAddress)
```

On Ethereum, fresh addresses need ETH for gas. On Arc, **USDC IS the native gas token.** Funding a session key with USDC simultaneously funds its payment budget AND its gas. No paymaster. No account abstraction. Just send USDC.

---

## 6. Production Considerations

### Nonce Management

EIP-3009 nonces are **not sequential** — they are random `bytes32` values tracked in:
`mapping(address => mapping(bytes32 => bool)) authorizationState`

```typescript
// Always generate a fresh cryptographically secure nonce
function generateNonce(): `0x${string}` {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)  // OS CSPRNG — NOT Math.random()
  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`
}
// Never reuse nonces — same nonce = "authorization is used" rejection on-chain
```

### Replay Protection Layers

| Layer | Mechanism |
|-------|-----------|
| **Temporal** | `validBefore` makes the auth useless after the timeout window |
| **Uniqueness** | `nonce` tracked on-chain; same nonce = rejected |
| **Chain isolation** | `chainId` in domain prevents cross-chain replays |
| **Contract isolation** | `verifyingContract` prevents replay on different USDC deployments |

### Session Key Revocation on Compromise

**Immediate client-side (stops all future signing):**
```typescript
sessionStorage.removeItem('your_app_session_key')
```

**On-chain fund recovery:**
Sign another `transferWithAuthorization` from the session key, sending its remaining USDC back to the user's main wallet. This zeroes the balance before an attacker can drain it.

**Why no cancel-session contract is needed:**
- Session key only controls its own pre-funded USDC — never the user's main wallet.
- `allowedContracts` scope limits what it can pay.
- `expirySeconds` provides a hard time ceiling.
- Financial exposure is bounded: `min(sessionBudget, timeRemaining × maxRate)`.

### Server-Side Settler Security

1. **Verify the EIP-712 signature** before submitting — don't blindly relay.
2. **Check `validBefore > block.timestamp`** server-side before paying gas.
3. **Idempotency:** Log used nonces server-side to reject duplicates before they hit the chain.
4. **Rate limiting:** Per-IP and per-session-key rate limits to prevent DoS that drains settler gas.
5. **Separation:** The settler key signs transactions but doesn't hold treasury funds.

---

## 7. Quick Reference

### Arc Network Constants

```typescript
const ARC_CHAIN_ID        = 5042002
const USDC_DECIMALS       = 6
const USDC_EIP712_NAME    = 'USD Coin'  // exact, case-sensitive
const USDC_EIP712_VERSION = '2'

// Human-readable USDC → atomic units
const toAtomic = (usdc: number) => BigInt(Math.round(usdc * 1_000_000))
// toAtomic(0.001) → 1000n
// toAtomic(5.0)   → 5000000n
```

### Pre-Launch Checklist

- [ ] USDC `value` uses 6 decimals, not 18
- [ ] `validBefore` = `now + maxTimeoutSeconds` (never `0`)
- [ ] EIP-712 domain `name` is exactly `"USD Coin"`, `version` is `"2"`
- [ ] `chainId` is `5042002` in the EIP-712 domain
- [ ] Session keys stored in `sessionStorage` (not `localStorage`)
- [ ] Fresh random `bytes32` nonce per authorization
- [ ] Settler verifies signature before submitting on-chain
- [ ] Session key budget enforced both client-side AND server-side
- [ ] No paymaster logic — USDC funds gas natively on Arc

### Repository File Map

| File | Purpose |
|------|---------|
| `docs/X402_SESSION_KEYS.md` | This guide |
| `frontend/src/lib/sessionKey.example.ts` | Session key generation, storage, lifecycle |
| `frontend/src/lib/eip3009.example.ts` | EIP-3009 signing, header encoding/decoding |
| `frontend/src/lib/x402Client.example.ts` | x402-aware fetch wrapper |
| `scripts/x402_demo.ts` | Minimal runnable demo: 402 → sign → retry → success |
| `scripts/x402_full_demo.ts` | Extended demo with full session key lifecycle |
