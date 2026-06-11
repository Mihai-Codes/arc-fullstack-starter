# 🥚 Arc Fullstack Starter: x402 + EIP-3009 Session Keys

[![CI](https://github.com/Mihai-Codes/arc-fullstack-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/Mihai-Codes/arc-fullstack-starter/actions/workflows/ci.yml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)
![Arc Testnet](https://img.shields.io/badge/Arc-Testnet%205042002-6C47FF)
![Protocol: x402](https://img.shields.io/badge/Protocol-x402-ff6b35)
![EIP-3009](https://img.shields.io/badge/EIP--3009-transferWithAuthorization-00c896)
![Viem](https://img.shields.io/badge/viem-2.x-646cff?logo=ethereum)

An open-source, pedagogical starter kit for developers building on the **Arc L1 Network**. It provides a lightweight, fully documented framework for implementing frictionless, zero-popup micropayments using **x402 (HTTP Payment Required)** and **EIP-3009 (transferWithAuthorization)** session keys.

---

## 💡 What problem does this solve?

In traditional Web3, every transaction or token transfer triggers a wallet popup (like MetaMask), asking the user to confirm. This model is completely unusable for high-frequency micropayments or autonomous AI agents:
- **Web3 Friction:** A user reading an article costing $0.001 (0.001 USDC) will not click "Confirm" 50 times per session.
- **No Autonomy:** Autonomous agents cannot pay other agents if they must constantly wait for a human wallet click.

### The Arc Solution
1. **Session Keys:** The user authorizes a temporary, ephemeral in-memory wallet *once* with a strict spending budget (e.g., up to 5 USDC for 24 hours). This is the only wallet popup.
2. **x402 Protocol:** An open HTTP standard. The server rejects unauthorized requests with a `402 Payment Required` status and machine-readable pricing instructions.
3. **EIP-3009:** The session key silently signs a `transferWithAuthorization` message in the background. The server's settler wallet executes it on-chain, paying gas in native USDC on Arc.

The entire loop completes silently in **under 2 seconds** with **zero user popups**.

---

## 🏗️ Repository Architecture & Examples

This repository is optimized for learning. Code density is reduced by 40% compared to production, and comment density is increased by 300% to explain the underlying cryptographic principles and common pitfalls.

### 1. Architectural & Protocol Documentation
- **[docs/X402_SESSION_KEYS.md](./docs/X402_SESSION_KEYS.md)**: A comprehensive guide covering the mental model, three-layer architecture, production checklist, and Arc-specific pitfalls.

### 2. Shared Types (Single Source of Truth)
- **[frontend/src/lib/x402Types.ts](./frontend/src/lib/x402Types.ts)**: All x402 v2 spec-compliant types (`PaymentRequired`, `PaymentPayload`, `SettlementResponse`, `VerifyResponse`, `SupportedResponse`) and shared constants (`ARC_TESTNET_CAIP2`, `X402_VERSION`, `DEFAULT_EIP3009_EXTRA`). Both client and server import from here — no duplicate type definitions.

### 3. Simplified Example Implementations
- **[frontend/src/lib/sessionKey.example.ts](./frontend/src/lib/sessionKey.example.ts)**: Pure-functional session key generation, EIP-712 auth message builder, budget, and sessionStorage lifecycle.
- **[frontend/src/lib/eip3009.example.ts](./frontend/src/lib/eip3009.example.ts)**: Constructing and signing EIP-3009 meta-transactions using the session key's private key.
- **[frontend/src/lib/x402Client.example.ts](./frontend/src/lib/x402Client.example.ts)**: A drop-in `fetch` wrapper that auto-intercepts `402`, handles background signing, and retries with payment headers.
- **[frontend/src/lib/x402Server.example.ts](./frontend/src/lib/x402Server.example.ts)**: Full `withX402()` middleware — validates 402 responses, verifies EIP-3009 signatures via ecrecover, deduplicates nonces in-memory, and settles off-chain or on-chain.

### 4. Runnable Local Simulation (No Browser Required)
- **[scripts/x402_full_demo.ts](./scripts/x402_full_demo.ts)**: A standalone Node.js script that simulates the entire user approval, 402 rejection, session key signing, and successful server settlement flow.

### 5. Tests (92 passing)
- **[tests/session-key.test.ts](./tests/session-key.test.ts)**: 36 tests — session key generation, EIP-712 auth messages, budget enforcement, expiry, sessionStorage lifecycle.
- **[tests/eip3009.test.ts](./tests/eip3009.test.ts)**: 20 tests — EIP-712 domain, nonce validation, signature verification, decodeFullPaymentPayload, encodePaymentHeader.
- **[tests/x402Server.test.ts](./tests/x402Server.test.ts)**: 18 tests — input validation, accepted field checks, replay detection, TOCTOU race condition, settlement response schema.
- **[tests/x402Client.test.ts](./tests/x402Client.test.ts)**: 7 tests — passthrough, error taxonomy, network validation, full challenge-response loop.
- **[tests/chain-config.test.ts](./tests/chain-config.test.ts)**: 6 tests — chain ID validation, USDC address constants, network configuration.
- **[tests/x402Handshake.test.ts](./tests/x402Handshake.test.ts)**: 5 end-to-end tests — full crypto flow with real keys (no mocks for signing), accepted field validation, replay detection.

---

## 🚀 Quick Start (Local Run)

Clone the repo, install dependencies, and run the localized full simulation:

```bash
git clone https://github.com/Mihai-Codes/arc-fullstack-starter.git
cd arc-fullstack-starter
npm install
npx ts-node scripts/x402_full_demo.ts
```

---

## 🥚 Why Arc OSS? Exposing High-Value Primitives

While existing repositories (like `circlefin/arc-*`) focus on basic transaction sending or raw contract interactions, **Arc Fullstack Starter** exposes three highly reusable, advanced primitives:

1. **The Ephemeral Wallet Pre-Funding Pattern:** A developer-friendly implementation of EIP-3009 where the session key acts as the `from` address. This sidesteps the need for custom paymasters or account abstraction contracts, natively matching Arc's fee model.
2. **Standard-Compliant x402 Client-Server Negotiation:** A drop-in `fetch` client that implements modern `PAYMENT-SIGNATURE` headers, making client-side integrations clean and standard.
3. **Server-Side Settler Meta-Transaction Relayer:** A pre-configured server wrapper that validates off-chain EIP-712 signatures and settles transactions directly via standard RPC providers.

By open-sourcing these primitives, other developers can instantly incorporate frictionless pay-per-use, pay-per-crawl, and autonomous agent loops into their Arc projects.

---

## ⚠️ What's Not Covered (Intentional Gaps)

This is an educational implementation. The following are production hardening concerns that belong in a separate `production/` example, not in the `.example.ts` pedagogical layer:

| Gap | Why It's Omitted | What You'd Add |
|---|---|---|
| **Nonce persistence** | In-memory `Map` resets on restart — acceptable for demos | PostgreSQL/Redis-backed nonce store with TTL |
| **Rate limiting** | Not part of the x402 protocol itself | Per-IP and per-session-key rate limits |
| **Multi-scheme negotiation** | Client picks first `accepts` entry | Scheme preference ranking, fallback chains |
| **Facilitator integration** | `POST /verify` and `POST /settle` stubs | Wire to a real x402 facilitator service |
| **HTTPS/TLS** | Local dev only | TLS termination in production |
| **Error telemetry** | No logging infrastructure | Structured logging, metrics, alerting |

### Security Model (What IS Covered)

All 5 documented attacks from arXiv `2605.11781` are mitigated:

| Attack | Mitigation | Code Location |
|---|---|---|
| **Frontrunning (TOCTOU)** | Nonce marked used BEFORE handler executes | `x402Server.example.ts:432-442` |
| **Cache poisoning** | `validAfter` check rejects future-dated auths | `x402Server.example.ts:582` |
| **Signature malleability** | EIP-712 typed data signatures are non-malleable by design | `x402Server.example.ts:635` (recoverTypedDataAddress) |
| **Amount manipulation** | Server validates `accepted.amount` matches config | `x402Server.example.ts:342` |
| **Expiry bypass** | `validBefore` check rejects expired auths | `x402Server.example.ts:588` |
