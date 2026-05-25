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

### 2. Simplified Example Implementations
- **[frontend/src/lib/sessionKey.example.ts](./frontend/src/lib/sessionKey.example.ts)**: Pure-functional session key generation, EIP-712 auth message builder, budget, and sessionStorage lifecycle.
- **[frontend/src/lib/eip3009.example.ts](./frontend/src/lib/eip3009.example.ts)**: Constructing and signing EIP-3009 meta-transactions using the session key's private key.
- **[frontend/src/lib/x402Client.example.ts](./frontend/src/lib/x402Client.example.ts)**: A drop-in `fetch` wrapper that auto-intercepts `402`, handles background signing, and retries with payment headers.

### 3. Runnable Local Simulation (No Browser Required)
- **[scripts/x402_full_demo.ts](./scripts/x402_full_demo.ts)**: A standalone Node.js script that simulates the entire user approval, 402 rejection, session key signing, and successful server settlement flow.

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
