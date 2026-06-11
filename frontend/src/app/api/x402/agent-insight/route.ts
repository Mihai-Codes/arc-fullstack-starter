/**
 * Example: x402-Protected API Route
 * ==================================
 * A complete example of how to gate an API endpoint behind x402 micropayments.
 *
 * WHAT THIS FILE TEACHES:
 * -----------------------
 *   • How to use withX402() to protect any Next.js App Router route
 *   • Dynamic pricing (different costs for different queries)
 *   • The full server-side x402 flow in a real endpoint
 *   • How to structure a response that works with the x402 client
 *
 * TRY IT:
 *   1. Start the dev server: npm run dev
 *   2. Hit the endpoint without payment:
 *      curl http://localhost:3000/api/x402/agent-insight
 *      → 402 with payment requirements
 *   3. The x402 client (x402Client.example.ts) handles this automatically
 *
 * PRICING MODEL:
 *   This endpoint charges $0.001 per request (1000 USDC atomic units).
 *   In production, you might charge based on:
 *     - Query complexity (simple vs deep analysis)
 *     - Data freshness (real-time vs cached)
 *     - User tier (free vs premium)
 */

import { withX402 } from '@/lib/x402Server.example'

// ─── Route Configuration ───────────────────────────────────────────────────
//
// In production, these would come from environment variables.
// Hardcoded here for clarity in the example.

const TREASURY_ADDRESS = '0x8888888888888888888888888888888888888888'
const RPC_URL = process.env.ARC_RPC_URL || 'https://rpc.testnet.arc.network'
const USDC_ADDRESS = process.env.NEXT_PUBLIC_USDC_ARC_ADDRESS || '0x3600000000000000000000000000000000000000'
const SETTLER_KEY = process.env.ARC_SETTLER_PRIVATE_KEY || '0x...'

// ─── The Protected Handler ─────────────────────────────────────────────────
//
// This is your actual business logic. It doesn't know about x402.
// The withX402() middleware wraps it with payment gating.
//
// IMPORTANT: This handler is only called AFTER payment succeeds.
// You don't need to check for payment here — the middleware handles it.

async function handleAgentInsight(req: Request): Promise<Response> {
  // Parse the query from the request
  const url = new URL(req.url)
  const query = url.searchParams.get('query') || 'What is the current market sentiment?'

  // Simulate some AI/agent work
  // In production, this would call your LLM, data pipeline, etc.
  const insight = {
    query,
    analysis: `Based on current market data, the sentiment for "${query}" is cautiously optimistic.`,
    confidence: 0.82,
    timestamp: new Date().toISOString(),
    dataSources: ['CoinGecko', 'DeFiLlama', 'Arc on-chain data'],
  }

  return Response.json(insight)
}

// ─── Export the x402-Gated Handler ─────────────────────────────────────────
//
// withX402() wraps your handler with payment gating.
// When a request arrives:
//   1. No payment header → 402 with requirements
//   2. Payment header present → verify → settle → call handleAgentInsight()
//
// The export name (GET) must match the HTTP method you want to protect.
// You can also export POST, PUT, DELETE, etc.

export const GET = withX402(
  {
    resource: '/api/x402/agent-insight',
    priceUsdc: 0.001, // $0.001 per request
    description: 'AI agent market insight',
    treasuryAddress: TREASURY_ADDRESS,
    rpcUrl: RPC_URL,
    usdcAddress: USDC_ADDRESS,
    settlerPrivateKey: SETTLER_KEY,
    // Set to false for demo/prototype (verifies signature but doesn't settle on-chain)
    // Omit or set to true for production (settles USDC on Arc)
    settleOnChain: false,
  },
  handleAgentInsight
)
