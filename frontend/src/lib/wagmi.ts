/**
 * wagmi.ts
 * ========
 * Arc Testnet chain configuration.
 *
 * This file defines the chain object used by wagmi/RainbowKit to:
 *   - Add Arc Testnet to MetaMask via wallet_addEthereumChain
 *   - Resolve the correct RPC endpoint for viem clients
 *   - Display the correct block explorer links
 *
 * CRITICAL DETAILS:
 *   - Chain ID:  5042002 (Arc Testnet)
 *   - Currency:  USDC (not ETH!) — 6 decimals, NOT 18
 *   - RPC:       https://rpc.arc.fun
 *   - Explorer:  https://arcscan.net
 *
 * Why USDC as native currency?
 *   Arc is a stablecoin-native chain — all gas fees are denominated
 *   in USDC. This removes the need for users to hold a separate
 *   "gas token" (like ETH on mainnet), simplifying onboarding.
 *   The 6-decimal precision matches USDC's standard (not Ethereum's 18).
 */

import { defineChain } from 'viem'

export const arcTestnet = defineChain({
  id: 5042002,
  name: 'Arc Testnet',
  nativeCurrency: {
    name: 'USD Coin',
    symbol: 'USDC',
    decimals: 6,           // ← CRITICAL: USDC uses 6 decimals, NOT 18
  },
  rpcUrls: {
    default: {
      http: ['https://rpc.arc.fun'],
    },
  },
  blockExplorers: {
    default: {
      name: 'ArcScan',
      url: 'https://arcscan.net',
    },
  },
  testnet: true,
})
