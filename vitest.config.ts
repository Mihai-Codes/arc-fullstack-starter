import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // jsdom environment provides window, sessionStorage, crypto.getRandomValues
    // — required for session-key.test.ts
    environment: 'jsdom',

    // Expose describe/test/expect/vi globally (no import needed in test files)
    globals: true,

    // Test file patterns
    include: ['tests/**/*.test.ts'],

    // Coverage via v8 (built into Node — no Babel needed)
    coverage: {
      provider: 'v8',
      include: ['frontend/src/lib/**/*.ts'],
      exclude: ['**/*.example.ts'],  // example files are teaching material, not production
      reporter: ['text', 'lcov'],
    },
  },
})
