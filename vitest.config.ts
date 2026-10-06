import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.ts'],
    // The integration suite binds loopback ports and proxies real sockets.
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
})
