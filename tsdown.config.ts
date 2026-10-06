/**
 * Standalone build for the host half of the plugin.
 *
 * `lib/index.js` is the loader entry; `lib/password.js` and `lib/totp.js` are
 * small standalone entries the enrollment script imports without loading the
 * Cordis plugin. Every `@deepseek-ai/*` specifier stays external and resolves
 * from the running installation.
 */
import type { UserConfig } from 'tsdown'

const config: UserConfig = {
  name: 'dsh-login-gateway',
  entry: ['src/index.ts', 'src/password.ts', 'src/totp.ts'],
  outDir: 'lib',
  format: ['esm'],
  platform: 'node',
  target: 'es2024',
  fixedExtension: false,
  dts: false,
  // `tsc` writes lib/types first; a clean pass here would delete it.
  clean: false,
  deps: { neverBundle: [/^@deepseek-ai\//] },
}

export default config
