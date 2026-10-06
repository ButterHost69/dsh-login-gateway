/**
 * Host half of `dsh-login-gateway`.
 *
 * Adds an authenticated front door to a Web profile. The plugin listens on its
 * own loopback port, serves a username + password + TOTP login form, and
 * forwards authenticated traffic to the running harness web server — including
 * WebSocket upgrades — so a tunnel or reverse proxy can expose the harness
 * without exposing an unauthenticated API.
 *
 * The harness keeps its own launch-token authentication. This plugin performs
 * that exchange server-side through `ctx.connection.authenticatedUrl` and
 * attaches the resulting cookie to forwarded requests, so neither the launch
 * token nor the harness cookie reaches the browser.
 *
 * @module dsh-login-gateway
 */

import type { Context } from '@deepseek-ai/cordis'
import { Config as ConfigSchema, resolveConfig, type LoginGatewayConfig } from './config.ts'
import { createLoginGateway } from './gateway.ts'
import { createUpstreamCookieProvider } from './upstream-auth.ts'
// Type-only: applies the ctx.webServer and ctx.connection Context merges.
import type {} from './types.ts'

export type {
  LoginGatewayConfig,
  ResolvedConfig,
  SessionConfig,
  TotpConfig,
  UserConfig,
} from './config.ts'
export { hashPassword, parsePasswordHash, verifyPassword } from './password.ts'
export {
  DEFAULT_TOTP_OPTIONS,
  generateTotp,
  generateTotpSecret,
  totpUri,
  verifyTotp,
} from './totp.ts'
export type { TotpAlgorithm, TotpOptions } from './totp.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-login-gateway'

/** Services required before the gateway can start. */
export const inject = ['webServer', 'connection']

/** Plugin configuration schema. */
export const Config = ConfigSchema

/**
 * Start the login gateway in front of the running web server.
 * @param ctx - host context carrying `webServer` and `connection`.
 * @param config - validated plugin configuration.
 */
export async function apply(ctx: Context, config?: LoginGatewayConfig): Promise<void> {
  const resolved = resolveConfig(config, ctx.webServer.port)
  const upstream = { host: resolved.upstreamHost, port: resolved.upstreamPort }
  const cookies = createUpstreamCookieProvider({
    upstream,
    authenticatedUrl: baseUrl => ctx.connection.authenticatedUrl(baseUrl),
  })
  const gateway = createLoginGateway(resolved, {
    upstreamCookie: authority => cookies.cookieFor(authority),
    logger: {
      info: (message: string) => { ctx.logger.info(message) },
      warn: (message: string) => { ctx.logger.warn(message) },
    },
  })
  await gateway.start()
  ctx.effect(() => () => gateway.stop(), 'dsh-login-gateway: listener')
  // The sign-in URL is an operator readiness signal, like the `dsh web:` line,
  // so it is printed rather than left to the profile's log level.
  console.log(
    `dsh-login-gateway: sign in at ${gateway.url}${resolved.loginPath} `
    + `(forwarding to http://${upstream.host}:${String(upstream.port)})`,
  )
  if (resolved.listenHost === '0.0.0.0') {
    console.warn(
      'dsh-login-gateway: listening on every interface; terminate TLS at the tunnel or reverse proxy',
    )
  }
}
