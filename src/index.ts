/**
 * Host half of `dsh-login-gateway`.
 *
 * Adds an authenticated front door to a Web profile. The plugin listens on its
 * own loopback port, serves a username + password + TOTP login form, and
 * forwards authenticated traffic to the running harness web server — including
 * WebSocket upgrades — so a tunnel or reverse proxy can expose the harness
 * without exposing an unauthenticated API.
 *
 * With no configured account the plugin starts in first-run setup instead of
 * failing: the login path asks for the first username and password, generates
 * the TOTP secret, and stores the account as a credential record. Setup is
 * reachable from loopback, or once through a one-time token printed at startup.
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
import { createUserDirectory } from './user-store.ts'
import { hostServices } from './types.ts'

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
export { createUserDirectory, CREDENTIAL_SCOPE, isCreatableUsername } from './user-store.ts'
export type { LoginUser, UserDirectory } from './user-store.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-login-gateway'

/**
 * Services required before the gateway can start. `credentials` is required
 * because first-run setup stores the account it creates as a credential
 * record; the shipped Web composition always mounts a credential store.
 */
export const inject = ['webServer', 'connection', 'credentials']

/** Plugin configuration schema. */
export const Config = ConfigSchema

/**
 * Start the login gateway in front of the running web server.
 * @param ctx - host context carrying `webServer` and `connection`.
 * @param config - validated plugin configuration.
 */
export async function apply(ctx: Context, config?: LoginGatewayConfig): Promise<void> {
  const host = hostServices(ctx)
  const resolved = resolveConfig(config, host.webServer.port)
  const upstream = { host: resolved.upstreamHost, port: resolved.upstreamPort }
  const cookies = createUpstreamCookieProvider({
    upstream,
    authenticatedUrl: baseUrl => host.connection.authenticatedUrl(baseUrl),
  })
  const users = createUserDirectory(
    resolved.users,
    host.credentials,
    message => { ctx.logger.warn(message) },
  )
  const gateway = createLoginGateway(resolved, {
    upstreamCookie: authority => cookies.cookieFor(authority),
    users,
    logger: {
      info: (message: string) => { ctx.logger.info(message) },
      warn: (message: string) => { ctx.logger.warn(message) },
    },
  })
  await gateway.start()
  ctx.effect(() => () => gateway.stop(), 'dsh-login-gateway: listener')
  // The sign-in URL is an operator readiness signal, like the `dsh web:` line,
  // so it is printed rather than left to the profile's log level.
  const signInUrl = `${gateway.url}${resolved.loginPath}`
  console.log(
    `dsh-login-gateway: ${gateway.configured ? 'sign in' : 'set up'} at ${signInUrl} `
    + `(forwarding to http://${upstream.host}:${String(upstream.port)})`,
  )
  if (!gateway.configured) {
    console.log(
      'dsh-login-gateway: no account exists yet; open that URL on this machine, or use '
      + `${signInUrl}?setup=${gateway.setupToken} once to set one up through a tunnel`,
    )
  }
  if (resolved.listenHost === '0.0.0.0') {
    console.warn(
      'dsh-login-gateway: listening on every interface; terminate TLS at the tunnel or reverse proxy',
    )
  }
}
