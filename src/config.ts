/**
 * Configuration schema and load-time validation.
 *
 * Everything a deployment varies is a validated field here, and anything
 * self-contained and wrong fails at load rather than at the first login: a
 * malformed password hash, an undecodable TOTP secret, a duplicated username,
 * or a listener that would proxy to itself all stop the plugin.
 *
 * @module dsh-login-gateway/config
 */

import z from '@deepseek-ai/schemastery'
import { decodeBase32 } from './base32.ts'
import { parsePasswordHash } from './password.ts'
import { DEFAULT_TOTP_OPTIONS, type TotpAlgorithm, type TotpOptions } from './totp.ts'
import type { RateLimitOptions } from './rate-limit.ts'

/** One login account. */
export interface UserConfig {
  /** Login name, matched exactly and case-sensitively. */
  username: string
  /** Encoded scrypt hash from `hashPassword` or `npm run enroll`. */
  passwordHash: string
  /** Base32 TOTP shared secret. */
  totpSecret: string
}

/** How the login page describes itself. */
export interface BrandingConfig {
  /** Product name shown in the page title and heading. */
  issuer?: string
}

/** Browser-session settings. */
export interface SessionConfig {
  /** Session lifetime in seconds. */
  maxAgeSeconds?: number
  /** Session cookie name. */
  cookieName?: string
  /** `auto` marks the cookie Secure when the request arrived over HTTPS. */
  secure?: 'auto' | 'always' | 'never'
}

/** TOTP verification settings, applied to every user. */
export interface TotpConfig {
  /** Code length in decimal digits. */
  digits?: 6 | 8
  /** Seconds per time step. */
  periodSeconds?: number
  /** HMAC hash algorithm. */
  algorithm?: TotpAlgorithm
  /** Time steps accepted on either side of the current one. */
  windowSteps?: number
}

/** Login throttling settings. */
export interface RateLimitConfig {
  /** Failures within the window that trigger a lockout. */
  maxFailures?: number
  /** Sliding window length in seconds. */
  windowSeconds?: number
  /** Lockout length in seconds. */
  lockoutSeconds?: number
}

/** Raw plugin configuration as it appears in `cordis.patch.yml`. */
export interface LoginGatewayConfig {
  /** Public listener bind host. */
  listenHost?: '127.0.0.1' | '0.0.0.0'
  /** Public listener port. */
  listenPort?: number
  /** Upstream bind host; the Host web server listens on loopback. */
  upstreamHost?: string
  /** Upstream port; defaults to the running web server's listening port. */
  upstreamPort?: number
  /** Path serving the login form. */
  loginPath?: string
  /** Path clearing the session. */
  logoutPath?: string
  /** Login accounts; at least one is required. */
  users?: UserConfig[]
  /** Product name shown on the login page. */
  branding?: BrandingConfig
  /** TOTP verification settings. */
  totp?: TotpConfig
  /** Browser-session settings. */
  session?: SessionConfig
  /** Login throttling settings. */
  rateLimit?: RateLimitConfig
  /** Trust the first `x-forwarded-for` hop as the client address. */
  trustProxy?: boolean
}

const MAX_PATH_LENGTH = 128
const COOKIE_NAME = /^[A-Za-z0-9_.-]+$/u
const MIN_TOTP_SECRET_BYTES = 10

/** The validated configuration the gateway runs from. */
export interface ResolvedConfig {
  readonly listenHost: '127.0.0.1' | '0.0.0.0'
  readonly listenPort: number
  readonly upstreamHost: string
  readonly upstreamPort: number
  readonly loginPath: string
  readonly logoutPath: string
  readonly users: readonly UserConfig[]
  readonly issuer: string
  readonly totp: TotpOptions
  readonly session: {
    readonly maxAgeMilliseconds: number
    readonly cookieName: string
    readonly secure: SessionConfig['secure']
  }
  readonly rateLimit: RateLimitOptions
  readonly trustProxy: boolean
}

/** Plugin configuration schema. */
export const Config: z<LoginGatewayConfig> = z.object({
  listenHost: z.union([z.const('127.0.0.1'), z.const('0.0.0.0')]).default('127.0.0.1'),
  listenPort: z.natural().max(65535).default(8080),
  upstreamHost: z.string().default('127.0.0.1'),
  upstreamPort: z.natural().max(65535),
  loginPath: z.string().default('/login'),
  logoutPath: z.string().default('/logout'),
  users: z.array(z.object({
    username: z.string().required(),
    passwordHash: z.string().required(),
    totpSecret: z.string().required(),
  })).default([]),
  branding: z.object({
    issuer: z.string().default('DeepSeek Harness'),
  }).default({}),
  totp: z.object({
    digits: z.union([z.const(6), z.const(8)]).default(6),
    periodSeconds: z.natural().min(15).max(300).default(DEFAULT_TOTP_OPTIONS.periodSeconds),
    algorithm: z.union([z.const('sha1'), z.const('sha256'), z.const('sha512')])
      .default(DEFAULT_TOTP_OPTIONS.algorithm),
    windowSteps: z.natural().max(10).default(DEFAULT_TOTP_OPTIONS.windowSteps),
  }).default({}),
  session: z.object({
    maxAgeSeconds: z.natural().min(60).default(12 * 60 * 60),
    cookieName: z.string().default('dsh_login_session'),
    secure: z.union([z.const('auto'), z.const('always'), z.const('never')]).default('auto'),
  }).default({}),
  rateLimit: z.object({
    maxFailures: z.natural().min(1).default(5),
    windowSeconds: z.natural().min(1).default(300),
    lockoutSeconds: z.natural().min(1).default(300),
  }).default({}),
  trustProxy: z.boolean().default(false),
})

function assertPath(value: string, field: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.length > MAX_PATH_LENGTH
    || value === '/' || /[\s?#\\]/u.test(value)) {
    throw new Error(`dsh-login-gateway: ${field} must be a single absolute path such as "/login"`)
  }
  if (value === '/api' || value.startsWith('/api/')) {
    throw new Error(`dsh-login-gateway: ${field} must not shadow the harness API under "/api"`)
  }
  return value
}

function resolveUsers(users: readonly UserConfig[]): readonly UserConfig[] {
  if (users.length === 0) {
    throw new Error(
      'dsh-login-gateway: config.users is empty; add at least one user (see the README enrollment section) '
      + 'or remove the plugin. The gateway refuses to start open.',
    )
  }
  const seen = new Set<string>()
  return users.map((user) => {
    const username = user.username.trim()
    if (username === '' || /[\s\u0000-\u001f\u007f]/u.test(username)) {
      throw new Error('dsh-login-gateway: every user needs a non-empty username without whitespace or control characters')
    }
    const folded = username.toLowerCase()
    if (seen.has(folded)) {
      throw new Error(`dsh-login-gateway: duplicate username ${JSON.stringify(username)}`)
    }
    seen.add(folded)
    if (parsePasswordHash(user.passwordHash) === undefined) {
      throw new Error(
        `dsh-login-gateway: user ${JSON.stringify(username)} has a malformed passwordHash; `
        + 'generate one with `npm run enroll`',
      )
    }
    const secret = decodeBase32(user.totpSecret)
    if (secret === undefined || secret.byteLength < MIN_TOTP_SECRET_BYTES) {
      throw new Error(
        `dsh-login-gateway: user ${JSON.stringify(username)} has an invalid totpSecret; `
        + 'expected base32 of at least 80 bits',
      )
    }
    return { username, passwordHash: user.passwordHash, totpSecret: user.totpSecret }
  })
}

/**
 * Validate raw configuration and fill in the resolved shape.
 * @param config - validated plugin configuration, or undefined for direct calls.
 * @param upstreamPort - the running web server's listening port.
 * @returns the complete gateway configuration.
 */
export function resolveConfig(
  config: LoginGatewayConfig | undefined,
  upstreamPort: number,
): ResolvedConfig {
  const source = config ?? {}
  const listenHost = source.listenHost ?? '127.0.0.1'
  const listenPort = source.listenPort ?? 8080
  const upstreamHost = source.upstreamHost ?? '127.0.0.1'
  const resolvedUpstreamPort = source.upstreamPort ?? upstreamPort
  if (!Number.isSafeInteger(resolvedUpstreamPort) || resolvedUpstreamPort < 1 || resolvedUpstreamPort > 65535) {
    throw new Error('dsh-login-gateway: upstreamPort must be the web server port when it is not configured')
  }
  if (listenPort === resolvedUpstreamPort && (listenHost === upstreamHost || listenHost === '0.0.0.0')) {
    throw new Error('dsh-login-gateway: listenPort must differ from the upstream web server port')
  }
  const loginPath = assertPath(source.loginPath ?? '/login', 'loginPath')
  const logoutPath = assertPath(source.logoutPath ?? '/logout', 'logoutPath')
  if (loginPath === logoutPath) {
    throw new Error('dsh-login-gateway: loginPath and logoutPath must differ')
  }
  const session: SessionConfig = source.session ?? {}
  const cookieName = session.cookieName ?? 'dsh_login_session'
  if (!COOKIE_NAME.test(cookieName)) {
    throw new Error('dsh-login-gateway: session.cookieName must be a valid cookie token')
  }
  const rateLimit: RateLimitConfig = source.rateLimit ?? {}
  const maxFailures = rateLimit.maxFailures ?? 5
  const windowSeconds = rateLimit.windowSeconds ?? 300
  const lockoutSeconds = rateLimit.lockoutSeconds ?? 300
  if (maxFailures < 1 || windowSeconds < 1 || lockoutSeconds < 1) {
    throw new Error('dsh-login-gateway: rateLimit values must be positive')
  }
  const maxAgeSeconds = session.maxAgeSeconds ?? 12 * 60 * 60
  if (maxAgeSeconds < 60) {
    throw new Error('dsh-login-gateway: session.maxAgeSeconds must be at least 60')
  }
  const totp: TotpConfig = source.totp ?? {}
  return {
    listenHost,
    listenPort,
    upstreamHost,
    upstreamPort: resolvedUpstreamPort,
    loginPath,
    logoutPath,
    users: resolveUsers(source.users ?? []),
    issuer: source.branding?.issuer ?? 'DeepSeek Harness',
    totp: {
      digits: totp.digits ?? DEFAULT_TOTP_OPTIONS.digits,
      periodSeconds: totp.periodSeconds ?? DEFAULT_TOTP_OPTIONS.periodSeconds,
      algorithm: totp.algorithm ?? DEFAULT_TOTP_OPTIONS.algorithm,
      windowSteps: totp.windowSteps ?? DEFAULT_TOTP_OPTIONS.windowSteps,
    },
    session: {
      maxAgeMilliseconds: maxAgeSeconds * 1000,
      cookieName,
      secure: session.secure ?? 'auto',
    },
    rateLimit: {
      maxFailures,
      windowMilliseconds: windowSeconds * 1000,
      lockoutMilliseconds: lockoutSeconds * 1000,
    },
    trustProxy: source.trustProxy ?? false,
  }
}
