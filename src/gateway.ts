/**
 * The login gateway: an authenticated front door for one harness web server.
 *
 * It listens on its own port, serves the login form, and forwards every other
 * request and upgrade to the harness after checking the session cookie. The
 * gateway never forwards to anything but its configured upstream, and it keeps
 * the harness launch token and cookie server-side, so the browser only ever
 * holds the gateway's own signed session cookie.
 *
 * @module dsh-login-gateway/gateway
 */

import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import type { ResolvedConfig } from './config.ts'
import { dummyPasswordVerify, hashPassword, verifyPassword } from './password.ts'
import { generateTotpSecret, totpUri, verifyTotp } from './totp.ts'
import {
  renderEnrollmentPage,
  renderLoginPage,
  renderNoticePage,
  renderSetupPage,
  renderUnconfiguredPage,
} from './login-page.ts'
import { isCreatableUsername, type UserDirectory } from './user-store.ts'
import { FailureLimiter } from './rate-limit.ts'
import { SessionStore } from './session.ts'
import { AUTH_COOKIE_PREFIX } from './upstream-auth.ts'
import { proxyRequest, proxyUpgrade, type UpstreamTarget } from './proxy.ts'

/** Health endpoint served without authentication. */
export const HEALTH_PATH = '/_dsh-login-gateway/health'

/** Largest accepted login form body. */
const MAX_LOGIN_BODY_BYTES = 16 * 1024

/** Session cookie HMAC key length. */
const SESSION_SECRET_BYTES = 32

/** Interval for dropping expired sessions and stale throttle entries. */
const PRUNE_INTERVAL_MILLISECONDS = 60_000

const CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded'

/** Cookie carrying the one-time setup token from the tokenized URL to the form post. */
const SETUP_COOKIE = 'dsh_login_setup'

/** Lifetime of the setup cookie, in seconds. */
const SETUP_COOKIE_MAX_AGE_SECONDS = 600

/** Shortest password accepted for an account created through setup. */
const MIN_SETUP_PASSWORD_LENGTH = 12

/** Setup token length in bytes. */
const SETUP_TOKEN_BYTES = 32

/** Where the gateway reports lifecycle messages. */
export interface LoginGatewayLogger {
  /** A normal lifecycle message. */
  info(message: string): void
  /** A failure the operator should see but that must not stop the process. */
  warn(message: string): void
}

/** Injected dependencies; everything with a side effect or a clock is a parameter. */
export interface LoginGatewayDeps {
  /**
   * Resolve the harness cookie for one browser authority.
   * @param authority - the browser-facing `host[:port]`.
   */
  upstreamCookie(authority: string): Promise<string | undefined>
  /** Configured and stored login accounts. */
  users: UserDirectory
  /** Lifecycle sink. */
  logger: LoginGatewayLogger
  /** Clock, injectable for tests. */
  now?: () => number
}

/** The running gateway. */
export interface LoginGateway {
  /** The port actually listening, including an OS-assigned port for a configured 0. */
  readonly port: number
  /** A URL an operator can open, on loopback even for an all-interfaces bind. */
  readonly url: string
  /** Whether any account exists; false means first-run setup is being served. */
  readonly configured: boolean
  /** One-time token authorizing setup from a peer that is not loopback. */
  readonly setupToken: string
  /** Bind the listener and resolve whether any account exists. */
  start(): Promise<void>
  /** Stop the listener and drop every live connection. */
  stop(): Promise<void>
}

class BodyTooLargeError extends Error {}

function headerValue(headers: IncomingMessage['headers'], name: string): string | undefined {
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

/** Read one cookie value from a Cookie header without a general parser. */
function cookieValue(cookieHeader: string | undefined, name: string): string | undefined {
  if (cookieHeader === undefined) return undefined
  for (const segment of cookieHeader.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1) continue
    if (segment.slice(0, at).trim() !== name) continue
    return segment.slice(at + 1).trim()
  }
  return undefined
}

/** Keep every browser cookie except this gateway's session and the harness's own. */
function forwardedCookies(cookieHeader: string | undefined, sessionName: string): string[] {
  if (cookieHeader === undefined) return []
  const kept: string[] = []
  for (const segment of cookieHeader.split(';')) {
    const trimmed = segment.trim()
    if (trimmed === '') continue
    const at = trimmed.indexOf('=')
    const name = at === -1 ? trimmed : trimmed.slice(0, at)
    if (name === sessionName || name.startsWith(AUTH_COOKIE_PREFIX)) continue
    kept.push(trimmed)
  }
  return kept
}

/** First token of a comma-separated header, used for `x-forwarded-*`. */
function firstToken(value: string | undefined): string | undefined {
  const token = value?.split(',')[0]?.trim()
  return token === undefined || token === '' ? undefined : token
}

function clientAddress(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = firstToken(headerValue(req.headers, 'x-forwarded-for'))
    if (forwarded !== undefined) return forwarded
  }
  return req.socket.remoteAddress ?? 'unknown'
}

/** Constant-time comparison for one-time tokens. */
function tokenMatches(actual: string | undefined, expected: string): boolean {
  if (actual === undefined) return false
  const actualBytes = Buffer.from(actual, 'utf8')
  const expectedBytes = Buffer.from(expected, 'utf8')
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes)
}

/**
 * Headers a reverse proxy adds. A browser cannot set them, so their presence
 * means the request was relayed even though the socket peer is loopback.
 */
const FORWARDING_HEADERS = [
  'x-forwarded-for',
  'x-forwarded-host',
  'x-real-ip',
  'cf-connecting-ip',
  'forwarded',
] as const

/**
 * Whether the request came straight from the local machine.
 *
 * A tunnel or reverse proxy connects from loopback, so a loopback socket alone
 * does not mean local: without this, every internet visitor would look like the
 * operator and could claim the first account. A forwarding header marks the
 * request as relayed, and setup then requires the one-time token.
 * @param req - the incoming request.
 * @returns true only for a direct loopback request carrying no forwarding header.
 */
function isLoopbackPeer(req: IncomingMessage): boolean {
  const address = req.socket.remoteAddress
  if (address !== '127.0.0.1' && address !== '::1' && address !== '::ffff:127.0.0.1') return false
  return FORWARDING_HEADERS.every(name => headerValue(req.headers, name) === undefined)
}

function forwardedProto(req: IncomingMessage): string {
  return firstToken(headerValue(req.headers, 'x-forwarded-proto')) ?? 'http'
}

/** Whether the request expects a navigable document rather than an API response. */
function wantsHtml(req: IncomingMessage): boolean {
  const destination = headerValue(req.headers, 'sec-fetch-dest')
  if (destination !== undefined) {
    return destination === 'document' || destination === 'iframe' || destination === 'frame'
  }
  const accept = headerValue(req.headers, 'accept') ?? ''
  return (req.method === 'GET' || req.method === 'HEAD') && accept.includes('text/html')
}

/** Accept only a same-site absolute path as a post-login destination. */
function safeNext(value: string | null | undefined): string | undefined {
  if (value === undefined || value === null || value === '' || value.length > 512) return undefined
  if (!value.startsWith('/') || value.startsWith('//')) return undefined
  if (/[\\\u0000-\u001f\u007f]/u.test(value)) return undefined
  return value
}

/**
 * Reject a cross-site form post.
 *
 * Browsers label every request with `Sec-Fetch-Site`, which script cannot set,
 * so a `same-origin` post is accepted without comparing `Origin` to `Host`. A
 * tunnel or reverse proxy in front may rewrite `Host` — the harness's own
 * fence requires it to preserve the browser-facing authority, but this
 * gateway's pages must work either way. Without Fetch Metadata, fall back to
 * comparing `Origin` against `Host` and the proxy-supplied `X-Forwarded-Host`.
 */
function isSameOrigin(req: IncomingMessage): boolean {
  const site = headerValue(req.headers, 'sec-fetch-site')
  if (site === 'cross-site') return false
  if (site === 'same-origin' || site === 'none') return true
  const origin = headerValue(req.headers, 'origin')
  if (origin === undefined) return true
  const candidates = [
    headerValue(req.headers, 'host'),
    firstToken(headerValue(req.headers, 'x-forwarded-host')),
  ]
  for (const candidate of candidates) {
    if (candidate === undefined) continue
    try {
      if (new URL(origin).host === new URL(`http://${candidate}`).host) return true
    } catch {
      // An unparsable candidate cannot match; try the next one.
    }
  }
  return false
}

/**
 * Read a bounded form body. Past the limit the body is drained and discarded
 * rather than destroying the socket, so the caller can still answer 413.
 */
function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let overflowed = false
    req.on('data', (chunk: Buffer) => {
      size += chunk.byteLength
      if (overflowed) return
      if (size > limit) {
        overflowed = true
        chunks.length = 0
        reject(new BodyTooLargeError('login body too large'))
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (!overflowed) resolve(Buffer.concat(chunks).toString('utf8'))
    })
    req.on('error', (error: Error) => {
      if (!overflowed) reject(error)
    })
  })
}

/**
 * Create the gateway.
 * @param config - resolved plugin configuration.
 * @param deps - upstream cookie resolver, logger, and clock.
 * @returns the gateway, not yet listening.
 */
export function createLoginGateway(config: ResolvedConfig, deps: LoginGatewayDeps): LoginGateway {
  const now = deps.now ?? Date.now
  const sessions = new SessionStore(randomBytes(SESSION_SECRET_BYTES), config.session.maxAgeMilliseconds, now)
  const limiter = new FailureLimiter(config.rateLimit, now)
  const upstream: UpstreamTarget = { host: config.upstreamHost, port: config.upstreamPort }
  const sockets = new Set<Duplex>()
  const setupToken = randomBytes(SETUP_TOKEN_BYTES).toString('base64url')
  let configured = false
  let port = config.listenPort
  let pruneTimer: NodeJS.Timeout | undefined

  const secureCookie = (req: IncomingMessage): boolean => {
    if (config.session.secure === 'always') return true
    if (config.session.secure === 'never') return false
    return forwardedProto(req) === 'https'
  }

  const sessionCookie = (req: IncomingMessage, value: string, expiresAt: number, maxAgeSeconds: number): string => {
    const parts = [
      `${config.session.cookieName}=${value}`,
      'Path=/',
      'HttpOnly',
      // Lax, not Strict: a link to the deployment from another site must land
      // in the application rather than bounce to the login form. Sign-out and
      // the sign-in POST each require a same-origin request instead.
      'SameSite=Lax',
      `Max-Age=${String(maxAgeSeconds)}`,
      `Expires=${new Date(expiresAt).toUTCString()}`,
    ]
    if (secureCookie(req)) parts.push('Secure')
    return parts.join('; ')
  }

  const clearedCookie = (req: IncomingMessage): string => {
    const parts = [
      `${config.session.cookieName}=`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      'Max-Age=0',
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    ]
    if (secureCookie(req)) parts.push('Secure')
    return parts.join('; ')
  }

  const securityHeaders = (): Record<string, string> => ({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  })

  const sendHtml = (res: ServerResponse, status: number, body: string, headOnly: boolean): void => {
    res.writeHead(status, { ...securityHeaders(), 'content-type': 'text/html; charset=utf-8' })
    res.end(headOnly ? undefined : body)
  }

  const sendText = (
    res: ServerResponse,
    status: number,
    body: string,
    extra: Record<string, string> = {},
  ): void => {
    res.writeHead(status, {
      'cache-control': 'no-store',
      'content-type': 'text/plain; charset=utf-8',
      ...extra,
    })
    res.end(body)
  }

  const redirect = (res: ServerResponse, location: string, extra: Record<string, string> = {}): void => {
    res.writeHead(303, { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', location, ...extra })
    res.end()
  }

  const loginRedirect = (url: URL): string => {
    const target = `${url.pathname}${url.search}`
    if (target === '/' || target === '') return config.loginPath
    return `${config.loginPath}?next=${encodeURIComponent(target)}`
  }

  const notice = (res: ServerResponse, status: number, title: string, message: string): void => {
    sendHtml(res, status, renderNoticePage({
      issuer: config.issuer,
      title,
      message,
      loginPath: config.loginPath,
      tone: status >= 400 ? 'error' : 'info',
    }), false)
  }

  const handleLogin = async (req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> => {
    const session = sessions.verify(cookieValue(req.headers.cookie, config.session.cookieName))
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (session !== undefined) {
        redirect(res, safeNext(url.searchParams.get('next')) ?? '/')
        return
      }
      // Recover when the last account disappeared — its record was deleted, or
      // a credential file was restored from a backup. The sign-in form becomes
      // the setup form again instead of locking everyone out.
      if (await deps.users.isEmpty()) {
        configured = false
        await handleSetup(req, res, url)
        return
      }
      sendHtml(res, 200, renderLoginPage({
        issuer: config.issuer,
        loginPath: config.loginPath,
        next: safeNext(url.searchParams.get('next')),
        digits: config.totp.digits,
      }), req.method === 'HEAD')
      return
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, HEAD, POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    if (!isSameOrigin(req)) {
      notice(res, 403, 'Request refused', 'The sign-in request did not come from this site.')
      return
    }
    const contentType = headerValue(req.headers, 'content-type') ?? ''
    if (!contentType.toLowerCase().startsWith(CONTENT_TYPE_FORM)) {
      sendText(res, 415, 'expected application/x-www-form-urlencoded\n')
      return
    }
    let body: string
    try {
      body = await readBody(req, MAX_LOGIN_BODY_BYTES)
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        sendText(res, 413, 'sign-in form too large\n', { connection: 'close' })
        return
      }
      throw error
    }
    const form = new URLSearchParams(body)
    const username = (form.get('username') ?? '').slice(0, 256)
    const password = (form.get('password') ?? '').slice(0, 4096)
    const otp = (form.get('otp') ?? '').trim().slice(0, 16)
    const next = safeNext(form.get('next'))
    const ipKey = `ip:${clientAddress(req, config.trustProxy)}`
    const userKey = `user:${username.toLowerCase()}`
    for (const key of [ipKey, userKey]) {
      const decision = limiter.check(key)
      if (decision.allowed) continue
      res.writeHead(429, {
        ...securityHeaders(),
        'content-type': 'text/html; charset=utf-8',
        'retry-after': String(decision.retryAfterSeconds),
      })
      res.end(renderNoticePage({
        issuer: config.issuer,
        title: 'Too many attempts',
        message: `Too many failed sign-ins. Try again in ${String(decision.retryAfterSeconds)} seconds.`,
        loginPath: config.loginPath,
        tone: 'error',
      }))
      return
    }
    const user = await deps.users.find(username)
    let accepted = false
    if (user === undefined) {
      // Spend one derivation so an unknown username is not answered faster.
      await dummyPasswordVerify(password)
      // No account exists at all: this is first-run setup, not a failed login.
      if (await deps.users.isEmpty()) {
        configured = false
        sendHtml(res, 200, renderSetupPage({
          issuer: config.issuer,
          loginPath: config.loginPath,
          minPasswordLength: MIN_SETUP_PASSWORD_LENGTH,
        }), false)
        return
      }
    } else {
      const passwordOk = await verifyPassword(password, user.passwordHash)
      const otpOk = verifyTotp(user.totpSecret, otp, config.totp, now())
      accepted = passwordOk && otpOk
    }
    if (!accepted || user === undefined) {
      limiter.recordFailure(ipKey)
      limiter.recordFailure(userKey)
      sendHtml(res, 401, renderLoginPage({
        issuer: config.issuer,
        loginPath: config.loginPath,
        next,
        username,
        digits: config.totp.digits,
        error: 'Invalid username, password, or authenticator code.',
      }), false)
      return
    }
    limiter.recordSuccess(ipKey)
    limiter.recordSuccess(userKey)
    const session2 = sessions.create(user.username)
    redirect(res, next ?? '/', {
      'set-cookie': sessionCookie(
        req,
        session2.value,
        session2.expiresAt,
        Math.floor(config.session.maxAgeMilliseconds / 1000),
      ),
    })
  }

  const handleLogout = (req: IncomingMessage, res: ServerResponse): void => {
    if (req.method !== 'GET' && req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    // A Lax cookie travels on a cross-site top-level navigation, so sign-out
    // itself has to refuse one; otherwise any page could end the session.
    if (!isSameOrigin(req)) {
      notice(res, 403, 'Request refused', 'The sign-out request did not come from this site.')
      return
    }
    sessions.delete(cookieValue(req.headers.cookie, config.session.cookieName))
    redirect(res, config.loginPath, { 'set-cookie': clearedCookie(req) })
  }

  const extraHeadersFor = (req: IncomingMessage, authority: string): Record<string, string> => ({
    'x-forwarded-for': clientAddress(req, config.trustProxy),
    'x-forwarded-host': authority,
    'x-forwarded-proto': forwardedProto(req),
  })

  const forward = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const authority = headerValue(req.headers, 'host') ?? `${config.upstreamHost}:${String(config.upstreamPort)}`
    const extra = extraHeadersFor(req, authority)
    const cookies = forwardedCookies(req.headers.cookie, config.session.cookieName)
    const upstreamCookie = await deps.upstreamCookie(authority)
    if (upstreamCookie !== undefined) cookies.push(upstreamCookie)
    if (cookies.length > 0) extra['cookie'] = cookies.join('; ')
    proxyRequest(req, res, {
      target: upstream,
      extraHeaders: extra,
      dropHeaders: cookies.length > 0 ? [] : ['cookie'],
      dropResponseCookiePrefix: AUTH_COOKIE_PREFIX,
      onError: error => deps.logger.warn(`dsh-login-gateway: upstream request failed: ${error.message}`),
    })
  }

  /** Whether this request may read or complete first-run setup. */
  const setupAuthorized = (req: IncomingMessage): boolean => {
    if (isLoopbackPeer(req)) return true
    return tokenMatches(cookieValue(req.headers.cookie, SETUP_COOKIE), setupToken)
  }

  const setupCookie = (req: IncomingMessage): string => {
    const parts = [
      `${SETUP_COOKIE}=${setupToken}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${String(SETUP_COOKIE_MAX_AGE_SECONDS)}`,
    ]
    if (secureCookie(req)) parts.push('Secure')
    return parts.join('; ')
  }

  /**
   * Refuse first-run setup to a peer that neither is loopback nor presented the
   * one-time token. Without this, the first internet visitor would own the
   * deployment.
   */
  const refuseSetup = (res: ServerResponse): void => {
    sendHtml(res, 403, renderNoticePage({
      issuer: config.issuer,
      title: 'Setup is local-only',
      message: 'This deployment has no account yet. Open the sign-in URL on the machine running the harness, '
        + 'or use the one-time setup link printed at startup to continue through the tunnel.',
      tone: 'error',
    }), false)
  }

  const handleSetup = async (req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> => {
    const presentedToken = url.searchParams.get('setup')
    if (presentedToken !== null) {
      if (!tokenMatches(presentedToken, setupToken)) {
        refuseSetup(res)
        return
      }
      // Exchange the token for a short-lived cookie so the form post carries it
      // without keeping the token in the address bar.
      redirect(res, config.loginPath, { 'set-cookie': setupCookie(req) })
      return
    }
    if (!setupAuthorized(req)) {
      refuseSetup(res)
      return
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      sendHtml(res, 200, renderSetupPage({
        issuer: config.issuer,
        loginPath: config.loginPath,
        minPasswordLength: MIN_SETUP_PASSWORD_LENGTH,
      }), req.method === 'HEAD')
      return
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, HEAD, POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    if (!isSameOrigin(req)) {
      notice(res, 403, 'Request refused', 'The setup request did not come from this site.')
      return
    }
    const contentType = headerValue(req.headers, 'content-type') ?? ''
    if (!contentType.toLowerCase().startsWith(CONTENT_TYPE_FORM)) {
      sendText(res, 415, 'expected application/x-www-form-urlencoded\n', { connection: 'close' })
      return
    }
    let body: string
    try {
      body = await readBody(req, MAX_LOGIN_BODY_BYTES)
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        sendText(res, 413, 'setup form too large\n', { connection: 'close' })
        return
      }
      throw error
    }
    const form = new URLSearchParams(body)
    const username = (form.get('username') ?? '').trim().slice(0, 64)
    const password = (form.get('password') ?? '').slice(0, 4096)
    const confirm = (form.get('confirm') ?? '').slice(0, 4096)
    const reject = (message: string, status = 400): void => {
      sendHtml(res, status, renderSetupPage({
        issuer: config.issuer,
        loginPath: config.loginPath,
        error: message,
        username,
        minPasswordLength: MIN_SETUP_PASSWORD_LENGTH,
      }), false)
    }
    if (!isCreatableUsername(username)) {
      reject('Username must be 2-32 characters of lowercase letters, digits, and hyphens, starting with a letter.')
      return
    }
    if (password.length < MIN_SETUP_PASSWORD_LENGTH) {
      reject(`Password must be at least ${String(MIN_SETUP_PASSWORD_LENGTH)} characters.`)
      return
    }
    if (password !== confirm) {
      reject('The passwords do not match.')
      return
    }
    const totpSecret = generateTotpSecret()
    const passwordHash = await hashPassword(password)
    try {
      await deps.users.create({ username, passwordHash, totpSecret })
    } catch (error) {
      reject(error instanceof Error ? error.message : 'The account could not be created.', 409)
      return
    }
    configured = true
    sendHtml(res, 200, renderEnrollmentPage({
      issuer: config.issuer,
      loginPath: config.loginPath,
      username,
      secret: totpSecret,
      uri: totpUri({
        secret: totpSecret,
        account: username,
        issuer: config.issuer,
        digits: config.totp.digits,
        periodSeconds: config.totp.periodSeconds,
        algorithm: config.totp.algorithm,
      }),
    }), false)
  }

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    let url: URL
    try {
      url = new URL(req.url ?? '/', 'http://gateway.invalid')
    } catch {
      sendText(res, 400, 'bad request\n')
      return
    }
    if (url.pathname === HEALTH_PATH) {
      sendText(res, 200, 'ok\n')
      return
    }
    if (url.pathname === '/favicon.ico') {
      res.writeHead(204, { 'cache-control': 'no-store' })
      res.end()
      return
    }
    if (!configured) {
      if (url.pathname === config.loginPath) {
        await handleSetup(req, res, url)
        return
      }
      // Nothing else is served before the first account exists: the harness is
      // not reachable through an unconfigured gateway.
      if (wantsHtml(req)) {
        sendHtml(res, 503, renderUnconfiguredPage({
          issuer: config.issuer,
          loginPath: config.loginPath,
        }), false)
        return
      }
      res.writeHead(503, {
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        'retry-after': '30',
      })
      res.end(JSON.stringify({ error: 'not-configured' }))
      return
    }
    if (url.pathname === config.loginPath) {
      await handleLogin(req, res, url)
      return
    }
    if (url.pathname === config.logoutPath) {
      handleLogout(req, res)
      return
    }
    if (sessions.verify(cookieValue(req.headers.cookie, config.session.cookieName)) === undefined) {
      // A browser fetches the web app manifest without credentials, and the
      // harness serves everything but its dist root and index publicly, so
      // gating this request only produces a 401 in the console.
      if (headerValue(req.headers, 'sec-fetch-dest') === 'manifest') {
        await forward(req, res)
        return
      }
      if (wantsHtml(req)) {
        redirect(res, loginRedirect(url))
        return
      }
      res.writeHead(401, {
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        'www-authenticate': 'Cookie',
      })
      res.end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    await forward(req, res)
  }

  const handleUpgrade = async (req: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> => {
    const url = new URL(req.url ?? '/', 'http://gateway.invalid')
    if (!configured) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    if (url.pathname === config.loginPath || url.pathname === config.logoutPath || url.pathname === HEALTH_PATH) {
      socket.write('HTTP/1.1 404 Not Found\r\nconnection: close\r\ncontent-length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    if (sessions.verify(cookieValue(req.headers.cookie, config.session.cookieName)) === undefined) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nconnection: close\r\ncontent-length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    const authority = headerValue(req.headers, 'host') ?? `${config.upstreamHost}:${String(config.upstreamPort)}`
    const extra = extraHeadersFor(req, authority)
    const cookies = forwardedCookies(req.headers.cookie, config.session.cookieName)
    const upstreamCookie = await deps.upstreamCookie(authority)
    if (upstreamCookie !== undefined) cookies.push(upstreamCookie)
    if (cookies.length > 0) extra['cookie'] = cookies.join('; ')
    proxyUpgrade(req, socket, head, {
      target: upstream,
      extraHeaders: extra,
      dropHeaders: cookies.length > 0 ? [] : ['cookie'],
      dropResponseCookiePrefix: AUTH_COOKIE_PREFIX,
      onError: error => deps.logger.warn(`dsh-login-gateway: upstream upgrade failed: ${error.message}`),
    })
  }

  const server: Server = createServer((req, res) => {
    void handle(req, res).catch((error: unknown) => {
      deps.logger.warn(`dsh-login-gateway: request failed: ${error instanceof Error ? error.message : String(error)}`)
      if (res.headersSent) {
        res.destroy()
        return
      }
      sendText(res, 500, 'internal error\n')
    })
  })
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.once('close', () => { sockets.delete(socket) })
  })
  server.on('upgrade', (req, socket, head) => {
    void handleUpgrade(req, socket, head).catch((error: unknown) => {
      deps.logger.warn(`dsh-login-gateway: upgrade failed: ${error instanceof Error ? error.message : String(error)}`)
      socket.destroy()
    })
  })

  return {
    get port(): number {
      return port
    },
    get url(): string {
      const host = config.listenHost === '0.0.0.0' ? '127.0.0.1' : config.listenHost
      return `http://${host}:${String(port)}`
    },
    get configured(): boolean {
      return configured
    },
    get setupToken(): string {
      return setupToken
    },
    async start(): Promise<void> {
      configured = !(await deps.users.isEmpty())
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error): void => { reject(error) }
        server.once('error', onError)
        server.listen(config.listenPort, config.listenHost, () => {
          server.off('error', onError)
          server.on('error', (error: Error) => {
            deps.logger.warn(`dsh-login-gateway: listener error: ${error.message}`)
          })
          resolve()
        })
      })
      const address = server.address()
      if (typeof address === 'object' && address !== null) port = address.port
      pruneTimer = setInterval(() => {
        sessions.prune()
        limiter.prune()
      }, PRUNE_INTERVAL_MILLISECONDS)
      pruneTimer.unref()
    },
    async stop(): Promise<void> {
      if (pruneTimer !== undefined) {
        clearInterval(pruneTimer)
        pruneTimer = undefined
      }
      const closed = new Promise<void>((resolve) => { server.close(() => { resolve() }) })
      for (const socket of sockets) socket.destroy()
      sockets.clear()
      server.closeAllConnections()
      await closed
    },
  }
}
