import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders } from 'node:http'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resolveConfig, type LoginGatewayConfig } from '../src/config.ts'
import { createLoginGateway, type LoginGateway } from '../src/gateway.ts'
import { hashPassword } from '../src/password.ts'
import { generateTotp, generateTotpSecret } from '../src/totp.ts'
import { createUpstreamCookieProvider } from '../src/upstream-auth.ts'
import { createUserDirectory } from '../src/user-store.ts'
import { createFakeCredentials, type FakeCredentials } from './helpers/credentials.ts'
import { startFakeUpstream, type FakeUpstream } from './helpers/upstream.ts'

const PASSWORD = 'correct horse battery staple'
const USERNAME = 'alice'

let upstream: FakeUpstream
let gateway: LoginGateway
let secret: string
let base: string

function currentCode(): string {
  const code = generateTotp(secret)
  if (code === undefined) throw new Error('the test secret produced no code')
  return code
}

function hostOf(url: string): string {
  return new URL(url).host
}

function sessionCookie(response: Response): string {
  const cookie = response.headers.getSetCookie().find(value => value.startsWith('gw_session='))
  if (cookie === undefined) throw new Error('the login response set no session cookie')
  return cookie.split(';')[0] ?? ''
}

async function login(options: {
  username?: string
  password?: string
  otp?: string
  next?: string
  origin?: string | null
} = {}): Promise<Response> {
  const body = new URLSearchParams({
    username: options.username ?? USERNAME,
    password: options.password ?? PASSWORD,
    otp: options.otp ?? currentCode(),
  })
  if (options.next !== undefined) body.set('next', options.next)
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (options.origin !== null) headers['origin'] = options.origin ?? base
  return await fetch(`${base}/login`, { method: 'POST', body, headers, redirect: 'manual' })
}

/**
 * Send a request with full control over its headers, which `fetch` forbids for
 * `Host` and `X-Forwarded-*`. Used to stand in for a proxy or tunnel.
 */
function requestWithHeaders(
  method: string,
  target: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; body: string; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const url = new URL(target)
    const payload = body ?? ''
    const request = httpRequest({
      host: url.hostname,
      port: url.port,
      path,
      method,
      headers: body === undefined
        ? headers
        : { ...headers, 'content-length': String(Buffer.byteLength(payload)) },
    }, (response) => {
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      response.on('end', () => {
        resolve({
          status: response.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
          headers: response.headers,
        })
      })
    })
    request.on('error', reject)
    request.end(body)
  })
}

/** Open one WebSocket-shaped upgrade and read its status line and headers. */
function upgrade(path: string, cookie?: string, target: string = base): Promise<{ status: number; socket: Socket }> {
  return new Promise((resolve, reject) => {
    const socket = connect(Number(new URL(target).port), '127.0.0.1')
    socket.once('error', reject)
    socket.once('connect', () => {
      const lines = [
        `GET ${path} HTTP/1.1`,
        `host: ${hostOf(target)}`,
        'upgrade: websocket',
        'connection: Upgrade',
        'sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==',
        'sec-websocket-version: 13',
      ]
      if (cookie !== undefined) lines.push(`cookie: ${cookie}`)
      socket.write(`${lines.join('\r\n')}\r\n\r\n`)
    })
    let buffer = Buffer.alloc(0)
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk])
      const end = buffer.indexOf('\r\n\r\n')
      if (end === -1) return
      socket.off('data', onData)
      const statusLine = buffer.subarray(0, end).toString('utf8').split('\r\n')[0] ?? ''
      resolve({ status: Number(statusLine.split(' ')[1] ?? 0), socket })
    }
    socket.on('data', onData)
  })
}

beforeEach(async () => {
  upstream = await startFakeUpstream()
  secret = generateTotpSecret()
  // A deliberately cheap work factor keeps the integration suite fast.
  const passwordHash = await hashPassword(PASSWORD, { N: 1024, r: 8, p: 1 })
  const config: LoginGatewayConfig = {
    listenHost: '127.0.0.1',
    listenPort: 0,
    upstreamHost: '127.0.0.1',
    upstreamPort: upstream.port,
    loginPath: '/login',
    logoutPath: '/logout',
    users: [{ username: USERNAME, passwordHash, totpSecret: secret }],
    session: { maxAgeSeconds: 3600, cookieName: 'gw_session', secure: 'never' },
    rateLimit: { maxFailures: 3, windowSeconds: 60, lockoutSeconds: 60 },
    trustProxy: true,
  }
  const cookies = createUpstreamCookieProvider({
    upstream: { host: '127.0.0.1', port: upstream.port },
    authenticatedUrl: (baseUrl) => {
      const url = new URL(baseUrl)
      url.searchParams.set('token', upstream.launchToken)
      return url.href
    },
  })
  const resolved = resolveConfig(config, upstream.port)
  gateway = createLoginGateway(resolved, {
    upstreamCookie: authority => cookies.cookieFor(authority),
    users: createUserDirectory(resolved.users, undefined),
    logger: { info: () => {}, warn: () => {} },
  })
  await gateway.start()
  base = gateway.url
})

afterEach(async () => {
  await gateway.stop()
  await upstream.close()
})

describe('gateway routing', () => {
  it('redirects an unauthenticated document request to the login page', async () => {
    const response = await fetch(`${base}/api/sessions`, {
      redirect: 'manual',
      headers: { 'sec-fetch-dest': 'document' },
    })
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/login?next=%2Fapi%2Fsessions')
  })

  it('answers an unauthenticated API request with 401 JSON', async () => {
    const response = await fetch(`${base}/api/sessions`)
    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({ error: 'unauthorized' })
  })

  it('serves the login form and the health endpoint without a session', async () => {
    const form = await fetch(`${base}/login`, { headers: { 'sec-fetch-dest': 'document' } })
    expect(form.status).toBe(200)
    expect(form.headers.get('content-type')).toContain('text/html')
    expect(form.headers.get('content-security-policy')).toContain("default-src 'none'")
    expect(await form.text()).toContain('name="otp"')

    const health = await fetch(`${base}/_dsh-login-gateway/health`)
    expect(health.status).toBe(200)
    await expect(health.text()).resolves.toBe('ok\n')
  })

  it('redirects an authenticated login-page visit to the application', async () => {
    const cookie = sessionCookie(await login())
    const response = await fetch(`${base}/login`, { redirect: 'manual', headers: { cookie } })
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/')
  })
})

describe('sign-in', () => {
  it('signs in with the right password and code', async () => {
    const response = await login()
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/')
    const cookie = sessionCookie(response)
    expect(cookie).toMatch(/^gw_session=/u)
    expect(response.headers.getSetCookie()[0]).toContain('SameSite=Lax')
  })

  it('refuses a wrong password, a wrong code, and an unknown user', async () => {
    for (const attempt of [
      { password: 'wrong' },
      { otp: '000000' },
      { username: 'nobody' },
    ]) {
      const response = await login(attempt)
      expect(response.status).toBe(401)
      expect(response.headers.getSetCookie()).toEqual([])
      expect(await response.text()).toContain('Invalid username, password, or authenticator code.')
    }
  })

  it('refuses a cross-site form post', async () => {
    const response = await login({ origin: 'https://evil.example' })
    expect(response.status).toBe(403)
    expect(await response.text()).toContain('did not come from this site')
  })

  it('refuses a non-form content type', async () => {
    const response = await fetch(`${base}/login`, {
      method: 'POST',
      body: 'username=alice',
      headers: { 'content-type': 'text/plain', origin: base },
      redirect: 'manual',
    })
    expect(response.status).toBe(415)
  })

  it('refuses an oversized form body', async () => {
    const response = await fetch(`${base}/login`, {
      method: 'POST',
      body: `username=alice&password=${'x'.repeat(20_000)}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: base },
      redirect: 'manual',
    })
    expect(response.status).toBe(413)
  })

  it('ignores an off-site next destination', async () => {
    for (const next of ['//evil.example/path', 'https://evil.example', '/\\evil']) {
      const response = await login({ next })
      expect(response.status).toBe(303)
      expect(response.headers.get('location')).toBe('/')
    }
  })

  it('honours a safe next destination', async () => {
    const response = await login({ next: '/api/sessions?page=2' })
    expect(response.headers.get('location')).toBe('/api/sessions?page=2')
  })

  it('locks out a client after repeated failures', async () => {
    for (let at = 0; at < 3; at += 1) {
      expect((await login({ otp: '000000' })).status).toBe(401)
    }
    const locked = await login()
    expect(locked.status).toBe(429)
    expect(Number(locked.headers.get('retry-after'))).toBeGreaterThan(0)
  })

  it('refuses a cross-site sign-out', async () => {
    const cookie = sessionCookie(await login())
    const refused = await fetch(`${base}/logout`, {
      redirect: 'manual',
      headers: { cookie, origin: 'https://evil.example' },
    })
    expect(refused.status).toBe(403)
    const stillIn = await fetch(`${base}/api/echo`, { headers: { cookie } })
    expect(stillIn.status).toBe(200)
  })

  it('signs out and invalidates the session', async () => {
    const cookie = sessionCookie(await login())
    const signOut = await fetch(`${base}/logout`, { redirect: 'manual', headers: { cookie } })
    expect(signOut.status).toBe(303)
    expect(signOut.headers.get('location')).toBe('/login')
    expect(signOut.headers.getSetCookie()[0]).toContain('Max-Age=0')
    const after = await fetch(`${base}/api/echo`, { headers: { cookie } })
    expect(after.status).toBe(401)
  })
})

describe('forwarding', () => {
  it('forwards an authenticated request with the harness cookie and no browser cookies', async () => {
    const cookie = sessionCookie(await login())
    const response = await fetch(`${base}/api/echo`, {
      method: 'POST',
      body: 'hello upstream',
      headers: {
        cookie: `dsh-auth-forged=1; ${cookie}`,
        'content-type': 'text/plain',
        origin: base,
      },
    })
    expect(response.status).toBe(200)
    const payload = await response.json() as Record<string, string>
    expect(payload['body']).toBe('hello upstream')
    expect(payload['host']).toBe(hostOf(base))
    expect(payload['cookie']).toContain(`${upstream.cookieName}=${upstream.cookieValue}`)
    expect(payload['cookie']).not.toContain('forged')
    expect(payload['cookie']).not.toContain('gw_session')
    expect(payload['forwardedFor']).toBeDefined()
    expect(payload['forwardedProto']).toBe('http')
    // The harness cookie the upstream sets must not leak into the browser jar.
    expect(response.headers.getSetCookie()).toEqual([])
  })

  it('streams a response without buffering it', async () => {
    const cookie = sessionCookie(await login())
    const response = await fetch(`${base}/api/stream`, { headers: { cookie } })
    expect(response.status).toBe(200)
    await expect(response.text()).resolves.toBe('data: one\n\ndata: two\n\n')
  })

  it('preserves the browser Host and reports the forwarded proto', async () => {
    const cookie = sessionCookie(await login())
    const response = await fetch(`${base}/api/echo`, {
      headers: { cookie, 'x-forwarded-proto': 'https' },
    })
    const payload = await response.json() as Record<string, string>
    expect(payload['host']).toBe(hostOf(base))
    expect(payload['forwardedProto']).toBe('https')
  })

  it('answers 502 when the upstream is unreachable', async () => {
    const cookie = sessionCookie(await login())
    await upstream.close()
    const response = await fetch(`${base}/api/echo`, { headers: { cookie } })
    expect(response.status).toBe(502)
    upstream = await startFakeUpstream()
  })
})

describe('upgrades', () => {
  it('refuses an unauthenticated upgrade', async () => {
    const { status, socket } = await upgrade('/api/remote.mux')
    expect(status).toBe(401)
    socket.destroy()
  })

  it('tunnels an authenticated upgrade', async () => {
    const cookie = sessionCookie(await login())
    const { status, socket } = await upgrade('/api/remote.mux', cookie)
    expect(status).toBe(101)
    const echoed = new Promise<string>((resolve) => {
      socket.once('data', (chunk: Buffer) => { resolve(chunk.toString('utf8')) })
    })
    socket.write('ping')
    await expect(echoed).resolves.toBe('ping')
    socket.destroy()
  })
})

describe('first-run setup', () => {
  const SETUP_PASSWORD = 'a-long-enough-password'
  let setupGateway: LoginGateway
  let credentials: FakeCredentials
  let setupBase: string

  beforeEach(async () => {
    credentials = createFakeCredentials()
    const config: LoginGatewayConfig = {
      listenHost: '127.0.0.1',
      listenPort: 0,
      upstreamHost: '127.0.0.1',
      upstreamPort: upstream.port,
      loginPath: '/login',
      logoutPath: '/logout',
      users: [],
      session: { maxAgeSeconds: 3600, cookieName: 'gw_session', secure: 'never' },
    }
    const resolved = resolveConfig(config, upstream.port)
    const cookies = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: upstream.port },
      authenticatedUrl: (baseUrl) => {
        const url = new URL(baseUrl)
        url.searchParams.set('token', upstream.launchToken)
        return url.href
      },
    })
    setupGateway = createLoginGateway(resolved, {
      upstreamCookie: authority => cookies.cookieFor(authority),
      users: createUserDirectory([], credentials),
      logger: { info: () => {}, warn: () => {} },
    })
    await setupGateway.start()
    setupBase = setupGateway.url
  })

  afterEach(async () => {
    await setupGateway.stop()
  })

  async function createAccount(body: Record<string, string>): Promise<Response> {
    return await fetch(`${setupBase}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: setupBase },
      body: new URLSearchParams(body),
      redirect: 'manual',
    })
  }

  it('serves the setup form and refuses every other path', async () => {
    expect(setupGateway.configured).toBe(false)
    const form = await fetch(`${setupBase}/login`, { headers: { 'sec-fetch-dest': 'document' } })
    expect(form.status).toBe(200)
    expect(await form.text()).toContain('Create the first account')

    const api = await fetch(`${setupBase}/api/sessions`)
    expect(api.status).toBe(503)
    await expect(api.json()).resolves.toEqual({ error: 'not-configured' })

    const page = await fetch(`${setupBase}/`, { headers: { 'sec-fetch-dest': 'document' } })
    expect(page.status).toBe(503)
    expect(await page.text()).toContain('Not configured')
  })

  it('exchanges the setup token for a cookie and refuses a wrong one', async () => {
    const exchanged = await fetch(`${setupBase}/login?setup=${setupGateway.setupToken}`, { redirect: 'manual' })
    expect(exchanged.status).toBe(303)
    expect(exchanged.headers.get('location')).toBe('/login')
    const cookie = exchanged.headers.getSetCookie()[0]?.split(';')[0] ?? ''
    expect(cookie).toContain('dsh_login_setup=')

    const wrong = await fetch(`${setupBase}/login?setup=nope`, { redirect: 'manual' })
    expect(wrong.status).toBe(403)
    expect(await wrong.text()).toContain('Setup is local-only')
  })

  it('creates the first account, enrolls the secret, and signs in with it', async () => {
    const created = await createAccount({
      username: 'alice',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    })
    expect(created.status).toBe(200)
    const enrollment = await created.text()
    expect(enrollment).toContain('Add the authenticator')
    expect(enrollment).toContain('otpauth://totp/')
    expect(credentials.records.has('login-gateway/alice')).toBe(true)
    expect(setupGateway.configured).toBe(true)

    const secret = /value="([A-Z2-7 ]{8,})"/u.exec(enrollment)?.[1]?.replaceAll(' ', '')
    expect(secret).toBeDefined()
    const login = await fetch(`${setupBase}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: setupBase },
      body: new URLSearchParams({
        username: 'alice',
        password: SETUP_PASSWORD,
        otp: generateTotp(secret ?? '') ?? '',
      }),
      redirect: 'manual',
    })
    expect(login.status).toBe(303)
    expect(login.headers.getSetCookie()[0]).toContain('gw_session=')
  })

  it('rejects a username, password, or confirmation the form cannot accept', async () => {
    const cases: readonly (readonly [Record<string, string>, RegExp])[] = [
      [{ username: 'Alice', password: SETUP_PASSWORD, confirm: SETUP_PASSWORD }, /lowercase letters/u],
      [{ username: 'alice', password: 'short', confirm: 'short' }, /at least 12 characters/u],
      [{ username: 'alice', password: SETUP_PASSWORD, confirm: 'something-else' }, /do not match/u],
    ]
    for (const [body, expected] of cases) {
      const response = await createAccount(body)
      expect(response.status).toBe(400)
      expect(await response.text()).toMatch(expected)
    }
    expect(credentials.records.size).toBe(0)
    expect(setupGateway.configured).toBe(false)
  })

  it('refuses a cross-site setup post', async () => {
    const response = await fetch(`${setupBase}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' },
      body: new URLSearchParams({ username: 'alice', password: SETUP_PASSWORD, confirm: SETUP_PASSWORD }),
      redirect: 'manual',
    })
    expect(response.status).toBe(403)
    expect(credentials.records.size).toBe(0)
  })

  it('accepts a same-origin post when a proxy rewrote Host', async () => {
    const response = await requestWithHeaders('POST', setupBase, '/login', {
      // What a tunnel that does not preserve Host sends, while the browser's
      // own Fetch Metadata still says the request is same-origin.
      host: '127.0.0.1:9',
      origin: 'https://harness.example.com',
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/x-www-form-urlencoded',
    }, new URLSearchParams({
      username: 'proxied',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    }).toString())
    expect(response.status).toBe(200)
    expect(response.body).toContain('Add the authenticator')
  })

  it('still refuses a cross-site post that claims nothing', async () => {
    const response = await requestWithHeaders('POST', setupBase, '/login', {
      host: '127.0.0.1:9',
      origin: 'https://evil.example',
      'sec-fetch-site': 'cross-site',
      'content-type': 'application/x-www-form-urlencoded',
    }, new URLSearchParams({
      username: 'attacker',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    }).toString())
    expect(response.status).toBe(403)
    expect(credentials.records.size).toBe(0)
  })

  it('falls back to X-Forwarded-Host without Fetch Metadata', async () => {
    // X-Forwarded-Host also marks the request as proxied, so setup needs the
    // token; the point of this case is the Origin comparison itself.
    const exchange = await requestWithHeaders(
      'GET',
      setupBase,
      `/login?setup=${setupGateway.setupToken}`,
      { 'x-forwarded-host': 'harness.example.com' },
    )
    const cookie = (exchange.headers['set-cookie'] ?? [])
      .map(String)
      .find(value => value.startsWith('dsh_login_setup='))?.split(';')[0] ?? ''
    const response = await requestWithHeaders('POST', setupBase, '/login', {
      host: '127.0.0.1:9',
      'x-forwarded-host': 'harness.example.com',
      cookie,
      origin: 'https://harness.example.com',
      'content-type': 'application/x-www-form-urlencoded',
    }, new URLSearchParams({
      username: 'forwarded',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    }).toString())
    expect(response.status).toBe(200)
    expect(response.body).toContain('Add the authenticator')
  })

  it('refuses setup to a proxied request that only looks loopback', async () => {
    const response = await requestWithHeaders('POST', setupBase, '/login', {
      // A tunnel connects from loopback and adds this header.
      'x-forwarded-for': '203.0.113.9',
      origin: setupBase,
      'content-type': 'application/x-www-form-urlencoded',
    }, new URLSearchParams({
      username: 'proxied',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    }).toString())
    expect(response.status).toBe(403)
    expect(response.body).toContain('Setup is local-only')
    expect(credentials.records.size).toBe(0)
  })

  it('allows a proxied setup that presents the one-time token', async () => {
    const exchange = await requestWithHeaders(
      'GET',
      setupBase,
      `/login?setup=${setupGateway.setupToken}`,
      { 'x-forwarded-for': '203.0.113.9' },
    )
    expect(exchange.status).toBe(303)
    const setCookie = exchange.headers['set-cookie'] ?? []
    const cookie = setCookie.map(String).find(value => value.startsWith('dsh_login_setup='))?.split(';')[0] ?? ''
    expect(cookie).not.toBe('')

    const created = await requestWithHeaders('POST', setupBase, '/login', {
      'x-forwarded-for': '203.0.113.9',
      cookie,
      origin: 'https://harness.example.com',
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/x-www-form-urlencoded',
    }, new URLSearchParams({
      username: 'proxied',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    }).toString())
    expect(created.status).toBe(200)
    expect(created.body).toContain('Add the authenticator')
  })

  it('returns to setup when the last stored account disappears', async () => {
    expect((await createAccount({
      username: 'alice',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    })).status).toBe(200)
    expect(setupGateway.configured).toBe(true)

    credentials.records.clear()

    const form = await fetch(`${setupBase}/login`, { headers: { 'sec-fetch-dest': 'document' } })
    expect(form.status).toBe(200)
    expect(await form.text()).toContain('Create the first account')
    expect(setupGateway.configured).toBe(false)
  })

  it('offers setup when a sign-in finds no account at all', async () => {
    expect((await createAccount({
      username: 'alice',
      password: SETUP_PASSWORD,
      confirm: SETUP_PASSWORD,
    })).status).toBe(200)
    credentials.records.clear()

    const response = await fetch(`${setupBase}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: setupBase },
      body: new URLSearchParams({ username: 'alice', password: SETUP_PASSWORD, otp: '000000' }),
      redirect: 'manual',
    })
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('Create the first account')
    expect(setupGateway.configured).toBe(false)
  })

  it('refuses an unauthenticated upgrade while unconfigured', async () => {
    const { status, socket } = await upgrade('/api/remote.mux', undefined, setupBase)
    expect(status).toBe(503)
    socket.destroy()
  })
})
