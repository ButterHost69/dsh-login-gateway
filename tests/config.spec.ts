import { describe, expect, it } from 'vitest'
import { Config, resolveConfig } from '../src/config.ts'
import { hashPassword } from '../src/password.ts'
import { generateTotpSecret } from '../src/totp.ts'

async function makeUser(username = 'alice'): Promise<{ username: string; passwordHash: string; totpSecret: string }> {
  return {
    username,
    passwordHash: await hashPassword('correct horse', { N: 1024, r: 8, p: 1 }),
    totpSecret: generateTotpSecret(),
  }
}

describe('Config schema', () => {
  it('applies defaults for an empty config', () => {
    const resolved = Config({}) as Record<string, unknown>
    expect(resolved['listenHost']).toBe('127.0.0.1')
    expect(resolved['listenPort']).toBe(8080)
    expect(resolved['loginPath']).toBe('/login')
    expect(resolved['logoutPath']).toBe('/logout')
    expect(resolved['users']).toEqual([])
    expect(resolved['trustProxy']).toBe(false)
    expect(resolved['session']).toMatchObject({ cookieName: 'dsh_login_session', secure: 'auto', maxAgeSeconds: 43_200 })
    expect(resolved['totp']).toMatchObject({ digits: 6, periodSeconds: 30, algorithm: 'sha1', windowSteps: 1 })
    expect(resolved['rateLimit']).toMatchObject({ maxFailures: 5, windowSeconds: 300, lockoutSeconds: 300 })
  })

  it('rejects values outside the declared ranges', () => {
    expect(() => Config({ listenPort: 70_000 })).toThrow()
  })
})

describe('resolveConfig', () => {
  it('resolves users and converts durations', async () => {
    const resolved = resolveConfig({ users: [await makeUser()] }, 3080)
    expect(resolved.upstreamPort).toBe(3080)
    expect(resolved.users).toHaveLength(1)
    expect(resolved.session.maxAgeMilliseconds).toBe(43_200_000)
    expect(resolved.rateLimit).toEqual({
      maxFailures: 5,
      windowMilliseconds: 300_000,
      lockoutMilliseconds: 300_000,
    })
  })

  it('lets an explicit upstreamPort override the server port', async () => {
    const resolved = resolveConfig({ users: [await makeUser()], upstreamPort: 9999 }, 3080)
    expect(resolved.upstreamPort).toBe(9999)
  })

  it('refuses to start with no users', () => {
    expect(() => resolveConfig({}, 3080)).toThrow(/config\.users is empty/u)
  })

  it('refuses duplicate usernames regardless of case', async () => {
    const first = await makeUser('Alice')
    const second = await makeUser('alice')
    expect(() => resolveConfig({ users: [first, second] }, 3080)).toThrow(/duplicate username/u)
  })

  it('refuses a blank or malformed username', async () => {
    const user = await makeUser()
    expect(() => resolveConfig({ users: [{ ...user, username: '   ' }] }, 3080))
      .toThrow(/non-empty username/u)
    expect(() => resolveConfig({ users: [{ ...user, username: 'a b' }] }, 3080))
      .toThrow(/non-empty username/u)
  })

  it('refuses a malformed password hash', async () => {
    const user = await makeUser()
    expect(() => resolveConfig({ users: [{ ...user, passwordHash: 'plain' }] }, 3080))
      .toThrow(/malformed passwordHash/u)
  })

  it('refuses a short or undecodable TOTP secret', async () => {
    const user = await makeUser()
    expect(() => resolveConfig({ users: [{ ...user, totpSecret: 'ABC' }] }, 3080))
      .toThrow(/invalid totpSecret/u)
    expect(() => resolveConfig({ users: [{ ...user, totpSecret: 'not-base32!' }] }, 3080))
      .toThrow(/invalid totpSecret/u)
  })

  it('refuses a login path that would shadow the API or is not a path', async () => {
    const users = [await makeUser()]
    expect(() => resolveConfig({ users, loginPath: 'login' }, 3080)).toThrow(/loginPath/u)
    expect(() => resolveConfig({ users, loginPath: '/api/login' }, 3080)).toThrow(/shadow the harness API/u)
    expect(() => resolveConfig({ users, loginPath: '/' }, 3080)).toThrow(/loginPath/u)
    expect(() => resolveConfig({ users, loginPath: '/login?x=1' }, 3080)).toThrow(/loginPath/u)
  })

  it('refuses identical login and logout paths', async () => {
    const users = [await makeUser()]
    expect(() => resolveConfig({ users, loginPath: '/same', logoutPath: '/same' }, 3080))
      .toThrow(/must differ/u)
  })

  it('refuses to listen on the upstream port', async () => {
    const users = [await makeUser()]
    expect(() => resolveConfig({ users, listenPort: 3080 }, 3080))
      .toThrow(/must differ from the upstream/u)
  })

  it('allows a shared port when the upstream is on another host', async () => {
    const resolved = resolveConfig(
      { users: [await makeUser()], listenPort: 3080, upstreamHost: 'upstream.internal' },
      3080,
    )
    expect(resolved.listenPort).toBe(3080)
  })

  it('refuses an invalid cookie name, short session, or bad rate limits', async () => {
    const users = [await makeUser()]
    expect(() => resolveConfig({ users, session: { cookieName: 'bad name' } }, 3080))
      .toThrow(/cookieName/u)
    expect(() => resolveConfig({ users, session: { maxAgeSeconds: 5 } }, 3080))
      .toThrow(/maxAgeSeconds/u)
    expect(() => resolveConfig({ users, rateLimit: { maxFailures: 0 } }, 3080))
      .toThrow(/rateLimit/u)
  })

  it('requires a usable upstream port when none is configured', async () => {
    const users = [await makeUser()]
    expect(() => resolveConfig({ users }, 0)).toThrow(/upstreamPort/u)
  })
})
