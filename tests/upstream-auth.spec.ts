import { afterEach, describe, expect, it } from 'vitest'
import { createUpstreamCookieProvider } from '../src/upstream-auth.ts'
import { startFakeUpstream, type FakeUpstream } from './helpers/upstream.ts'

let upstream: FakeUpstream | undefined

afterEach(async () => {
  await upstream?.close()
  upstream = undefined
})

describe('createUpstreamCookieProvider', () => {
  it('exchanges the launch token for the harness cookie', async () => {
    upstream = await startFakeUpstream()
    const provider = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: upstream.port },
      authenticatedUrl: (baseUrl) => {
        const url = new URL(baseUrl)
        url.searchParams.set('token', upstream?.launchToken ?? '')
        return url.href
      },
    })
    await expect(provider.cookieFor('harness.example')).resolves
      .toBe(`${upstream.cookieName}=${upstream.cookieValue}`)
    expect(upstream.exchanges()).toBe(1)
  })

  it('reuses a cached cookie until it nears expiry', async () => {
    upstream = await startFakeUpstream()
    let now = 1_000
    const provider = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: upstream.port },
      authenticatedUrl: (baseUrl) => {
        const url = new URL(baseUrl)
        url.searchParams.set('token', upstream?.launchToken ?? '')
        return url.href
      },
      now: () => now,
      refreshMarginMilliseconds: 60_000,
    })
    await provider.cookieFor('harness.example')
    now += 3_000_000
    await provider.cookieFor('harness.example')
    expect(upstream.exchanges()).toBe(1)
    // The cookie was issued for 3600 s; past that minus the margin it is re-minted.
    now += 600_000
    await provider.cookieFor('harness.example')
    expect(upstream.exchanges()).toBe(2)
  })

  it('mints one cookie per authority', async () => {
    upstream = await startFakeUpstream()
    const provider = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: upstream.port },
      authenticatedUrl: (baseUrl) => {
        const url = new URL(baseUrl)
        url.searchParams.set('token', upstream?.launchToken ?? '')
        return url.href
      },
    })
    await provider.cookieFor('one.example')
    await provider.cookieFor('two.example')
    expect(upstream.exchanges()).toBe(2)
  })

  it('reports an unavailable upstream instead of throwing', async () => {
    const provider = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: 1 },
      authenticatedUrl: (baseUrl) => `${baseUrl}?token=none`,
    })
    await expect(provider.cookieFor('harness.example')).resolves.toBeUndefined()
  })

  it('rejects an unparsable authority', async () => {
    upstream = await startFakeUpstream()
    const provider = createUpstreamCookieProvider({
      upstream: { host: '127.0.0.1', port: upstream.port },
      authenticatedUrl: (baseUrl) => `${baseUrl}?token=${upstream?.launchToken ?? ''}`,
    })
    await expect(provider.cookieFor('http://[bad')).resolves.toBeUndefined()
    expect(upstream.exchanges()).toBe(0)
  })
})
