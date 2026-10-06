/**
 * Mints and caches the harness's own browser-session cookie on behalf of
 * authenticated users.
 *
 * The Web composition authenticates browsers with a process launch token that
 * is exchanged for a signed, authority-bound cookie. The gateway keeps that
 * exchange server-side: it asks Connection for the tokenized URL, performs the
 * exchange itself, and attaches the resulting cookie to forwarded requests, so
 * the launch token and the harness cookie never reach the browser.
 *
 * @module dsh-login-gateway/upstream-auth
 */

import { request as createRequest } from 'node:http'
import type { UpstreamTarget } from './proxy.ts'

/** Cookie-name prefix the harness uses for its browser session. */
export const AUTH_COOKIE_PREFIX = 'dsh-auth-'

/** Resolves the harness cookie for one browser authority. */
export interface UpstreamCookieProvider {
  /**
   * Get a usable harness cookie for an authority, minting one when absent or stale.
   * @param authority - the browser-facing `host[:port]`.
   * @returns the `name=value` pair, or undefined when the exchange failed.
   */
  cookieFor(authority: string): Promise<string | undefined>
}

/** Construction inputs for {@link createUpstreamCookieProvider}. */
export interface UpstreamCookieOptions {
  /** The harness web server to exchange against. */
  readonly upstream: UpstreamTarget
  /** Connection's launch-URL builder. */
  readonly authenticatedUrl: (baseUrl: string) => string
  /** Clock, injectable for tests. */
  readonly now?: () => number
  /** Re-mint when the cached cookie has less than this long to live. */
  readonly refreshMarginMilliseconds?: number
}

const DEFAULT_REFRESH_MARGIN_MILLISECONDS = 60_000
const FALLBACK_LIFETIME_MILLISECONDS = 60 * 60 * 1000
const FORBIDDEN_AUTHORITY = /[\s/\\@?#]/u

interface CachedCookie {
  readonly cookie: string
  readonly expiresAt: number
}

/**
 * Exchange the process launch token for the harness cookie, one authority at a
 * time, and reuse it until it is close to expiry.
 * @param options - upstream, launch-URL builder, and clock.
 * @returns the provider.
 */
export function createUpstreamCookieProvider(options: UpstreamCookieOptions): UpstreamCookieProvider {
  const cache = new Map<string, CachedCookie>()
  const now = options.now ?? Date.now
  const margin = options.refreshMarginMilliseconds ?? DEFAULT_REFRESH_MARGIN_MILLISECONDS
  return {
    async cookieFor(authority: string): Promise<string | undefined> {
      const canonical = canonicalAuthority(authority)
      if (canonical === undefined) return undefined
      const cached = cache.get(canonical)
      if (cached !== undefined && cached.expiresAt - margin > now()) return cached.cookie
      const minted = await mint(options, canonical, now)
      if (minted === undefined) {
        cache.delete(canonical)
        return undefined
      }
      cache.set(canonical, minted)
      return minted.cookie
    },
  }
}

/**
 * Canonicalize a browser authority for the cookie audience and the upstream
 * `Host` header, rejecting anything a URL cannot express as a bare authority.
 * @param authority - the browser-facing `host[:port]`.
 * @returns the canonical `host[:port]`, or undefined when it is not one.
 */
function canonicalAuthority(authority: string): string | undefined {
  if (authority === '' || FORBIDDEN_AUTHORITY.test(authority)) return undefined
  try {
    const url = new URL(`http://${authority}/`)
    if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return undefined
    if (url.username !== '' || url.password !== '') return undefined
    return url.host
  } catch {
    return undefined
  }
}

function mint(
  options: UpstreamCookieOptions,
  authority: string,
  now: () => number,
): Promise<CachedCookie | undefined> {
  let target: URL
  try {
    target = new URL(options.authenticatedUrl(`http://${authority}/`))
  } catch {
    return Promise.resolve(undefined)
  }
  if (target.pathname !== '/' || target.search === '') return Promise.resolve(undefined)
  const path = `${target.pathname}${target.search}`
  return new Promise((resolve) => {
    const exchange = createRequest({
      host: options.upstream.host,
      port: options.upstream.port,
      method: 'GET',
      path,
      headers: { host: authority, 'user-agent': 'dsh-login-gateway' },
    }, (response) => {
      response.resume()
      const setCookies = response.headers['set-cookie'] ?? []
      const authCookie = setCookies.find(cookie => cookie.startsWith(AUTH_COOKIE_PREFIX))
      if (authCookie === undefined) {
        resolve(undefined)
        return
      }
      const pair = authCookie.split(';')[0]
      if (pair === undefined || pair === '') {
        resolve(undefined)
        return
      }
      const maxAge = /;\s*max-age=(\d+)/iu.exec(authCookie)
      const lifetime = maxAge?.[1] === undefined
        ? FALLBACK_LIFETIME_MILLISECONDS
        : Number(maxAge[1]) * 1000
      resolve({ cookie: pair, expiresAt: now() + lifetime })
    })
    exchange.on('error', () => { resolve(undefined) })
    exchange.end()
  })
}
