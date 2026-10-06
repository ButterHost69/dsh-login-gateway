/**
 * A bounded HTTP/1.1 reverse proxy with WebSocket upgrade forwarding.
 *
 * The gateway only ever forwards to the configured upstream, so this module is
 * not a general-purpose proxy: it preserves the browser-facing `Host`, drops
 * hop-by-hop headers in both directions, re-frames bodies through Node's own
 * HTTP client (so chunked and streamed bodies, including large uploads and SSE,
 * pass through without buffering), and tunnels upgraded sockets.
 *
 * @module dsh-login-gateway/proxy
 */

import { request as createRequest } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'

/** The one backend this gateway forwards to. */
export interface UpstreamTarget {
  /** Upstream host. */
  readonly host: string
  /** Upstream port. */
  readonly port: number
}

/** Options shared by request and upgrade forwarding. */
export interface ProxyOptions {
  /** The backend to reach. */
  readonly target: UpstreamTarget
  /** Headers set or replaced on the upstream request. */
  readonly extraHeaders: Readonly<Record<string, string>>
  /** Request headers removed before forwarding. */
  readonly dropHeaders?: readonly string[]
  /** Response `Set-Cookie` values with this prefix are withheld from the browser. */
  readonly dropResponseCookiePrefix?: string
  /** Called on transport failure after the caller's response is handled. */
  readonly onError: (error: Error) => void
}

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Build the upstream request headers: hop-by-hop headers and any header named
 * by `Connection` are removed, the listed headers are dropped, and `extra`
 * entries are applied last.
 * @param headers - the incoming request headers.
 * @param extra - headers to set or replace.
 * @param drop - additional header names to remove.
 * @returns headers for the upstream request.
 */
export function forwardRequestHeaders(
  headers: IncomingHttpHeaders,
  extra: Readonly<Record<string, string>>,
  drop: readonly string[] = [],
): Record<string, string> {
  const dropped = new Set(drop.map(name => name.toLowerCase()))
  const connectionTokens = new Set(
    (headers.connection ?? '')
      .split(',')
      .map(token => token.trim().toLowerCase())
      .filter(token => token !== ''),
  )
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    const lower = name.toLowerCase()
    if (HOP_BY_HOP.has(lower) || connectionTokens.has(lower) || dropped.has(lower)) continue
    out[lower] = Array.isArray(value) ? value.join(', ') : value
  }
  for (const [name, value] of Object.entries(extra)) out[name.toLowerCase()] = value
  return out
}

/**
 * Build the browser-facing response headers, dropping hop-by-hop headers and
 * optionally withholding named `Set-Cookie` values.
 * @param headers - the upstream response headers.
 * @param dropCookiePrefix - when set, `Set-Cookie` values starting with it are removed.
 * @returns headers for the browser response.
 */
export function forwardResponseHeaders(
  headers: IncomingHttpHeaders,
  dropCookiePrefix?: string,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    const lower = name.toLowerCase()
    if (HOP_BY_HOP.has(lower)) continue
    if (lower === 'set-cookie') {
      const values = Array.isArray(value) ? value : [value]
      const kept = dropCookiePrefix === undefined
        ? values
        : values.filter(cookie => !cookie.startsWith(dropCookiePrefix))
      if (kept.length > 0) out[lower] = kept
      continue
    }
    out[lower] = value
  }
  return out
}

/**
 * Forward one HTTP request and stream its response.
 * @param req - the browser request.
 * @param res - the browser response.
 * @param options - target, header edits, and failure reporting.
 */
export function proxyRequest(req: IncomingMessage, res: ServerResponse, options: ProxyOptions): void {
  const upstream = createRequest({
    host: options.target.host,
    port: options.target.port,
    method: req.method,
    path: req.url ?? '/',
    headers: forwardRequestHeaders(req.headers, options.extraHeaders, options.dropHeaders),
  }, (upstreamResponse) => {
    const status = upstreamResponse.statusCode ?? 502
    const headers = forwardResponseHeaders(upstreamResponse.headers, options.dropResponseCookiePrefix)
    if (upstreamResponse.statusMessage === undefined) res.writeHead(status, headers)
    else res.writeHead(status, upstreamResponse.statusMessage, headers)
    upstreamResponse.pipe(res)
  })
  upstream.on('error', (error: Error) => {
    options.onError(error)
    if (res.headersSent) {
      res.destroy()
      return
    }
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    res.end('Bad gateway\n')
  })
  // A browser that goes away mid-response must not leave the upstream request open.
  res.once('close', () => {
    if (!res.writableEnded) upstream.destroy()
  })
  req.pipe(upstream)
}

/**
 * Forward one upgraded socket, including the bytes already read after the
 * request headers on both legs.
 * @param req - the browser upgrade request.
 * @param socket - the browser socket.
 * @param head - bytes read past the browser request headers.
 * @param options - target, header edits, and failure reporting.
 */
export function proxyUpgrade(
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
  options: ProxyOptions,
): void {
  const headers = forwardRequestHeaders(req.headers, options.extraHeaders, options.dropHeaders)
  headers['connection'] = 'Upgrade'
  if (req.headers.upgrade !== undefined) headers['upgrade'] = req.headers.upgrade
  const upstream = createRequest({
    host: options.target.host,
    port: options.target.port,
    method: req.method ?? 'GET',
    path: req.url ?? '/',
    headers,
  })
  upstream.on('error', (error: Error) => {
    options.onError(error)
    socket.destroy()
  })
  upstream.on('response', (upstreamResponse) => {
    // The upstream answered with a normal response instead of upgrading.
    const status = upstreamResponse.statusCode ?? 502
    const lines = [`HTTP/1.1 ${status} ${upstreamResponse.statusMessage ?? 'Bad Gateway'}`]
    const headers = forwardResponseHeaders(upstreamResponse.headers, options.dropResponseCookiePrefix)
    for (const [name, value] of Object.entries(headers)) {
      for (const entry of Array.isArray(value) ? value : [value]) lines.push(`${name}: ${entry}`)
    }
    socket.write(`${lines.join('\r\n')}\r\n\r\n`)
    upstreamResponse.pipe(socket)
  })
  upstream.on('upgrade', (upstreamResponse, upstreamSocket, upstreamHead) => {
    const lines = [
      `HTTP/1.1 ${upstreamResponse.statusCode ?? 101} ${upstreamResponse.statusMessage ?? 'Switching Protocols'}`,
    ]
    const raw = upstreamResponse.rawHeaders
    for (let at = 0; at + 1 < raw.length; at += 2) {
      lines.push(`${raw[at] ?? ''}: ${raw[at + 1] ?? ''}`)
    }
    socket.write(`${lines.join('\r\n')}\r\n\r\n`)
    if (upstreamHead.byteLength > 0) socket.write(upstreamHead)
    if (head.byteLength > 0) upstreamSocket.write(head)
    upstreamSocket.pipe(socket)
    socket.pipe(upstreamSocket)
    const destroy = (): void => {
      upstreamSocket.destroy()
      socket.destroy()
    }
    socket.on('error', destroy)
    upstreamSocket.on('error', destroy)
    socket.once('close', () => { upstreamSocket.destroy() })
    upstreamSocket.once('close', () => { socket.destroy() })
  })
  upstream.end()
}
