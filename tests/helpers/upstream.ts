/**
 * A stand-in for the harness web server.
 *
 * It reproduces the one exchange the gateway depends on — a `?token=` request
 * answered with a signed `dsh-auth-*` cookie — plus authenticated HTTP routes
 * and a WebSocket upgrade, so the integration suite exercises the gateway over
 * real sockets.
 */

import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { AddressInfo, Socket } from 'node:net'

/** A running fake upstream. */
export interface FakeUpstream {
  /** Listening port. */
  readonly port: number
  /** Token the upstream exchanges for a cookie. */
  readonly launchToken: string
  /** Name of the cookie the upstream issues. */
  readonly cookieName: string
  /** Value of the cookie the upstream issues. */
  readonly cookieValue: string
  /** Number of token exchanges served so far. */
  exchanges(): number
  /** Stop the server. */
  close(): Promise<void>
}

const WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

/**
 * Start the fake upstream on an OS-assigned loopback port.
 * @returns the running upstream and its facts.
 */
export async function startFakeUpstream(): Promise<FakeUpstream> {
  const launchToken = 'launch-token-abc123'
  const cookieName = 'dsh-auth-deadbeef'
  const cookieValue = 'signed-session-value'
  let exchanges = 0

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://upstream.invalid')
    if (url.pathname === '/' && url.searchParams.get('token') === launchToken) {
      exchanges += 1
      res.writeHead(303, {
        location: './',
        'set-cookie': `${cookieName}=${cookieValue}; Max-Age=3600; Path=/`,
      })
      res.end()
      return
    }
    if (!(req.headers.cookie ?? '').includes(`${cookieName}=${cookieValue}`)) {
      res.writeHead(401, { 'content-type': 'text/plain' })
      res.end('upstream unauthorized')
      return
    }
    if (url.pathname === '/api/echo') {
      const chunks: Buffer[] = []
      req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      req.on('end', () => {
        res.writeHead(200, {
          'content-type': 'application/json',
          // A stale harness cookie must never reach the browser through the gateway.
          'set-cookie': `${cookieName}=stale; Path=/`,
        })
        res.end(JSON.stringify({
          method: req.method,
          path: url.pathname,
          body: Buffer.concat(chunks).toString('utf8'),
          host: req.headers.host,
          cookie: req.headers.cookie,
          forwardedFor: req.headers['x-forwarded-for'],
          forwardedProto: req.headers['x-forwarded-proto'],
        }))
      })
      return
    }
    if (url.pathname === '/api/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.write('data: one\n\n')
      res.write('data: two\n\n')
      res.end()
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end(`<html><body>upstream:${url.pathname}</body></html>`)
  })

  server.on('upgrade', (req, socket) => {
    if (!(req.headers.cookie ?? '').includes(`${cookieName}=${cookieValue}`)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nconnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    const key = req.headers['sec-websocket-key'] ?? ''
    const accept = createHash('sha1').update(`${key}${WEBSOCKET_GUID}`).digest('base64')
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'upgrade: websocket\r\n'
      + 'connection: Upgrade\r\n'
      + `sec-websocket-accept: ${accept}\r\n\r\n`,
    )
    socket.on('data', (chunk: Buffer) => { socket.write(chunk) })
  })

  // Node does not close upgraded sockets from closeAllConnections(), so the
  // server tracks every connection it accepts and destroys them on close.
  const sockets = new Set<Socket>()
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.once('close', () => { sockets.delete(socket) })
  })

  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', () => { resolve() }) })
  const port = (server.address() as AddressInfo).port
  return {
    port,
    launchToken,
    cookieName,
    cookieValue,
    exchanges: () => exchanges,
    async close(): Promise<void> {
      const closed = new Promise<void>((resolve) => { server.close(() => { resolve() }) })
      for (const socket of sockets) socket.destroy()
      sockets.clear()
      server.closeAllConnections()
      await closed
    },
  }
}
