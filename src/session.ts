/**
 * In-memory browser sessions with signed cookies.
 *
 * A session id is random and lives only in the process, so a restart signs
 * everyone out and no stolen cookie survives it. The cookie value binds the id
 * to an HMAC, so a guessed or edited id is rejected before any lookup.
 *
 * @module dsh-login-gateway/session
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/** One authenticated browser session. */
export interface SessionRecord {
  /** The authenticated username. */
  readonly username: string
  /** Absolute expiry in milliseconds since the epoch. */
  readonly expiresAt: number
}

/** A freshly created session and the cookie value that carries it. */
export interface CreatedSession {
  /** Cookie value to send to the browser. */
  readonly value: string
  /** Absolute expiry in milliseconds since the epoch. */
  readonly expiresAt: number
}

const VERSION = 'v1'
const ID_BYTES = 32
const SEPARATOR = '.'

/** Sessions for one gateway process, keyed by random id. */
export class SessionStore {
  private readonly sessions = new Map<string, SessionRecord>()

  /**
   * @param secret - HMAC key for cookie values.
   * @param maxAgeMilliseconds - session lifetime.
   * @param now - clock, injectable for tests.
   */
  constructor(
    private readonly secret: Buffer,
    private readonly maxAgeMilliseconds: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Number of live (not necessarily unexpired) sessions. */
  get size(): number {
    return this.sessions.size
  }

  /**
   * Create a session for one username.
   * @param username - the authenticated user.
   * @returns the cookie value and expiry.
   */
  create(username: string): CreatedSession {
    const id = randomBytes(ID_BYTES).toString('base64url')
    const expiresAt = this.now() + this.maxAgeMilliseconds
    this.sessions.set(id, { username, expiresAt })
    return { value: this.sign(id), expiresAt }
  }

  /**
   * Verify a cookie value and return its live session.
   * @param value - the cookie value, when present.
   * @returns the session, or undefined when the value is unsigned, unknown, or expired.
   */
  verify(value: string | undefined): SessionRecord | undefined {
    const id = value === undefined ? undefined : this.readId(value)
    if (id === undefined) return undefined
    const record = this.sessions.get(id)
    if (record === undefined) return undefined
    if (record.expiresAt <= this.now()) {
      this.sessions.delete(id)
      return undefined
    }
    return record
  }

  /**
   * Drop the session a cookie value names, when it is well formed.
   * @param value - the cookie value, when present.
   */
  delete(value: string | undefined): void {
    const id = value === undefined ? undefined : this.readId(value)
    if (id !== undefined) this.sessions.delete(id)
  }

  /** Drop every expired session. */
  prune(): void {
    const now = this.now()
    for (const [id, record] of this.sessions) {
      if (record.expiresAt <= now) this.sessions.delete(id)
    }
  }

  private sign(id: string): string {
    const body = `${VERSION}${SEPARATOR}${id}`
    return `${body}${SEPARATOR}${this.mac(body)}`
  }

  private readId(value: string): string | undefined {
    const parts = value.split(SEPARATOR)
    if (parts.length !== 3) return undefined
    const [version, id, signature] = parts
    if (version !== VERSION || id === undefined || id === '' || signature === undefined) return undefined
    const expected = Buffer.from(this.mac(`${VERSION}${SEPARATOR}${id}`), 'utf8')
    const actual = Buffer.from(signature, 'utf8')
    if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return undefined
    return id
  }

  private mac(body: string): string {
    return createHmac('sha256', this.secret).update(body).digest('base64url')
  }
}
