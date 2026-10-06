/**
 * Failure-based throttling for the login endpoint.
 *
 * An internet-facing login is guessed at continuously, so failures are counted
 * per key (client address and submitted username) in a sliding window; passing
 * the threshold locks that key for a fixed period. Successes clear the key so a
 * legitimate user is never locked out by their own earlier typo.
 *
 * @module dsh-login-gateway/rate-limit
 */

/** Thresholds for one limiter. */
export interface RateLimitOptions {
  /** Failures within the window that trigger a lockout. */
  readonly maxFailures: number
  /** Sliding window length in milliseconds. */
  readonly windowMilliseconds: number
  /** How long a triggered lockout lasts in milliseconds. */
  readonly lockoutMilliseconds: number
}

/** Whether a key may attempt a login now. */
export interface RateLimitDecision {
  /** True when the key is not locked out. */
  readonly allowed: boolean
  /** Seconds until the key may retry; 0 when allowed. */
  readonly retryAfterSeconds: number
}

/** Sliding-window failure counter with lockout. */
export class FailureLimiter {
  private readonly failures = new Map<string, number[]>()
  private readonly lockedUntil = new Map<string, number>()

  /**
   * @param options - thresholds.
   * @param now - clock, injectable for tests.
   */
  constructor(
    private readonly options: RateLimitOptions,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Check whether a key may attempt a login.
   * @param key - the tracked identity, such as `ip:127.0.0.1`.
   * @returns the decision and, when locked, the retry delay.
   */
  check(key: string): RateLimitDecision {
    const until = this.lockedUntil.get(key)
    if (until === undefined) return { allowed: true, retryAfterSeconds: 0 }
    const now = this.now()
    if (until > now) {
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((until - now) / 1000)) }
    }
    this.lockedUntil.delete(key)
    this.failures.delete(key)
    return { allowed: true, retryAfterSeconds: 0 }
  }

  /**
   * Record one failed attempt and lock the key once it passes the threshold.
   * @param key - the tracked identity.
   */
  recordFailure(key: string): void {
    const now = this.now()
    const recent = (this.failures.get(key) ?? []).filter(at => now - at < this.options.windowMilliseconds)
    recent.push(now)
    this.failures.set(key, recent)
    if (recent.length >= this.options.maxFailures) {
      this.lockedUntil.set(key, now + this.options.lockoutMilliseconds)
    }
  }

  /**
   * Clear a key after a successful login.
   * @param key - the tracked identity.
   */
  recordSuccess(key: string): void {
    this.failures.delete(key)
    this.lockedUntil.delete(key)
  }

  /** Drop window entries and lockouts that have aged out. */
  prune(): void {
    const now = this.now()
    for (const [key, timestamps] of this.failures) {
      const recent = timestamps.filter(at => now - at < this.options.windowMilliseconds)
      if (recent.length === 0) this.failures.delete(key)
      else this.failures.set(key, recent)
    }
    for (const [key, until] of this.lockedUntil) {
      if (until <= now) this.lockedUntil.delete(key)
    }
  }
}
