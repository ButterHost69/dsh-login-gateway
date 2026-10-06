import { describe, expect, it } from 'vitest'
import { FailureLimiter } from '../src/rate-limit.ts'

const OPTIONS = { maxFailures: 3, windowMilliseconds: 60_000, lockoutMilliseconds: 120_000 }

describe('FailureLimiter', () => {
  it('allows attempts until the threshold, then locks', () => {
    let now = 1_000
    const limiter = new FailureLimiter(OPTIONS, () => now)
    expect(limiter.check('ip:1')).toEqual({ allowed: true, retryAfterSeconds: 0 })
    limiter.recordFailure('ip:1')
    limiter.recordFailure('ip:1')
    expect(limiter.check('ip:1').allowed).toBe(true)
    limiter.recordFailure('ip:1')
    expect(limiter.check('ip:1')).toEqual({ allowed: false, retryAfterSeconds: 120 })
  })

  it('releases the lock once the lockout expires', () => {
    let now = 1_000
    const limiter = new FailureLimiter(OPTIONS, () => now)
    for (let at = 0; at < 3; at += 1) limiter.recordFailure('ip:1')
    now += 119_000
    expect(limiter.check('ip:1').allowed).toBe(false)
    now += 1_000
    expect(limiter.check('ip:1').allowed).toBe(true)
  })

  it('forgets failures older than the window', () => {
    let now = 1_000
    const limiter = new FailureLimiter(OPTIONS, () => now)
    limiter.recordFailure('ip:1')
    limiter.recordFailure('ip:1')
    now += 61_000
    limiter.recordFailure('ip:1')
    expect(limiter.check('ip:1').allowed).toBe(true)
  })

  it('clears a key on success and prunes aged entries', () => {
    let now = 1_000
    const limiter = new FailureLimiter(OPTIONS, () => now)
    for (let at = 0; at < 3; at += 1) limiter.recordFailure('ip:1')
    limiter.recordSuccess('ip:1')
    expect(limiter.check('ip:1').allowed).toBe(true)
    for (let at = 0; at < 3; at += 1) limiter.recordFailure('ip:1')
    now += 200_000
    limiter.prune()
    expect(limiter.check('ip:1').allowed).toBe(true)
  })

  it('tracks keys independently', () => {
    const limiter = new FailureLimiter(OPTIONS, () => 1_000)
    for (let at = 0; at < 3; at += 1) limiter.recordFailure('ip:1')
    expect(limiter.check('ip:1').allowed).toBe(false)
    expect(limiter.check('ip:2').allowed).toBe(true)
  })
})
