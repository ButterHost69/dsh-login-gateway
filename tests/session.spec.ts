import { describe, expect, it } from 'vitest'
import { SessionStore } from '../src/session.ts'

const SECRET = Buffer.alloc(32, 7)
const OTHER_SECRET = Buffer.alloc(32, 9)
const MAX_AGE = 60_000

function store(now: () => number, secret: Buffer = SECRET): SessionStore {
  return new SessionStore(secret, MAX_AGE, now)
}

describe('SessionStore', () => {
  it('creates and verifies a session', () => {
    const sessions = store(() => 1_000)
    const created = sessions.create('alice')
    expect(created.expiresAt).toBe(1_000 + MAX_AGE)
    expect(sessions.verify(created.value)).toEqual({ username: 'alice', expiresAt: 61_000 })
  })

  it('rejects a missing, malformed, or tampered value', () => {
    const sessions = store(() => 1_000)
    const created = sessions.create('alice')
    expect(sessions.verify(undefined)).toBeUndefined()
    expect(sessions.verify('')).toBeUndefined()
    expect(sessions.verify('v1.only-two')).toBeUndefined()
    expect(sessions.verify('v2.abc.def')).toBeUndefined()
    const tampered = `${created.value.slice(0, -1)}${created.value.endsWith('A') ? 'B' : 'A'}`
    expect(sessions.verify(tampered)).toBeUndefined()
  })

  it('rejects a value signed with another secret', () => {
    const created = store(() => 1_000).create('alice')
    expect(store(() => 1_000, OTHER_SECRET).verify(created.value)).toBeUndefined()
  })

  it('rejects an expired session and drops it', () => {
    let now = 1_000
    const sessions = store(() => now)
    const created = sessions.create('alice')
    now = 1_000 + MAX_AGE
    expect(sessions.verify(created.value)).toBeUndefined()
    expect(sessions.size).toBe(0)
  })

  it('deletes by cookie value and prunes expired entries', () => {
    let now = 1_000
    const sessions = store(() => now)
    const first = sessions.create('alice')
    sessions.create('bob')
    sessions.delete(first.value)
    expect(sessions.verify(first.value)).toBeUndefined()
    expect(sessions.size).toBe(1)
    now = 1_000 + MAX_AGE
    sessions.prune()
    expect(sessions.size).toBe(0)
    sessions.delete(undefined)
  })
})
