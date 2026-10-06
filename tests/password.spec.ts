import { describe, expect, it } from 'vitest'
import {
  DEFAULT_SCRYPT_PARAMS,
  dummyPasswordVerify,
  hashPassword,
  parsePasswordHash,
  verifyPassword,
} from '../src/password.ts'

describe('password hashing', () => {
  it('verifies the password it hashed', async () => {
    const encoded = await hashPassword('correct horse battery staple')
    expect(encoded.startsWith('scrypt$')).toBe(true)
    await expect(verifyPassword('correct horse battery staple', encoded)).resolves.toBe(true)
    await expect(verifyPassword('wrong password', encoded)).resolves.toBe(false)
  })

  it('salts every hash independently', async () => {
    const first = await hashPassword('same password')
    const second = await hashPassword('same password')
    expect(first).not.toBe(second)
    await expect(verifyPassword('same password', first)).resolves.toBe(true)
    await expect(verifyPassword('same password', second)).resolves.toBe(true)
  })

  it('round-trips non-ASCII and long passwords', async () => {
    const password = 'пароль-🔐-日本語'
    await expect(verifyPassword(password, await hashPassword(password))).resolves.toBe(true)
    const long = 'x'.repeat(4096)
    await expect(verifyPassword(long, await hashPassword(long))).resolves.toBe(true)
  })

  it('honours explicit work parameters', async () => {
    const encoded = await hashPassword('pw', { N: 1024, r: 4, p: 2 })
    const parsed = parsePasswordHash(encoded)
    expect(parsed?.params).toEqual({ N: 1024, r: 4, p: 2, keyLength: DEFAULT_SCRYPT_PARAMS.keyLength })
    await expect(verifyPassword('pw', encoded)).resolves.toBe(true)
  })

  it('rejects malformed stored hashes', () => {
    const valid = 'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    expect(parsePasswordHash(valid)).toBeDefined()
    expect(parsePasswordHash('')).toBeUndefined()
    expect(parsePasswordHash('bcrypt$16384$8$1$aa$bb')).toBeUndefined()
    expect(parsePasswordHash('scrypt$16384$8$1$aa')).toBeUndefined()
    expect(parsePasswordHash('scrypt$0$8$1$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeUndefined()
    expect(parsePasswordHash('scrypt$16384$8$1$not base64!$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeUndefined()
    expect(parsePasswordHash('scrypt$999999999$8$1$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeUndefined()
  })

  it('reports a malformed stored hash as a failed verification', async () => {
    await expect(verifyPassword('pw', 'nonsense')).resolves.toBe(false)
  })

  it('spends a derivation for an unknown user', async () => {
    await expect(dummyPasswordVerify('anything')).resolves.toBeUndefined()
  })
})
