import { describe, expect, it } from 'vitest'
import { decodeBase32, encodeBase32 } from '../src/base32.ts'

describe('base32', () => {
  it('decodes the RFC 4648 vectors', () => {
    const vectors: readonly (readonly [string, string])[] = [
      ['', ''],
      ['f', 'MY======'],
      ['fo', 'MZXQ===='],
      ['foo', 'MZXW6==='],
      ['foob', 'MZXW6YQ='],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI======'],
    ]
    for (const [plain, encoded] of vectors) {
      expect(Buffer.from(decodeBase32(encoded) ?? new Uint8Array()).toString('utf8')).toBe(plain)
      expect(encodeBase32(Buffer.from(plain, 'utf8'))).toBe(encoded.replace(/=+$/u, ''))
    }
  })

  it('ignores case, grouping, and padding', () => {
    const canonical = decodeBase32('MZXW6YTBOI')
    expect(Buffer.from(decodeBase32('mzxw 6ytb-oi') ?? new Uint8Array()).toString('utf8')).toBe('foobar')
    expect(decodeBase32('MZXW6YTBOI======')).toEqual(canonical)
  })

  it('rejects an empty or invalid secret', () => {
    expect(decodeBase32('')).toBeUndefined()
    expect(decodeBase32('   ')).toBeUndefined()
    expect(decodeBase32('MZXW6!')).toBeUndefined()
    expect(decodeBase32('0189')).toBeUndefined()
  })

  it('round-trips arbitrary bytes', () => {
    const bytes = Uint8Array.from({ length: 64 }, (_value, index) => (index * 37) % 256)
    expect(decodeBase32(encodeBase32(bytes))).toEqual(bytes)
  })
})
