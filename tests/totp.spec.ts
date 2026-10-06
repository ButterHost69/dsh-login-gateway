import { describe, expect, it } from 'vitest'
import { encodeBase32 } from '../src/base32.ts'
import {
  DEFAULT_TOTP_OPTIONS,
  generateTotp,
  generateTotpSecret,
  hotp,
  totpUri,
  verifyTotp,
} from '../src/totp.ts'

const SHA1_SECRET = encodeBase32(Buffer.from('12345678901234567890', 'utf8'))
const SHA256_SECRET = encodeBase32(Buffer.from('12345678901234567890123456789012', 'utf8'))
const SHA512_SECRET = encodeBase32(
  Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'utf8'),
)

describe('hotp', () => {
  it('matches the RFC 6238 SHA-1 vectors at eight digits', () => {
    const secret = Buffer.from('12345678901234567890', 'utf8')
    const vectors: readonly (readonly [number, string])[] = [
      [59, '94287082'],
      [1_111_111_109, '07081804'],
      [1_111_111_111, '14050471'],
      [1_234_567_890, '89005924'],
      [2_000_000_000, '69279037'],
      [20_000_000_000, '65353130'],
    ]
    for (const [seconds, expected] of vectors) {
      expect(hotp(secret, Math.floor(seconds / 30), 8, 'sha1')).toBe(expected)
    }
  })

  it('matches the RFC 6238 SHA-256 and SHA-512 vectors', () => {
    const sha256 = Buffer.from('12345678901234567890123456789012', 'utf8')
    const sha512 = Buffer.from(
      '1234567890123456789012345678901234567890123456789012345678901234',
      'utf8',
    )
    expect(hotp(sha256, Math.floor(59 / 30), 8, 'sha256')).toBe('46119246')
    expect(hotp(sha256, Math.floor(1_111_111_109 / 30), 8, 'sha256')).toBe('68084774')
    expect(hotp(sha512, Math.floor(59 / 30), 8, 'sha512')).toBe('90693936')
    expect(hotp(sha512, Math.floor(20_000_000_000 / 30), 8, 'sha512')).toBe('47863826')
  })

  it('truncates to six digits', () => {
    const secret = Buffer.from('12345678901234567890', 'utf8')
    expect(hotp(secret, Math.floor(59 / 30), 6, 'sha1')).toBe('287082')
  })
})

describe('verifyTotp', () => {
  const options = { ...DEFAULT_TOTP_OPTIONS, digits: 8 }

  it('accepts the current step and one step either side', () => {
    const at = 1_234_567_890_000
    const code = generateTotp(SHA1_SECRET, options, at)
    expect(code).toBe('89005924')
    expect(verifyTotp(SHA1_SECRET, '89005924', options, at)).toBe(true)
    expect(verifyTotp(SHA1_SECRET, '89005924', options, at + 30_000)).toBe(true)
    expect(verifyTotp(SHA1_SECRET, '89005924', options, at - 30_000)).toBe(true)
    expect(verifyTotp(SHA1_SECRET, '89005924', options, at + 60_000)).toBe(false)
    expect(verifyTotp(SHA1_SECRET, '89005924', options, at - 60_000)).toBe(false)
  })

  it('rejects wrong codes, wrong lengths, and non-digits', () => {
    const at = 1_234_567_890_000
    expect(verifyTotp(SHA1_SECRET, '89005925', options, at)).toBe(false)
    expect(verifyTotp(SHA1_SECRET, '8900592', options, at)).toBe(false)
    expect(verifyTotp(SHA1_SECRET, 'abcdefgh', options, at)).toBe(false)
    expect(verifyTotp(SHA1_SECRET, '', options, at)).toBe(false)
  })

  it('honours the configured algorithm and period', () => {
    const at = 59_000
    const sha256 = { digits: 8, periodSeconds: 30, algorithm: 'sha256' as const, windowSteps: 0 }
    expect(generateTotp(SHA256_SECRET, sha256, at)).toBe('46119246')
    expect(verifyTotp(SHA256_SECRET, '46119246', sha256, at)).toBe(true)
    const long = { digits: 8, periodSeconds: 60, algorithm: 'sha512' as const, windowSteps: 0 }
    const longCode = generateTotp(SHA512_SECRET, long, at)
    expect(longCode).toBeDefined()
    expect(verifyTotp(SHA512_SECRET, longCode ?? '', long, at)).toBe(true)
  })

  it('rejects an undecodable secret', () => {
    expect(verifyTotp('not base32!', '123456', DEFAULT_TOTP_OPTIONS, 0)).toBe(false)
    expect(generateTotp('not base32!', DEFAULT_TOTP_OPTIONS, 0)).toBeUndefined()
  })

  it('accepts a secret written with spaces and lower case', () => {
    const at = 59_000
    const grouped = SHA1_SECRET.toLowerCase().replace(/(.{4})/gu, '$1 ').trim()
    expect(verifyTotp(grouped, '94287082', options, at)).toBe(true)
  })
})

describe('enrollment helpers', () => {
  it('generates a decodable 160-bit secret', () => {
    const secret = generateTotpSecret()
    expect(secret).toMatch(/^[A-Z2-7]{32}$/u)
    expect(generateTotp(secret, DEFAULT_TOTP_OPTIONS, 0)).toMatch(/^\d{6}$/u)
  })

  it('builds an otpauth URI carrying the parameters', () => {
    const uri = new URL(totpUri({ secret: 'ABC234', account: 'alice@example.com', issuer: 'Harness' }))
    expect(uri.protocol).toBe('otpauth:')
    expect(uri.host).toBe('totp')
    expect(decodeURIComponent(uri.pathname)).toBe('/Harness:alice@example.com')
    expect(uri.searchParams.get('secret')).toBe('ABC234')
    expect(uri.searchParams.get('issuer')).toBe('Harness')
    expect(uri.searchParams.get('algorithm')).toBe('SHA1')
    expect(uri.searchParams.get('digits')).toBe('6')
    expect(uri.searchParams.get('period')).toBe('30')
  })
})
