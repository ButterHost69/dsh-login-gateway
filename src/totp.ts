/**
 * RFC 6238 TOTP verification (and generation, for enrollment and tests).
 *
 * The verifier accepts a bounded window of time steps so a code typed just
 * before or after a step boundary still works, and it compares every candidate
 * in constant time without an early exit, so a wrong code reveals nothing about
 * how close it was.
 *
 * @module dsh-login-gateway/totp
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { decodeBase32, encodeBase32 } from './base32.ts'

/** Hash algorithms authenticator apps support for TOTP. */
export type TotpAlgorithm = 'sha1' | 'sha256' | 'sha512'

/** How one TOTP secret is turned into codes. */
export interface TotpOptions {
  /** Code length in decimal digits. */
  readonly digits: number
  /** Seconds per time step. */
  readonly periodSeconds: number
  /** HMAC hash algorithm. */
  readonly algorithm: TotpAlgorithm
  /** Time steps accepted on either side of the current one. */
  readonly windowSteps: number
}

/** The defaults authenticator apps use for new TOTP entries. */
export const DEFAULT_TOTP_OPTIONS: TotpOptions = {
  digits: 6,
  periodSeconds: 30,
  algorithm: 'sha1',
  windowSteps: 1,
}

/** Secret length in bytes; 160 bits is the RFC 4226 recommendation. */
const SECRET_BYTES = 20

/**
 * Mint a fresh random TOTP secret.
 * @param bytes - secret length in bytes.
 * @returns the secret as unpadded base32.
 */
export function generateTotpSecret(bytes: number = SECRET_BYTES): string {
  return encodeBase32(randomBytes(bytes))
}

/**
 * Compute one HOTP value (RFC 4226 dynamic truncation).
 * @param secret - decoded shared secret.
 * @param counter - the time step.
 * @param digits - code length in decimal digits.
 * @param algorithm - HMAC hash algorithm.
 * @returns the zero-padded decimal code.
 */
export function hotp(secret: Uint8Array, counter: number, digits: number, algorithm: TotpAlgorithm): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac(algorithm, secret).update(message).digest()
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f
  const binary = ((digest[offset] ?? 0) & 0x7f) << 24
    | (digest[offset + 1] ?? 0) << 16
    | (digest[offset + 2] ?? 0) << 8
    | (digest[offset + 3] ?? 0)
  return String(binary % 10 ** digits).padStart(digits, '0')
}

/**
 * Compute the code for one instant, for enrollment checks and tests.
 * @param secretBase32 - the base32 shared secret.
 * @param options - digits, period, algorithm, and window.
 * @param nowMilliseconds - the instant, defaulting to the current time.
 * @returns the current code, or undefined when the secret is not base32.
 */
export function generateTotp(
  secretBase32: string,
  options: TotpOptions = DEFAULT_TOTP_OPTIONS,
  nowMilliseconds: number = Date.now(),
): string | undefined {
  const secret = decodeBase32(secretBase32)
  if (secret === undefined || secret.byteLength === 0) return undefined
  const step = Math.floor(nowMilliseconds / 1000 / options.periodSeconds)
  return hotp(secret, step, options.digits, options.algorithm)
}

/**
 * Verify a submitted code against a secret, accepting the configured window.
 * @param secretBase32 - the base32 shared secret.
 * @param code - the submitted decimal code.
 * @param options - digits, period, algorithm, and window.
 * @param nowMilliseconds - the instant to verify against, defaulting to the current time.
 * @returns true only when one candidate step matches exactly.
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  options: TotpOptions = DEFAULT_TOTP_OPTIONS,
  nowMilliseconds: number = Date.now(),
): boolean {
  const secret = decodeBase32(secretBase32)
  if (secret === undefined || secret.byteLength === 0) return false
  if (code.length !== options.digits || !/^\d+$/u.test(code)) return false
  const supplied = Buffer.from(code, 'utf8')
  const step = Math.floor(nowMilliseconds / 1000 / options.periodSeconds)
  let matched = 0
  for (let offset = -options.windowSteps; offset <= options.windowSteps; offset += 1) {
    const candidateStep = step + offset
    // A negative step cannot have produced a code; skipping it also keeps the
    // 64-bit counter conversion total.
    if (candidateStep < 0) continue
    const candidate = Buffer.from(hotp(secret, candidateStep, options.digits, options.algorithm), 'utf8')
    if (candidate.byteLength === supplied.byteLength && timingSafeEqual(candidate, supplied)) matched = 1
  }
  return matched === 1
}

/**
 * Build the `otpauth://` URI an authenticator app enrolls from.
 * @param options - secret, account name, issuer, and the code parameters.
 * @returns the enrollment URI.
 */
export function totpUri(options: {
  readonly secret: string
  readonly account: string
  readonly issuer: string
} & Partial<Omit<TotpOptions, 'windowSteps'>>): string {
  const digits = options.digits ?? DEFAULT_TOTP_OPTIONS.digits
  const period = options.periodSeconds ?? DEFAULT_TOTP_OPTIONS.periodSeconds
  const algorithm = (options.algorithm ?? DEFAULT_TOTP_OPTIONS.algorithm).toUpperCase()
  const label = `${options.issuer}:${options.account}`
  const query = new URLSearchParams({
    secret: options.secret,
    issuer: options.issuer,
    algorithm,
    digits: String(digits),
    period: String(period),
  })
  return `otpauth://totp/${encodeURIComponent(label)}?${query.toString()}`
}
