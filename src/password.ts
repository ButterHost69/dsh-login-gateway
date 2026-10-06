/**
 * Password hashing and verification with scrypt.
 *
 * Hashes are self-describing (`scrypt$N$r$p$salt$hash`, base64url) so a
 * deployment can raise the work factor later without invalidating existing
 * entries, and verification is a constant-time comparison of derived bytes.
 *
 * @module dsh-login-gateway/password
 */

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'

/** scrypt work parameters; `N` is the CPU/memory cost, `r` the block size, `p` the parallelism. */
export interface ScryptParams {
  /** CPU/memory cost; must be a power of two. */
  readonly N: number
  /** Block size. */
  readonly r: number
  /** Parallelization. */
  readonly p: number
  /** Derived key length in bytes. */
  readonly keyLength: number
}

/** Parameters used for new hashes: 16 MiB and roughly 50-100 ms on a modern core. */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = { N: 16_384, r: 8, p: 1, keyLength: 32 }

/** Salt length in bytes. */
const SALT_BYTES = 16

/** Ceiling for `N`-driven memory, so a mistyped hash cannot exhaust the process. */
const MAX_MEMORY_BYTES = 256 * 1024 * 1024

const PREFIX = 'scrypt'
const BASE64URL = /^[A-Za-z0-9_-]+$/u

/** A parsed password hash. */
export interface ParsedPasswordHash {
  /** Work parameters read from the hash. */
  readonly params: ScryptParams
  /** Salt bytes. */
  readonly salt: Buffer
  /** Expected derived key. */
  readonly hash: Buffer
}

function derive(
  password: string,
  salt: Buffer,
  params: ScryptParams,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(
      password,
      salt,
      params.keyLength,
      { N: params.N, r: params.r, p: params.p, maxmem: MAX_MEMORY_BYTES },
      (error, key) => {
        if (error !== null && error !== undefined) reject(error)
        else resolve(key)
      },
    )
  })
}

/**
 * Parse an encoded password hash.
 * @param encoded - the stored value.
 * @returns the work parameters and bytes, or undefined when the value is malformed.
 */
export function parsePasswordHash(encoded: string): ParsedPasswordHash | undefined {
  const parts = encoded.split('$')
  if (parts.length !== 6) return undefined
  const [prefix, rawN, rawR, rawP, rawSalt, rawHash] = parts
  if (prefix !== PREFIX || rawN === undefined || rawR === undefined || rawP === undefined
    || rawSalt === undefined || rawHash === undefined) return undefined
  if (!/^\d+$/u.test(rawN) || !/^\d+$/u.test(rawR) || !/^\d+$/u.test(rawP)) return undefined
  if (!BASE64URL.test(rawSalt) || !BASE64URL.test(rawHash)) return undefined
  const N = Number(rawN)
  const r = Number(rawR)
  const p = Number(rawP)
  const salt = Buffer.from(rawSalt, 'base64url')
  const hash = Buffer.from(rawHash, 'base64url')
  if (!Number.isSafeInteger(N) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) return undefined
  if (N < 2 || r < 1 || p < 1 || N > MAX_MEMORY_BYTES / 128 / r) return undefined
  if (salt.byteLength !== SALT_BYTES || hash.byteLength < 16 || hash.byteLength > 128) return undefined
  return { params: { N, r, p, keyLength: hash.byteLength }, salt, hash }
}

/**
 * Hash a password for storage.
 * @param password - the plaintext password.
 * @param params - overrides for the default work parameters.
 * @returns the encoded hash.
 */
export async function hashPassword(
  password: string,
  params: Partial<ScryptParams> = {},
): Promise<string> {
  const resolved: ScryptParams = { ...DEFAULT_SCRYPT_PARAMS, ...params }
  const salt = randomBytes(SALT_BYTES)
  const derived = await derive(password, salt, resolved)
  return [
    PREFIX,
    String(resolved.N),
    String(resolved.r),
    String(resolved.p),
    salt.toString('base64url'),
    derived.toString('base64url'),
  ].join('$')
}

/**
 * Verify a password against a stored hash in constant time.
 * @param password - the submitted password.
 * @param encoded - the stored hash.
 * @returns true only when the derived key matches.
 */
export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const parsed = parsePasswordHash(encoded)
  if (parsed === undefined) return false
  const derived = await derive(password, parsed.salt, parsed.params)
  if (derived.byteLength !== parsed.hash.byteLength) return false
  return timingSafeEqual(derived, parsed.hash)
}

/**
 * Spend one password derivation for a username that does not exist, so a
 * failed lookup and a wrong password take comparable time.
 * @param password - the submitted password.
 */
export async function dummyPasswordVerify(password: string): Promise<void> {
  await derive(password, Buffer.alloc(SALT_BYTES), DEFAULT_SCRYPT_PARAMS)
}
