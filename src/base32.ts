/**
 * RFC 4648 base32 encoding and decoding for TOTP shared secrets.
 *
 * Authenticator apps display and accept secrets in base32, usually with
 * grouping spaces, and users paste them in either case. Decoding is therefore
 * deliberately forgiving about presentation and strict about the alphabet.
 *
 * @module dsh-login-gateway/base32
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

const VALUES: ReadonlyMap<string, number> = new Map(
  [...ALPHABET].map((character, index) => [character, index] as const),
)

/**
 * Decode a base32 secret. Case, spaces, and hyphens are ignored, and trailing
 * `=` padding is optional.
 * @param input - the encoded secret.
 * @returns the decoded bytes, or undefined when the input is not base32.
 */
export function decodeBase32(input: string): Uint8Array | undefined {
  const clean = input.replace(/[\s-]+/gu, '').replace(/=+$/u, '').toUpperCase()
  if (clean.length === 0) return undefined
  const bytes = new Uint8Array(Math.floor(clean.length * 5 / 8))
  let bits = 0
  let accumulator = 0
  let at = 0
  for (const character of clean) {
    const digit = VALUES.get(character)
    if (digit === undefined) return undefined
    accumulator = (accumulator << 5) | digit
    bits += 5
    if (bits < 8) continue
    bits -= 8
    bytes[at] = (accumulator >>> bits) & 0xff
    at += 1
  }
  return bytes
}

/**
 * Encode bytes as unpadded upper-case base32.
 * @param bytes - the value to encode.
 * @returns the base32 representation.
 */
export function encodeBase32(bytes: Uint8Array): string {
  let out = ''
  let bits = 0
  let accumulator = 0
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(accumulator >>> bits) & 0x1f]
    }
  }
  if (bits > 0) out += ALPHABET[(accumulator << (5 - bits)) & 0x1f]
  return out
}
