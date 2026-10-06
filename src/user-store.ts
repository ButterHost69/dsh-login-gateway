/**
 * The login user directory: users declared in configuration plus users created
 * through first-run setup, which are stored as credential records so they
 * survive a restart.
 *
 * The two sources merge with configuration first, so a declarative deployment
 * keeps working and a name it declares always wins over a stored record with
 * the same name.
 *
 * @module dsh-login-gateway/user-store
 */

import { decodeBase32 } from './base32.ts'
import { parsePasswordHash } from './password.ts'
import type { CredentialKey, CredentialRecord, CredentialsProvider } from './types.ts'

/** One login account, whatever source it came from. */
export interface LoginUser {
  /** Login name, matched exactly and case-sensitively. */
  readonly username: string
  /** Encoded scrypt hash. */
  readonly passwordHash: string
  /** Base32 TOTP shared secret. */
  readonly totpSecret: string
}

/** Where the gateway reads users from and where first-run setup writes one. */
export interface UserDirectory {
  /**
   * Whether no user exists in any source, which puts the gateway in setup mode.
   * @returns true when there is nobody who could sign in.
   */
  isEmpty(): Promise<boolean>
  /**
   * Find one user by exact username.
   * @param username - the submitted login name.
   * @returns the user, or undefined when no source has that name.
   */
  find(username: string): Promise<LoginUser | undefined>
  /**
   * Store a user created through first-run setup.
   * @param user - the validated account to persist.
   * @throws when the name is taken, the store is unavailable, or it refuses the write.
   */
  create(user: LoginUser): Promise<void>
}

/** Scope segment of every credential record this plugin owns. */
export const CREDENTIAL_SCOPE = 'login-gateway'

/**
 * Usernames created through setup must be usable as a credential-record id,
 * which the seam restricts to a lowercase hyphenated identifier. Declaring the
 * same grammar here also keeps names free of whitespace and confusables.
 */
const USERNAME_PATTERN = /^[a-z][a-z0-9-]{1,31}$/u

const PAYLOAD_VERSION = 1
const MIN_TOTP_SECRET_BYTES = 10

/** Stored grant payload, written and read only by this plugin. */
interface StoredUserPayload {
  readonly version: typeof PAYLOAD_VERSION
  readonly username: string
  readonly passwordHash: string
  readonly totpSecret: string
}

/**
 * Whether a username may be created through setup.
 * @param username - the candidate name.
 * @returns true when it matches the credential-id grammar.
 */
export function isCreatableUsername(username: string): boolean {
  return USERNAME_PATTERN.test(username)
}

/** Build the credential address for one user id. */
function userKey(id: string): CredentialKey {
  return `${CREDENTIAL_SCOPE}/${id}` as CredentialKey
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Validate one stored payload, or undefined when it is not a user this plugin wrote. */
function parseStoredUser(id: string, record: CredentialRecord): LoginUser | undefined {
  if (record.kind !== 'grant' || !isRecord(record.payload)) return undefined
  const payload = record.payload
  if (payload['version'] !== PAYLOAD_VERSION) return undefined
  const username = payload['username']
  const passwordHash = payload['passwordHash']
  const totpSecret = payload['totpSecret']
  if (typeof username !== 'string' || typeof passwordHash !== 'string' || typeof totpSecret !== 'string') {
    return undefined
  }
  if (username !== id) return undefined
  if (parsePasswordHash(passwordHash) === undefined) return undefined
  const secret = decodeBase32(totpSecret)
  if (secret === undefined || secret.byteLength < MIN_TOTP_SECRET_BYTES) return undefined
  return { username, passwordHash, totpSecret }
}

function storedPayload(user: LoginUser): StoredUserPayload {
  return {
    version: PAYLOAD_VERSION,
    username: user.username,
    passwordHash: user.passwordHash,
    totpSecret: user.totpSecret,
  }
}

/**
 * Build the directory over the configured users and an optional credential
 * store.
 * @param configUsers - users declared in plugin configuration.
 * @param credentials - the credential store, when the profile mounts one.
 * @param onWarning - sink for a stored record this plugin cannot read.
 * @returns the directory.
 */
export function createUserDirectory(
  configUsers: readonly LoginUser[],
  credentials: CredentialsProvider | undefined,
  onWarning: (message: string) => void = () => {},
): UserDirectory {
  const readStored = async (): Promise<readonly LoginUser[]> => {
    if (credentials === undefined) return []
    const entries = await credentials.listRecords()
    const users: LoginUser[] = []
    for (const entry of entries) {
      if (!entry.key.startsWith(`${CREDENTIAL_SCOPE}/`)) continue
      const record = await credentials.readRecord(entry.key)
      if (record === undefined) continue
      const id = entry.key.slice(CREDENTIAL_SCOPE.length + 1)
      const user = parseStoredUser(id, record)
      if (user === undefined) {
        onWarning(
          `dsh-login-gateway: ignoring credential record ${JSON.stringify(entry.key)}; `
          + 'it is not a login-gateway user record',
        )
        continue
      }
      users.push(user)
    }
    return users
  }

  const findConfig = (username: string): LoginUser | undefined =>
    configUsers.find(user => user.username === username)

  return {
    async isEmpty(): Promise<boolean> {
      if (configUsers.length > 0) return false
      return (await readStored()).length === 0
    },
    async find(username: string): Promise<LoginUser | undefined> {
      const configured = findConfig(username)
      if (configured !== undefined) return configured
      return (await readStored()).find(user => user.username === username)
    },
    async create(user: LoginUser): Promise<void> {
      if (!isCreatableUsername(user.username)) {
        throw new Error(
          'username must be 2-32 characters of lowercase letters, digits, and hyphens, starting with a letter',
        )
      }
      if (credentials === undefined) {
        throw new Error(
          'this profile has no credential store, so the account cannot be saved; declare it under config.users instead',
        )
      }
      if (findConfig(user.username) !== undefined) {
        throw new Error(`username ${JSON.stringify(user.username)} is already declared in configuration`)
      }
      const key = userKey(user.username)
      const existing = await credentials.readRecord(key)
      if (existing !== undefined) throw new Error(`username ${JSON.stringify(user.username)} already exists`)
      const written = await credentials.modifyRecord(key, (current) => {
        if (current !== undefined) return Promise.resolve(undefined)
        return Promise.resolve({ kind: 'grant', payload: storedPayload(user) })
      })
      if (written === undefined) throw new Error('the credential store refused the write')
      const stored = parseStoredUser(user.username, written)
      if (stored === undefined || stored.passwordHash !== user.passwordHash) {
        throw new Error(`username ${JSON.stringify(user.username)} already exists`)
      }
    },
  }
}
