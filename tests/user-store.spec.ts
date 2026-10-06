import { describe, expect, it } from 'vitest'
import { hashPassword } from '../src/password.ts'
import { generateTotpSecret } from '../src/totp.ts'
import { createUserDirectory, isCreatableUsername, type LoginUser } from '../src/user-store.ts'
import { createFakeCredentials } from './helpers/credentials.ts'

async function makeUser(username: string, password = 'a-long-enough-password'): Promise<LoginUser> {
  return {
    username,
    passwordHash: await hashPassword(password, { N: 1024, r: 8, p: 1 }),
    totpSecret: generateTotpSecret(),
  }
}

describe('isCreatableUsername', () => {
  it('accepts the credential-id grammar', () => {
    expect(isCreatableUsername('alice')).toBe(true)
    expect(isCreatableUsername('ops-1')).toBe(true)
    expect(isCreatableUsername('a1')).toBe(true)
  })

  it('rejects names outside it', () => {
    expect(isCreatableUsername('Alice')).toBe(false)
    expect(isCreatableUsername('a')).toBe(false)
    expect(isCreatableUsername('1alice')).toBe(false)
    expect(isCreatableUsername('-alice')).toBe(false)
    expect(isCreatableUsername('alice_bob')).toBe(false)
    expect(isCreatableUsername('alice@example.com')).toBe(false)
    expect(isCreatableUsername('a'.repeat(33))).toBe(false)
    expect(isCreatableUsername('alice bob')).toBe(false)
  })
})

describe('createUserDirectory', () => {
  it('is empty with no configured and no stored users', async () => {
    const directory = createUserDirectory([], createFakeCredentials())
    await expect(directory.isEmpty()).resolves.toBe(true)
  })

  it('is not empty when configuration declares a user', async () => {
    const directory = createUserDirectory([await makeUser('alice')], undefined)
    await expect(directory.isEmpty()).resolves.toBe(false)
    await expect(directory.find('alice')).resolves.toMatchObject({ username: 'alice' })
    await expect(directory.find('bob')).resolves.toBeUndefined()
  })

  it('stores and finds a created user', async () => {
    const credentials = createFakeCredentials()
    const directory = createUserDirectory([], credentials)
    const user = await makeUser('alice')
    await directory.create(user)
    expect(credentials.records.has('login-gateway/alice')).toBe(true)
    await expect(directory.isEmpty()).resolves.toBe(false)
    await expect(directory.find('alice')).resolves.toEqual(user)
  })

  it('survives a fresh directory over the same store', async () => {
    const credentials = createFakeCredentials()
    await createUserDirectory([], credentials).create(await makeUser('alice'))
    await expect(createUserDirectory([], credentials).find('alice')).resolves.toMatchObject({ username: 'alice' })
  })

  it('prefers a configured user over a stored one with the same name', async () => {
    const credentials = createFakeCredentials()
    const stored = await makeUser('alice', 'stored-password')
    await createUserDirectory([], credentials).create(stored)
    const configured = await makeUser('alice', 'configured-password')
    const directory = createUserDirectory([configured], credentials)
    await expect(directory.find('alice')).resolves.toEqual(configured)
  })

  it('refuses a name that configuration already declares', async () => {
    const directory = createUserDirectory([await makeUser('alice')], createFakeCredentials())
    await expect(directory.create(await makeUser('alice'))).rejects.toThrow(/declared in configuration/u)
  })

  it('refuses a name already stored', async () => {
    const credentials = createFakeCredentials()
    const directory = createUserDirectory([], credentials)
    await directory.create(await makeUser('alice'))
    await expect(directory.create(await makeUser('alice'))).rejects.toThrow(/already exists/u)
  })

  it('refuses an invalid username before touching the store', async () => {
    const credentials = createFakeCredentials()
    const directory = createUserDirectory([], credentials)
    await expect(directory.create(await makeUser('Alice'))).rejects.toThrow(/lowercase letters/u)
    expect(credentials.records.size).toBe(0)
  })

  it('explains that a profile without a credential store cannot save setup', async () => {
    const directory = createUserDirectory([], undefined)
    await expect(directory.create(await makeUser('alice'))).rejects.toThrow(/no credential store/u)
  })

  it('ignores records from another scope', async () => {
    const credentials = createFakeCredentials()
    credentials.records.set('other-plugin/thing', { kind: 'grant', payload: { version: 1 } })
    const directory = createUserDirectory([], credentials)
    await expect(directory.isEmpty()).resolves.toBe(true)
  })

  it('ignores and reports a malformed record in its own scope', async () => {
    const credentials = createFakeCredentials()
    credentials.records.set('login-gateway/alice', { kind: 'grant', payload: { version: 99 } })
    const warnings: string[] = []
    const directory = createUserDirectory([], credentials, message => warnings.push(message))
    await expect(directory.isEmpty()).resolves.toBe(true)
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('login-gateway/alice')
  })

  it('ignores a record whose payload names another user', async () => {
    const credentials = createFakeCredentials()
    const user = await makeUser('alice')
    credentials.records.set('login-gateway/alice', {
      kind: 'grant',
      payload: { version: 1, ...user, username: 'bob' },
    })
    await expect(createUserDirectory([], credentials).isEmpty()).resolves.toBe(true)
  })

  it('ignores a record with an unusable secret or hash', async () => {
    const credentials = createFakeCredentials()
    const user = await makeUser('alice')
    credentials.records.set('login-gateway/alice', {
      kind: 'grant',
      payload: { version: 1, ...user, totpSecret: 'ABC' },
    })
    await expect(createUserDirectory([], credentials).isEmpty()).resolves.toBe(true)
    credentials.records.set('login-gateway/alice', {
      kind: 'grant',
      payload: { version: 1, ...user, passwordHash: 'plain' },
    })
    await expect(createUserDirectory([], credentials).isEmpty()).resolves.toBe(true)
  })
})
