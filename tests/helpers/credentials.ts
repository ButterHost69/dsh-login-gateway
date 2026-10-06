/**
 * An in-memory stand-in for the credential store, so the user directory and
 * first-run setup can be exercised without a harness home on disk.
 */

import type {
  CredentialKey,
  CredentialRecord,
  CredentialRecordEntry,
  CredentialsProvider,
} from '../../src/types.ts'

/** A fake store plus the raw map, for seeding and assertions. */
export interface FakeCredentials extends CredentialsProvider {
  /** Raw records, keyed by their `<scope>/<id>` address. */
  readonly records: Map<string, CredentialRecord>
}

/**
 * Create an empty in-memory credential store.
 * @returns the store.
 */
export function createFakeCredentials(): FakeCredentials {
  const records = new Map<string, CredentialRecord>()
  return {
    records,
    async readRecord(key: CredentialKey): Promise<CredentialRecord | undefined> {
      return records.get(key)
    },
    async listRecords(): Promise<readonly CredentialRecordEntry[]> {
      return [...records.keys()].map(key => ({ key: key as CredentialKey, kind: 'grant' as const }))
    },
    async modifyRecord(
      key: CredentialKey,
      mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>,
    ): Promise<CredentialRecord | undefined> {
      const next = await mutate(records.get(key))
      if (next !== undefined) records.set(key, next)
      return records.get(key)
    },
  }
}
