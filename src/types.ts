/**
 * The narrow Host contracts this plugin consumes.
 *
 * The authoritative types live in `@deepseek-ai/dsh-host-webserver`,
 * `@deepseek-ai/dsh-client-connection`, and `@deepseek-ai/dsh-credentials`.
 * Declaring the slices locally keeps the plugin's compile surface independent
 * of a published type version while the running installation still supplies
 * the services.
 *
 * The contracts are read through {@link hostServices} rather than a
 * `declare module '@deepseek-ai/cordis'` augmentation: augmenting the package
 * root declares a local `Context` there, which shadows the re-exported
 * interface instead of merging with it, so members declared by cordis's own
 * submodules (`ctx.effect`, `ctx.get`) disappear for this file's importers.
 *
 * @module dsh-login-gateway/types
 */

import type { Context } from '@deepseek-ai/cordis'

/** The web-server facts the gateway needs to find its upstream. */
export interface WebServerService {
  /** Configured bind host. */
  readonly host: '127.0.0.1' | '0.0.0.0'
  /** Listening port, including the port the OS assigned for a configured 0. */
  readonly port: number
}

/** The Connection member that mints this process's launch URL. */
export interface ConnectionService {
  /**
   * Add the fresh process launch token to an application URL.
   * @param baseUrl - clean browser URL.
   * @returns the same URL carrying the process token.
   */
  authenticatedUrl(baseUrl: string): string
}

/**
 * Opaque `<scope>/<id>` address of one stored credential record. The
 * credentials seam owns this brand; this plugin only produces well-formed keys
 * for its own scope.
 */
export type CredentialKey = string & { readonly __credentialKeyBrand: 'CredentialKey' }

/**
 * One durable credential record. This plugin stores only `grant` records,
 * whose payload is written and read exclusively by its owner.
 */
export interface CredentialRecord {
  /** Discriminant. */
  readonly kind: 'grant'
  /** Owner-defined JSON value, opaque to the seam. */
  readonly payload: unknown
}

/** Address and discriminant of one stored record, values excluded. */
export interface CredentialRecordEntry {
  /** The record's address. */
  readonly key: CredentialKey
  /** Discriminant of the stored record. */
  readonly kind: CredentialRecord['kind']
}

/**
 * The credential-store slice this plugin consumes: enumerate its own records,
 * read one, and take the serialized read-modify-write path to create one.
 */
export interface CredentialsProvider {
  /**
   * Read one stored record.
   * @param key - the record to read.
   * @returns the record, or undefined while none is stored.
   */
  readRecord(key: CredentialKey): Promise<CredentialRecord | undefined>
  /**
   * Enumerate every stored record's address and tag.
   * @returns every stored record, values excluded.
   */
  listRecords(): Promise<readonly CredentialRecordEntry[]>
  /**
   * Serialized read-modify-write over one record.
   * @param key - the record to modify.
   * @param mutate - receives the current record and returns its replacement, or undefined to leave it.
   * @returns the record after the write, or the current one when `mutate` declined.
   */
  modifyRecord(
    key: CredentialKey,
    mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>,
  ): Promise<CredentialRecord | undefined>
}

/** The Host services this plugin reads from the running composition. */
export interface LoginGatewayHost {
  /** The browser HTTP carrier. */
  readonly webServer: WebServerService
  /** The Host Connection transport. */
  readonly connection: ConnectionService
  /** Durable credential records, which first-run setup writes to. */
  readonly credentials: CredentialsProvider
}

/**
 * Read the Host services from a plugin context. Cordis only exposes a service
 * the plugin declared in `inject`, so every member here is one this plugin
 * requires.
 * @param ctx - the plugin context.
 * @returns the services this plugin consumes.
 */
export function hostServices(ctx: Context): LoginGatewayHost {
  return ctx as Context & LoginGatewayHost
}
