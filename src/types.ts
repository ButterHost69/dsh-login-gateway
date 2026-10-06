/**
 * The narrow Host contracts this plugin consumes.
 *
 * The authoritative types live in `@deepseek-ai/dsh-host-webserver` and
 * `@deepseek-ai/dsh-client-connection`, which this plugin reaches only for the
 * Context merges. Declaring the slices locally keeps the plugin's compile
 * surface independent of a published type version while the running
 * installation still supplies the services.
 *
 * @module dsh-login-gateway/types
 */

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

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** HTTP route registry provided by the Host web server. */
    webServer: WebServerService
    /** Host Connection transport provided by the Web composition. */
    connection: ConnectionService
  }
}
