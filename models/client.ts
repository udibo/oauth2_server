export interface ClientInterface {
  /** A unique identifier. */
  id: string;
  /** Grant types allowed for the client. */
  grants?: string[] | null;
  /** Redirect URIs allowed for the client. Required for the `authorization_code` grant type. */
  redirectUris?: string[] | null;
  /** Client specific lifetime of access tokens in seconds. */
  accessTokenLifetime?: number | null;
  /** Client specific lifetime of refresh tokens in seconds. */
  refreshTokenLifetime?: number | null;
}

// deno-lint-ignore no-empty-interface
export interface Client extends ClientInterface {}
