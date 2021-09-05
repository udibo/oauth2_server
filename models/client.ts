export interface Client {
  /** A unique identifier. */
  id: string;
  /** Grant types allowed for the client. */
  grants: string[];
  /** Redirect URIs allowed for the client. Required for the `authorization_code` grant type. */
  redirectUris?: string[];
  /** Client specific lifetime of access tokens in seconds. */
  accessTokenLifetime?: number;
  /** Client specific lifetime of refresh tokens in seconds. */
  refreshTokenLifetime?: number;
}
