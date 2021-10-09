import type { ScopeInterface } from "./scope.ts";
import type { ClientInterface } from "./client.ts";

export interface AccessToken<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  /** The access token. */
  accessToken: string;
  /** The expiration time for the access token. */
  accessTokenExpiresAt?: Date | null;
  /** The client associated with the token. */
  client: Client;
  /** The user associated with the token. */
  user: User;
  /** The scope granted to the token. */
  scope?: Scope | null;
  /** The authorization code used to issue the token. */
  code?: string | null;
}

export interface Token<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends AccessToken<Client, User, Scope> {
  /** The refresh token. */
  refreshToken?: string | null;
  /** The expiration time for the refresh token. */
  refreshTokenExpiresAt?: Date | null;
}

export interface RefreshToken<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends Token<Client, User, Scope> {
  /** The refresh token. */
  refreshToken: string;
}
