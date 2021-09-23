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
  accessTokenExpiresAt?: Date;
  /** The client associated with the token. */
  client: Client;
  /** The user associated with the token. */
  user: User;
  /** The scope granted to the token. */
  scope?: Scope;
  /** The authorization code used to issue the token. */
  code?: string;
}

export interface Token<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends AccessToken<Client, User, Scope> {
  /** The refresh token. */
  refreshToken?: string;
  /** The expiration time for the refresh token. */
  refreshTokenExpiresAt?: Date;
}

export interface RefreshToken<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends Token<Client, User, Scope> {
  /** The refresh token. */
  refreshToken: string;
}
