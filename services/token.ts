import { ScopeInterface } from "../models/scope.ts";
import { ServerError } from "../errors.ts";
import { User } from "../models/user.ts";
import { AccessToken, RefreshToken, Token } from "../models/token.ts";
import { Client } from "../models/client.ts";

export interface TokenServiceInterface<Scope extends ScopeInterface> {
  /** Lifetime of access tokens in seconds. */
  accessTokenLifetime: number;
  /** Lifetime of refresh tokens in seconds. */
  refreshTokenLifetime: number;
  /** Validates scope for a client and user. */
  acceptedScope(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Scope | undefined | false>;
  /** Generates an access token. */
  generateAccessToken(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<string>;
  /** Generates a refresh token. */
  generateRefreshToken(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<string | undefined>;
  /** Gets the date that a new access token would expire at. */
  accessTokenExpiresAt(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Date | undefined>;
  /** Gets the date that a new refresh token would expire at. */
  refreshTokenExpiresAt(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Date | undefined>;
  /** Retrieves an existing token by access token. */
  getToken(accessToken: string): Promise<Token<Scope> | undefined>;
  /** Retrieves an existing token by refresh token. */
  getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Scope> | undefined>;
  /** Saves a token. */
  save(token: Token<Scope>): Promise<Token<Scope>>;
  /** Revokes a token. Resolves true if a token was revoked. */
  revoke(token: Token<Scope>): Promise<boolean>;
  /** Revokes all tokens for an authorization code. Resolves true if a token was revoked. */
  revokeCode(code: string): Promise<boolean>;
}

export abstract class AbstractAccessTokenService<Scope extends ScopeInterface>
  implements TokenServiceInterface<Scope> {
  /** Lifetime of access tokens in seconds. Defaults to 1 hour. */
  accessTokenLifetime = 60 * 60;
  /** Lifetime of refresh tokens in seconds. Defaults to 0. */
  refreshTokenLifetime = 0;

  /** Returns the accepted scope for the client and user. */
  acceptedScope(
    _client: Client,
    _user: User,
    scope?: Scope,
  ): Promise<Scope | undefined | false> {
    return Promise.resolve(scope);
  }

  /** Generates an access token. Defaults to an RFC4122 v4 UUID (pseudo-randomly-based). */
  generateAccessToken(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Generates a refresh token. Not implemented by default. */
  generateRefreshToken(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<string | undefined> {
    return Promise.reject(
      new ServerError("generateRefreshToken not implemented"),
    );
  }

  /** Gets the date that a new access token would expire at. */
  accessTokenExpiresAt(
    client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<Date | undefined> {
    const lifetime: number = client.accessTokenLifetime ??
      this.accessTokenLifetime;
    return Promise.resolve(
      new Date(Date.now() + lifetime * 1000),
    );
  }

  /** Gets the date that a new refresh token would expire at. Not implemented by default. */
  refreshTokenExpiresAt(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<Date | undefined> {
    return Promise.reject(
      new ServerError("refreshTokenExpiresAt not implemented"),
    );
  }

  /** Retrieves an existing access token. */
  abstract getToken(
    accessToken: string,
  ): Promise<AccessToken<Scope> | undefined>;

  /** Retrieves an existing refresh token. Not implemented by default. */
  getRefreshToken(
    _refreshToken: string,
  ): Promise<RefreshToken<Scope> | undefined> {
    return Promise.reject(new ServerError("getRefreshToken not implemented"));
  }

  /** Saves a token. */
  abstract save(token: AccessToken<Scope>): Promise<AccessToken<Scope>>;

  /** Revokes a token. Resolves true if a token was revoked. */
  abstract revoke(token: AccessToken<Scope>): Promise<boolean>;

  /** Revokes all tokens for an authorization code. Resolves true if a token was revoked. */
  abstract revokeCode(code: string): Promise<boolean>;
}

export abstract class AbstractRefreshTokenService<Scope extends ScopeInterface>
  extends AbstractAccessTokenService<Scope>
  implements TokenServiceInterface<Scope> {
  /** Lifetime of refresh token in seconds. Defaults to 2 weeks. */
  refreshTokenLifetime = 14 * 24 * 60 * 60;

  /** Generates a refresh token.  Defaults to an RFC4122 v4 UUID (pseudo-randomly-based). */
  generateRefreshToken(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<string | undefined> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Gets the date that a new refresh token would expire at. */
  refreshTokenExpiresAt(
    client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<Date | undefined> {
    const lifetime: number = client.refreshTokenLifetime ??
      this.refreshTokenLifetime;
    return Promise.resolve(
      new Date(Date.now() + lifetime * 1000),
    );
  }

  /** Retrieves an existing token. */
  abstract getToken(
    accessToken: string,
  ): Promise<Token<Scope> | undefined>;

  /** Retrieves an existing refresh token. */
  abstract getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Scope> | undefined>;

  /** Saves a token. */
  abstract save(token: Token<Scope>): Promise<Token<Scope>>;

  /** Revokes a token. Resolves true if a token was revoked. */
  abstract revoke(token: Token<Scope> | string): Promise<boolean>;
}
