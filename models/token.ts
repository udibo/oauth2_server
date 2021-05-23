import { v4 } from "../deps/std/uuid/mod.ts";
import { ScopeInterface } from "./scope.ts";
import { ServerError } from "../errors.ts";
import type { Client } from "./client.ts";
import type { User } from "./user.ts";

export interface AccessToken {
  /** The access token. */
  accessToken: string;
  /** The expiration time for the access token. */
  accessTokenExpiresAt?: Date;
  /** The client associated with the token. */
  client: Client;
  /** The user associated with the token. */
  user: User;
  /** The scope granted to the token. */
  scope?: ScopeInterface;
  /** The authorization code used to issue the token. */
  code?: string;
}

export interface Token extends AccessToken {
  /** The refresh token. */
  refreshToken?: string;
  /** The expiration time for the refresh token. */
  refreshTokenExpiresAt?: Date;
}

export interface RefreshToken extends Token {
  /** The refresh token. */
  refreshToken: string;
}

export interface TokenServiceInterface {
  /** Lifetime of access tokens in seconds. */
  accessTokenLifetime: number;
  /** Lifetime of refresh tokens in seconds. */
  refreshTokenLifetime: number;
  /** Generates an access token. */
  generateAccessToken(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<string>;
  /** Generates a refresh token. */
  generateRefreshToken(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<string>;
  /** Gets the date that a new access token would expire at. */
  accessTokenExpiresAt(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Date>;
  /** Gets the date that a new refresh token would expire at. */
  refreshTokenExpiresAt(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Date>;
  /** Retrieves an existing token. */
  getAccessToken(accessToken: string): Promise<AccessToken | void>;
  /** Retrieves an existing token. */
  getRefreshToken(refreshToken: string): Promise<RefreshToken | void>;
  /** Saves a token. */
  save<T extends AccessToken>(token: T): Promise<T>;
  /** Revokes a token. */
  revoke(token: Token): Promise<boolean>;
  /** Revokes all tokens for an authorization code. */
  revokeCode(code: string): Promise<boolean>;
}

export abstract class AccessTokenService implements TokenServiceInterface {
  /** Lifetime of access tokens in seconds. Defaults to 1 hour. */
  accessTokenLifetime = 60 * 60;
  /** Lifetime of access tokens in seconds. Defaults to 0. */
  refreshTokenLifetime = 0;

  /** Generates an access token. Defaults to an RFC4122 v4 UUID (pseudo-randomly-based). */
  generateAccessToken(
    _client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<string> {
    return Promise.resolve(v4.generate());
  }

  /** Generates a refresh token. Not implemented by default. */
  generateRefreshToken(
    _client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<string> {
    return Promise.reject(
      new ServerError("generateRefreshToken not implemented"),
    );
  }

  /** Gets the date that a new access token would expire at. */
  accessTokenExpiresAt(
    client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<Date> {
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
    _scope?: ScopeInterface,
  ): Promise<Date> {
    return Promise.reject(
      new ServerError("refreshTokenExpiresAt not implemented"),
    );
  }

  /** Retrieves an existing token. */
  abstract getAccessToken(accessToken: string): Promise<AccessToken | void>;

  /** Retrieves an existing refresh token. Not implemented by default. */
  getRefreshToken(_refreshToken: string): Promise<RefreshToken | void> {
    return Promise.reject(new ServerError("getRefreshToken not implemented"));
  }

  /** Saves a token. */
  abstract save<T extends Token>(token: T): Promise<T>;

  /** Revokes a token. */
  abstract revoke(token: Token): Promise<boolean>;

  /** Revokes all tokens generated from an authorization code. */
  abstract revokeCode(code: string): Promise<boolean>;
}

export abstract class RefreshTokenService extends AccessTokenService
  implements TokenServiceInterface {
  /** Lifetime of refresh token in seconds. Defaults to 2 weeks. */
  refreshTokenLifetime = 14 * 24 * 60 * 60;

  /** Generates a refresh token.  Defaults to an RFC4122 v4 UUID (pseudo-randomly-based). */
  generateRefreshToken(
    _client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<string> {
    return Promise.resolve(v4.generate());
  }

  /** Gets the date that a new refresh token would expire at. */
  refreshTokenExpiresAt(
    client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<Date> {
    const lifetime: number = client.refreshTokenLifetime ??
      this.refreshTokenLifetime;
    return Promise.resolve(
      new Date(Date.now() + lifetime * 1000),
    );
  }

  /** Retrieves an existing refresh token. */
  abstract getRefreshToken(refreshToken: string): Promise<RefreshToken | void>;
}
