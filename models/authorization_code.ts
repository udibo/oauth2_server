import { v4 } from "../deps/std/uuid/mod.ts";
import { ScopeInterface } from "./scope.ts";
import type { Client } from "./client.ts";
import type { User } from "./user.ts";

//  return Promise.resolve(v4.generate());

export interface AuthorizationCode {
  /** The authorization code. */
  code: string;
  /** The expiration time for the authorization code. */
  expiresAt: Date;
  /** Redirect URI for the authorization code. */
  redirectUri: string;
  /** The client associated with the authorization code. */
  client: Client;
  /** The user associated with the authorization code. */
  user: User;
  /** The scope granted to the authorization code. */
  scope?: ScopeInterface;
  /** The code challenge used for PKCE. */
  codeChallenge?: string;
  /** The code challenge method used for PKCE. */
  codeChallengeMethod?: string;
}

export interface AuthorizationCodeServiceInterface {
  /** Lifetime of authorization codes in second. */
  lifetime: number;
  /** Generates an authorization code. */
  generateCode(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<string>;
  /** Gets the date that a new authorization code would expire at. */
  expiresAt(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Date>;
  /** Retrieves an existing authorization code. */
  get(code: string): Promise<AuthorizationCode | void>;
  /** Saves an authorization code. */
  save(authorizationCode: AuthorizationCode): Promise<AuthorizationCode>;
  /** Revokes an authorization code. */
  revoke(authorizationCode: AuthorizationCode): Promise<boolean>;
}

export abstract class AuthorizationCodeService
  implements AuthorizationCodeServiceInterface {
  /** Lifetime of authorization codes in second. Defaults to 5 minutes. */
  lifetime = 5 * 60;
  /** Generates an authorization code. */
  generateCode(
    _client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<string> {
    return Promise.resolve(v4.generate());
  }
  /** Gets the date that a new authorization code would expire at. */
  expiresAt(
    _client: Client,
    _user: User,
    _scope?: ScopeInterface,
  ): Promise<Date> {
    return Promise.resolve(
      new Date(Date.now() + this.lifetime * 1000),
    );
  }
  /** Retrieves an existing authorization code. */
  abstract get(code: string): Promise<AuthorizationCode | undefined>;
  /** Saves an authorization code. */
  abstract save(
    authorizationCode: AuthorizationCode,
  ): Promise<AuthorizationCode>;
  /** Revokes an authorization code. */
  abstract revoke(authorizationCode: AuthorizationCode): Promise<boolean>;
}
