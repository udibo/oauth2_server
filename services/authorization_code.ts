import { ScopeInterface } from "../models/scope.ts";
import { Client } from "../models/client.ts";
import { User } from "../models/user.ts";
import { AuthorizationCode } from "../models/authorization_code.ts";

export interface AuthorizationCodeServiceInterface<
  Scope extends ScopeInterface,
> {
  /** Lifetime of authorization codes in second. */
  lifetime: number;
  /** Generates an authorization code. */
  generateCode(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<string>;
  /** Gets the date that a new authorization code would expire at. */
  expiresAt(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Date>;
  /** Retrieves an existing authorization code. */
  get(code: string): Promise<AuthorizationCode<Scope> | void>;
  /** Saves an authorization code. */
  save(
    authorizationCode: AuthorizationCode<Scope>,
  ): Promise<AuthorizationCode<Scope>>;
  /** Revokes an authorization code. */
  revoke(
    authorizationCode: AuthorizationCode<Scope> | string,
  ): Promise<boolean>;
}

export abstract class AbstractAuthorizationCodeService<
  Scope extends ScopeInterface,
> implements AuthorizationCodeServiceInterface<Scope> {
  /** Lifetime of authorization codes in second. Defaults to 5 minutes. */
  lifetime = 5 * 60;
  /** Generates an authorization code. */
  generateCode(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }
  /** Gets the date that a new authorization code would expire at. */
  expiresAt(
    _client: Client,
    _user: User,
    _scope?: Scope,
  ): Promise<Date> {
    return Promise.resolve(
      new Date(Date.now() + this.lifetime * 1000),
    );
  }
  /** Retrieves an existing authorization code. */
  abstract get(code: string): Promise<AuthorizationCode<Scope> | undefined>;
  /** Saves an authorization code. */
  abstract save(
    authorizationCode: AuthorizationCode<Scope>,
  ): Promise<AuthorizationCode<Scope>>;
  /** Revokes an authorization code. */
  abstract revoke(
    authorizationCode: AuthorizationCode<Scope> | string,
  ): Promise<boolean>;
}
