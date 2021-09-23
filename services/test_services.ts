import { AuthorizationCode } from "../models/authorization_code.ts";
import { AbstractAuthorizationCodeService } from "./authorization_code.ts";
import { Client } from "../models/client.ts";
import { AbstractClientService } from "./client.ts";
import { Scope } from "../models/scope.ts";
import { AccessToken, RefreshToken, Token } from "../models/token.ts";
import {
  AbstractAccessTokenService,
  AbstractRefreshTokenService,
} from "./token.ts";
import { AbstractUserService } from "./user.ts";
import { User } from "../models/user.ts";

export const client: Client = {
  id: "1",
  grants: ["refresh_token", "authorization_code"],
  redirectUris: [
    "https://client.example.com/cb",
    "https://client2.example.com/cb",
  ],
};
export const user: User = { username: "kyle" };
export const scope: Scope = new Scope("read write");

export class AccessTokenService
  extends AbstractAccessTokenService<Client, User, Scope> {
  client: Client;

  constructor(options?: { client: Client }) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing token by access token. */
  getToken(
    accessToken: string,
  ): Promise<AccessToken<Client, User, Scope> | undefined> {
    return Promise.resolve({
      accessToken,
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Saves a token. */
  save(token: Token<Client, User, Scope>): Promise<Token<Client, User, Scope>> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token<Client, User, Scope>): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

export class RefreshTokenService
  extends AbstractRefreshTokenService<Client, User, Scope> {
  client: Client;

  constructor(options?: { client: Client }) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing token by access token. */
  getToken(
    accessToken: string,
  ): Promise<Token<Client, User, Scope> | undefined> {
    return Promise.resolve({
      accessToken,
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Retrieves an existing token by refresh token. */
  getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Client, User, Scope> | undefined> {
    return Promise.resolve({
      accessToken: "fake",
      refreshToken,
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Saves a token. */
  save(token: Token<Client, User, Scope>): Promise<Token<Client, User, Scope>> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token<Client, User, Scope>): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

export class ClientService extends AbstractClientService<Client, User> {
  client: Client;

  constructor(options?: { client: Client }) {
    super();
    this.client = { ...client, ...options?.client };
  }

  get(_clientId: string): Promise<Client | undefined> {
    return Promise.resolve({ ...this.client });
  }

  getAuthenticated(
    _clientId: string,
    _clientSecret?: string,
  ): Promise<Client | undefined> {
    return Promise.resolve({ ...this.client });
  }
}

export class AuthorizationCodeService
  extends AbstractAuthorizationCodeService<Client, User, Scope> {
  client: Client;

  constructor(options?: { client: Client }) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing authorization code. */
  get(
    code: string,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined> {
    return Promise.resolve({
      code,
      expiresAt: new Date(Date.now() + 60000),
      redirectUri: "https://client.example.com/cb",
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Saves an authorization code. */
  save(
    authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<AuthorizationCode<Client, User, Scope>> {
    return Promise.resolve(authorizationCode);
  }

  /** Revokes an authorization code. */
  revoke(
    _authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<boolean> {
    return Promise.resolve(true);
  }
}

export class UserService extends AbstractUserService<User> {}
