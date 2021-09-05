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
import { User } from "../models/user.ts";
import { AbstractUserService } from "./user.ts";

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

export interface TokenServiceOptions {
  client: Client;
}

export class AccessTokenService extends AbstractAccessTokenService<Scope> {
  client: Client;

  constructor(options?: TokenServiceOptions) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing token by access token. */
  getToken(accessToken: string): Promise<AccessToken<Scope> | undefined> {
    return Promise.resolve({
      accessToken,
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Saves a token. */
  save(token: Token<Scope>): Promise<Token<Scope>> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token<Scope>): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

export class RefreshTokenService extends AbstractRefreshTokenService<Scope> {
  client: Client;

  constructor(options?: TokenServiceOptions) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing token by access token. */
  getToken(accessToken: string): Promise<Token<Scope> | undefined> {
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
  ): Promise<RefreshToken<Scope> | undefined> {
    return Promise.resolve({
      accessToken: "fake",
      refreshToken,
      client: { ...this.client },
      user,
      scope,
    });
  }

  /** Saves a token. */
  save(token: Token<Scope>): Promise<Token<Scope>> {
    return Promise.resolve(token);
  }

  /** Revokes a token. */
  revoke(_token: Token<Scope>): Promise<boolean> {
    return Promise.resolve(true);
  }

  /** Revokes all tokens generated from an authorization code. */
  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

interface ClientServiceOptions {
  client: Client;
}

export class ClientService extends AbstractClientService {
  client: Client;

  constructor(options?: ClientServiceOptions) {
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

export interface AuthorizationCodeServiceOptions {
  client: Client;
}

export class AuthorizationCodeService
  extends AbstractAuthorizationCodeService<Scope> {
  client: Client;

  constructor(options?: AuthorizationCodeServiceOptions) {
    super();
    this.client = { ...client, ...options?.client };
  }

  /** Retrieves an existing authorization code. */
  get(code: string): Promise<AuthorizationCode<Scope> | undefined> {
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
    authorizationCode: AuthorizationCode<Scope>,
  ): Promise<AuthorizationCode<Scope>> {
    return Promise.resolve(authorizationCode);
  }

  /** Revokes an authorization code. */
  revoke(_authorizationCode: AuthorizationCode<Scope>): Promise<boolean> {
    return Promise.resolve(true);
  }
}

export class UserService extends AbstractUserService {}
