import { Client } from "../models/client.ts";
import type { Token, TokenServiceInterface } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Scope, ScopeInterface } from "../models/scope.ts";
import type { User } from "../models/user.ts";

export interface GrantServices {
  tokenService: TokenServiceInterface;
}

export interface GrantOptions {
  services: GrantServices;
  /** Allow optional refresh token. */
  allowRefreshToken?: boolean;
}

export interface GrantInterface {
  services: GrantServices;
  allowRefreshToken: boolean;
  parseScope(scopeText?: string | null): ScopeInterface | undefined;
  generateToken(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Token>;
  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

export abstract class Grant implements GrantInterface {
  services: GrantServices;
  /** Allow optional refresh token. Defaults to false. */
  allowRefreshToken: boolean;

  constructor(options: GrantOptions) {
    this.services = { ...options.services };
    this.allowRefreshToken = options?.allowRefreshToken ?? false;
  }

  parseScope(scopeText?: string | null): ScopeInterface | undefined {
    return scopeText ? new Scope(scopeText) : undefined;
  }

  async generateToken(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Token> {
    const { tokenService }: GrantServices = this.services;
    const token: Token = {
      accessToken: await tokenService.generateAccessToken(client, user, scope),
      client,
      user,
      scope,
    };
    const accessTokenExpiresAt = await tokenService.accessTokenExpiresAt(
      client,
      user,
      scope,
    );
    if (accessTokenExpiresAt) token.accessTokenExpiresAt = accessTokenExpiresAt;
    if (this.allowRefreshToken) {
      const refreshToken = await tokenService.generateRefreshToken(
        client,
        user,
        scope,
      );
      if (refreshToken) {
        token.refreshToken = refreshToken;
        const refreshTokenExpiresAt = await tokenService.refreshTokenExpiresAt(
          client,
          user,
          scope,
        );
        if (refreshTokenExpiresAt) {
          token.refreshTokenExpiresAt = refreshTokenExpiresAt;
        }
      }
    }
    return token;
  }

  abstract handle(request: OAuth2Request, client: Client): Promise<Token>;
}
