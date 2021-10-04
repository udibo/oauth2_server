import {
  AbstractRefreshTokenService,
  RefreshToken,
  Scope,
  Token,
} from "../deps.ts";
import { Client } from "../models/client.ts";
import { User } from "../models/user.ts";
import { ClientService } from "./client.ts";
import { UserService } from "./user.ts";

interface TokenInternal {
  accessToken: string;
  accessTokenExpiresAt?: string;
  refreshToken?: string;
  refreshTokenExpiresAt?: string;
  clientId: string;
  username: string;
  scope?: string;
  code?: string;
}

export class TokenService
  extends AbstractRefreshTokenService<Client, User, Scope> {
  private clientService: ClientService;
  private userService: UserService;

  constructor(clientService: ClientService, userService: UserService) {
    super();
    this.clientService = clientService;
    this.userService = userService;
  }

  put(token: Token<Client, User, Scope>): Promise<void> {
    const {
      accessToken,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      client,
      user,
      scope,
      code,
    } = token;
    const accessTokenKey = `accessToken:${token.accessToken}`;
    const refreshTokenKey = token.refreshToken
      ? `refreshToken:${token.refreshToken}`
      : undefined;
    let tokenIndex = localStorage.getItem(accessTokenKey) ||
      (refreshTokenKey && localStorage.getItem(refreshTokenKey));
    if (!tokenIndex) {
      tokenIndex = localStorage.getItem("nextTokenIndex") ?? "0";
      localStorage.setItem("nextTokenIndex", `${parseInt(tokenIndex) + 1}`);
      localStorage.setItem(`accessToken:${token.accessToken}`, tokenIndex);
      if (token.refreshToken) {
        localStorage.setItem(`refreshToken:${token.refreshToken}`, tokenIndex);
      }
      if (token.code) {
        localStorage.setItem(`tokenCode:${token.code}`, tokenIndex);
      }
    }
    localStorage.setItem(
      `token:${tokenIndex}`,
      JSON.stringify({
        accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt?.toJSON(),
        refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt?.toJSON(),
        clientId: client.id,
        username: user.username,
        scope: scope?.toJSON(),
        code,
      } as TokenInternal),
    );
    return Promise.resolve();
  }

  deleteAccessToken(accessToken: string): Promise<boolean> {
    const accessTokenKey = `accessToken:${accessToken}`;
    const tokenIndex = localStorage.getItem(accessTokenKey);
    if (tokenIndex) {
      localStorage.removeItem(accessTokenKey);
      const tokenKey = `token:${tokenIndex}`;
      const internalText = localStorage.getItem(tokenKey);
      if (internalText) {
        const internal: TokenInternal = JSON.parse(internalText);
        if (!internal.refreshToken) {
          localStorage.removeItem(tokenKey);
          if (internal.code) {
            localStorage.removeItem(`tokenCode:${internal.code}`);
          }
        }
      }
    }
    return Promise.resolve(!!tokenIndex);
  }

  deleteRefreshToken(refreshToken: string): Promise<boolean> {
    const refreshTokenKey = `refreshToken:${refreshToken}`;
    const tokenIndex = localStorage.getItem(refreshTokenKey);
    if (tokenIndex) {
      localStorage.removeItem(refreshTokenKey);
      const tokenKey = `token:${tokenIndex}`;
      const internalText = localStorage.getItem(tokenKey);
      if (internalText) {
        const internal: TokenInternal = JSON.parse(internalText);
        if (localStorage.getItem(`accessToken:${internal.accessToken}`)) {
          delete internal.refreshToken;
          delete internal.refreshTokenExpiresAt;
          localStorage.setItem(tokenKey, JSON.stringify(internal));
        } else {
          localStorage.removeItem(tokenKey);
          if (internal.code) {
            localStorage.removeItem(`tokenCode:${internal.code}`);
          }
        }
      }
    }
    return Promise.resolve(!!tokenIndex);
  }

  private async deleteToken(
    token: Token<Client, User, Scope> | TokenInternal,
  ): Promise<boolean> {
    let existed = await this.deleteAccessToken(token.accessToken);
    if (token.refreshToken) {
      existed = await this.deleteRefreshToken(token.refreshToken) || existed;
    }
    return existed;
  }

  async delete(token: Token<Client, User, Scope>): Promise<boolean> {
    return await this.deleteToken(token);
  }

  private async getTokenByIndex(tokenIndex: string) {
    const internalText = localStorage.getItem(`token:${tokenIndex}`);
    const internal: TokenInternal | undefined = internalText
      ? JSON.parse(internalText)
      : undefined;
    let token: Token<Client, User, Scope> | undefined = undefined;
    if (internal) {
      const {
        accessToken,
        accessTokenExpiresAt,
        refreshToken,
        refreshTokenExpiresAt,
        clientId,
        username,
        scope,
        code,
      } = internal;
      const client = await this.clientService.get(clientId);
      const user = client && await this.userService.get(username);
      if (client && user) {
        token = {
          accessToken,
          refreshToken,
          client,
          user,
          code,
        };
        if (accessTokenExpiresAt) {
          token.accessTokenExpiresAt = new Date(accessTokenExpiresAt);
        }
        if (refreshTokenExpiresAt) {
          token.refreshTokenExpiresAt = new Date(refreshTokenExpiresAt);
        }
        if (scope) token.scope = Scope.from(scope);
      }
    }
    return token;
  }

  async getToken(
    accessToken: string,
  ): Promise<Token<Client, User, Scope> | undefined> {
    const tokenIndex = localStorage.getItem(`accessToken:${accessToken}`);
    return tokenIndex ? await this.getTokenByIndex(tokenIndex) : undefined;
  }

  async getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Client, User, Scope> | undefined> {
    const tokenIndex = localStorage.getItem(`refreshToken:${refreshToken}`);
    return tokenIndex
      ? (await this.getTokenByIndex(tokenIndex)) as RefreshToken<
        Client,
        User,
        Scope
      >
      : undefined;
  }

  async save(
    token: Token<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope>> {
    await this.put(token);
    return (await this.getToken(token.accessToken))!;
  }

  async revoke(token: Token<Client, User, Scope>): Promise<boolean> {
    return await this.delete(token);
  }

  async revokeCode(code: string): Promise<boolean> {
    let existed = false;
    const tokenIndex = localStorage.getItem(`tokenCode:${code}`);
    const internalText = tokenIndex &&
      localStorage.getItem(`token:${tokenIndex}`);
    if (internalText) {
      const internal: TokenInternal = JSON.parse(internalText);
      existed = await this.deleteToken(internal);
    }
    return existed;
  }
}
