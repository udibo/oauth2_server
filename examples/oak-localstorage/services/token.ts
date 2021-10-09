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
  userId: string;
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

  private getTokenIndex(
    token:
      & Partial<Token<Client, User, Scope>>
      & Pick<Token<Client, User, Scope>, "accessToken">,
  ): string | null {
    const accessTokenKey = `accessToken:${token.accessToken}`;
    const refreshTokenKey = token.refreshToken
      ? `refreshToken:${token.refreshToken}`
      : undefined;
    return localStorage.getItem(accessTokenKey) ??
      (refreshTokenKey && localStorage.getItem(refreshTokenKey)) ??
      null;
  }

  async put(token: Token<Client, User, Scope>): Promise<void> {
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
    let tokenIndex = this.getTokenIndex(token);
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
    const next: TokenInternal = {
      accessToken,
      clientId: client.id,
      userId: user.id,
    };

    if (accessTokenExpiresAt) {
      next.accessTokenExpiresAt = accessTokenExpiresAt.toJSON();
    }
    if (refreshToken) next.refreshToken = refreshToken;
    if (refreshTokenExpiresAt) {
      next.refreshTokenExpiresAt = refreshTokenExpiresAt.toJSON();
    }
    if (scope) next.scope = scope.toJSON();
    if (code) next.code = code;

    localStorage.setItem(
      `token:${tokenIndex}`,
      JSON.stringify(next),
    );
    return await Promise.resolve();
  }

  async patch(
    token:
      & Partial<Token<Client, User, Scope>>
      & Pick<Token<Client, User, Scope>, "accessToken">,
  ): Promise<void> {
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
    const tokenIndex = this.getTokenIndex(token);
    const current = tokenIndex !== null &&
      await this.getTokenInternalByIndex(tokenIndex);
    if (!current) throw new Error("token not found");
    const next: TokenInternal = { ...current, accessToken };

    if (client) next.clientId = client.id;
    if (user) next.userId = user.id;

    if (accessTokenExpiresAt) {
      next.accessTokenExpiresAt = accessTokenExpiresAt.toJSON();
    } else if (accessTokenExpiresAt === null) {
      delete next.accessTokenExpiresAt;
    }

    if (refreshToken) next.refreshToken = refreshToken;
    else if (refreshToken === null) delete next.refreshToken;

    if (refreshTokenExpiresAt) {
      next.refreshTokenExpiresAt = refreshTokenExpiresAt.toJSON();
    } else if (refreshTokenExpiresAt === null) {
      delete next.refreshTokenExpiresAt;
    }

    if (scope) next.scope = scope.toJSON();
    else if (scope === null) delete next.scope;

    if (code) next.code = code;
    else if (code === null) delete next.code;

    localStorage.setItem(`token:${tokenIndex}`, JSON.stringify(next));
  }

  async deleteAccessToken(accessToken: string): Promise<boolean> {
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
    return await Promise.resolve(!!tokenIndex);
  }

  async deleteRefreshToken(refreshToken: string): Promise<boolean> {
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
    return await Promise.resolve(!!tokenIndex);
  }

  async delete(
    token: Token<Client, User, Scope> | TokenInternal,
  ): Promise<boolean> {
    let existed = await this.deleteAccessToken(token.accessToken);
    if (token.refreshToken) {
      existed = await this.deleteRefreshToken(token.refreshToken) || existed;
    }
    return existed;
  }

  private async getTokenInternalByIndex(
    tokenIndex: string,
  ): Promise<TokenInternal> {
    const internalText = localStorage.getItem(`token:${tokenIndex}`);
    return await Promise.resolve(
      internalText ? JSON.parse(internalText) : undefined,
    );
  }

  private async getTokenByIndex(
    tokenIndex: string,
  ): Promise<Token<Client, User, Scope> | undefined> {
    const internal = await this.getTokenInternalByIndex(tokenIndex);
    let token: Token<Client, User, Scope> | undefined = undefined;
    if (internal) {
      const {
        accessToken,
        accessTokenExpiresAt,
        refreshToken,
        refreshTokenExpiresAt,
        clientId,
        userId,
        scope,
        code,
      } = internal;
      const client = await this.clientService.get(clientId);
      const user = client && await this.userService.get(userId);
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
      existed = await this.delete(internal);
    }
    return existed;
  }
}
