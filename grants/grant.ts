import { Client, ClientServiceInterface } from "../models/client.ts";
import type { Token, TokenServiceInterface } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Scope, ScopeInterface } from "../models/scope.ts";
import type { User } from "../models/user.ts";
import { InvalidClient } from "../errors.ts";
import { BasicAuth, parseBasicAuth } from "../basic_auth.ts";

export interface GrantServices {
  clientService: ClientServiceInterface;
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
  getClientCredentials(request: OAuth2Request): Promise<ClientCredentials>;
  getAuthenticatedClient(request: OAuth2Request): Promise<Client>;
  generateToken(
    client: Client,
    user: User,
    scope?: ScopeInterface,
  ): Promise<Token>;
  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

export interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
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

  async getClientCredentials(
    request: OAuth2Request,
  ): Promise<ClientCredentials> {
    let clientId: string | null = null;
    let clientSecret: string | null = null;
    try {
      const authorization: BasicAuth = parseBasicAuth(
        request.headers.get("authorization"),
      );
      clientId = authorization.name;
      clientSecret = authorization.pass;
    } catch (error) {
      if (!request.headers.has("authorization") && request.hasBody) {
        const body: URLSearchParams = await request.body!;
        clientId = body.get("client_id");
        clientSecret = body.get("client_secret");
      }
      if (!clientId) {
        throw error;
      }
    }
    const clientCredentials: ClientCredentials = { clientId };
    if (clientSecret) clientCredentials.clientSecret = clientSecret;
    return clientCredentials;
  }

  async getAuthenticatedClient(request: OAuth2Request): Promise<Client> {
    const { clientId, clientSecret }: ClientCredentials = await this
      .getClientCredentials(request);
    const { clientService }: GrantServices = this.services;
    const client: Client | void = clientSecret
      ? await clientService.getAuthenticated(clientId, clientSecret)
      : await clientService.getAuthenticated(clientId);
    if (!client) throw new InvalidClient("client authentication failed");
    return client;
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
