import { Client } from "../models/client.ts";
import { ClientServiceInterface } from "../services/client.ts";
import { Token } from "../models/token.ts";
import { TokenServiceInterface } from "../services/token.ts";
import { OAuth2Request } from "../context.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";
import type { User } from "../models/user.ts";
import { InvalidClient, InvalidScope } from "../errors.ts";
import { BasicAuth, parseBasicAuth } from "../basic_auth.ts";

export interface GrantServices<Scope extends ScopeInterface> {
  clientService: ClientServiceInterface;
  tokenService: TokenServiceInterface<Scope>;
}

export interface GrantOptions<Scope extends ScopeInterface> {
  services: GrantServices<Scope>;
  Scope?: ScopeConstructor<Scope>;
  /** Allow optional refresh token. */
  allowRefreshToken?: boolean;
}

export interface GrantInterface<Scope extends ScopeInterface> {
  services: GrantServices<Scope>;
  Scope: ScopeConstructor<Scope>;
  allowRefreshToken: boolean;
  parseScope(scopeText?: string | null): Scope | undefined;
  acceptedScope(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Scope | undefined>;
  getClientCredentials(
    request: OAuth2Request<Scope>,
  ): Promise<ClientCredentials>;
  getAuthenticatedClient(request: OAuth2Request<Scope>): Promise<Client>;
  generateToken(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Token<Scope>>;
  token(request: OAuth2Request<Scope>, client: Client): Promise<Token<Scope>>;
}

export interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export abstract class AbstractGrant<Scope extends ScopeInterface = DefaultScope>
  implements GrantInterface<Scope> {
  services: GrantServices<Scope>;
  Scope: ScopeConstructor<Scope>;
  /** Allow optional refresh token. Defaults to false. */
  allowRefreshToken: boolean;

  constructor(options: GrantOptions<Scope>) {
    this.services = { ...options.services };
    this.allowRefreshToken = options.allowRefreshToken ?? false;
    this.Scope = options.Scope ??
      (DefaultScope as unknown as ScopeConstructor<Scope>);
  }

  parseScope(scopeText?: string | null): Scope | undefined {
    return scopeText ? new this.Scope(scopeText) : undefined;
  }

  async acceptedScope(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Scope | undefined> {
    const { tokenService } = this.services;
    const acceptedScope = await tokenService.acceptedScope(client, user, scope);
    if (acceptedScope === false) {
      throw new InvalidScope(scope ? "invalid scope" : "scope required");
    }
    return acceptedScope;
  }

  async getClientCredentials(
    request: OAuth2Request<Scope>,
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

  async getAuthenticatedClient(request: OAuth2Request<Scope>): Promise<Client> {
    const { clientId, clientSecret }: ClientCredentials = await this
      .getClientCredentials(request);
    const { clientService } = this.services;
    const client: Client | void = clientSecret
      ? await clientService.getAuthenticated(clientId, clientSecret)
      : await clientService.getAuthenticated(clientId);
    if (!client) throw new InvalidClient("client authentication failed");
    return client;
  }

  async generateToken(
    client: Client,
    user: User,
    scope?: Scope,
  ): Promise<Token<Scope>> {
    const { tokenService } = this.services;
    const token: Token<Scope> = {
      accessToken: await tokenService.generateAccessToken(client, user, scope),
      client,
      user,
    };
    if (scope) token.scope = scope;
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

  /** Generates and saves a token. */
  abstract token(
    request: OAuth2Request<Scope>,
    client: Client,
  ): Promise<Token<Scope>>;
}
