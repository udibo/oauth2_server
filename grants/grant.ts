import { ClientInterface } from "../models/client.ts";
import { ClientServiceInterface } from "../services/client.ts";
import { Token } from "../models/token.ts";
import { TokenServiceInterface } from "../services/token.ts";
import { OAuth2Request } from "../context.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";
import { InvalidClientError, InvalidScopeError } from "../errors.ts";
import { BasicAuth, parseBasicAuth } from "../basic_auth.ts";

export interface GrantServices<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  clientService: ClientServiceInterface<Client, User>;
  tokenService: TokenServiceInterface<Client, User, Scope>;
}

export interface GrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services: GrantServices<Client, User, Scope>;
  Scope?: ScopeConstructor<Scope>;
  /** Allow optional refresh token. */
  allowRefreshToken?: boolean;
}

export interface GrantInterface<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services: GrantServices<Client, User, Scope>;
  Scope: ScopeConstructor<Scope>;
  allowRefreshToken: boolean;
  parseScope(scopeText?: string | null): Scope | undefined;
  acceptedScope(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<Scope | null | undefined>;
  getClientCredentials(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<ClientCredentials>;
  getAuthenticatedClient(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<Client>;
  generateToken(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<Token<Client, User, Scope>>;
  token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<Token<Client, User, Scope>>;
}

export interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export abstract class AbstractGrant<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> implements GrantInterface<Client, User, Scope> {
  services: GrantServices<Client, User, Scope>;
  Scope: ScopeConstructor<Scope>;
  /** Allow optional refresh token. Defaults to false. */
  allowRefreshToken: boolean;

  constructor(options: GrantOptions<Client, User, Scope>) {
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
  ): Promise<Scope | null | undefined> {
    const { tokenService } = this.services;
    const acceptedScope = await tokenService.acceptedScope(client, user, scope);
    if (acceptedScope === false) {
      throw new InvalidScopeError(scope ? "invalid scope" : "scope required");
    }
    return acceptedScope;
  }

  async getClientCredentials(
    request: OAuth2Request<Client, User, Scope>,
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
      if (!request.headers.has("authorization")) {
        const body: URLSearchParams = await request.body;
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

  async getAuthenticatedClient(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<Client> {
    const { clientId, clientSecret }: ClientCredentials = await this
      .getClientCredentials(request);
    const { clientService } = this.services;
    const client: Client | void = clientSecret
      ? await clientService.getAuthenticated(clientId, clientSecret)
      : await clientService.getAuthenticated(clientId);
    if (!client) throw new InvalidClientError("client authentication failed");
    return client;
  }

  async generateToken(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<Token<Client, User, Scope>> {
    const { tokenService } = this.services;
    const token: Token<Client, User, Scope> = {
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
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<Token<Client, User, Scope>>;
}
