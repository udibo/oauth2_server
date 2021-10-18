import {
  ErrorBody,
  OAuth2AuthenticatedRequest,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";
import {
  AccessDeniedError,
  isOAuth2Error,
  OAuth2Error,
  ServerError,
} from "./errors.ts";
import { ClientInterface } from "./models/client.ts";
import { Scope, ScopeConstructor, ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { TokenServiceInterface } from "./services/token.ts";

export const DefaultScope = Scope;

export interface ResourceServerServices<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  tokenService?: TokenServiceInterface<Client, User, Scope>;
}

export interface ResourceServerOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services?: ResourceServerServices<Client, User, Scope>;
  Scope?: ScopeConstructor<Scope>;
  realm?: string;
}

export const BEARER_TOKEN =
  /^ *(?:[Bb][Ee][Aa][Rr][Ee][Rr]) +([\w-.~+/]+=*) *$/;

export class ResourceServer<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services: ResourceServerServices<Client, User, Scope>;
  Scope: ScopeConstructor<Scope>;
  realm: string;

  constructor(options: ResourceServerOptions<Client, User, Scope>) {
    this.services = { ...options.services };
    this.Scope = options.Scope ??
      (DefaultScope as unknown as ScopeConstructor<Scope>);
    this.realm = options.realm ?? "Service";
  }

  /** Handles error responses. */
  async errorHandler(
    request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
    error: Error,
  ): Promise<void> {
    const e = isOAuth2Error(error)
      ? error
      : new ServerError("unexpected error", { cause: error });
    response.status = e.status;
    if (e.status === 401 && request.headers.has("authorization")) {
      response.headers.set(
        "WWW-Authenticate",
        `Basic realm="${this.realm}"`,
      );
    }
    const body: ErrorBody = {
      error: e.code ?? "server_error",
    };
    if (e.message) body.error_description = e.message;
    if (e.uri) body.error_uri = e.uri;
    response.body = body;
    return await Promise.resolve();
  }

  /** Gets an access token string from the authorization header or post body. */
  async getAccessToken(
    request: OAuth2Request<Client, User, Scope>,
  ): Promise<string | null> {
    let accessToken: string | null = null;
    const authorization = request.headers.get("authorization");
    if (authorization) {
      const match = BEARER_TOKEN.exec(authorization);
      if (match) accessToken = match[1];
    }

    if (!accessToken) {
      const contentType: string | null = request.headers.get(
        "content-type",
      );
      if (
        request.method === "POST" &&
        contentType === "application/x-www-form-urlencoded"
      ) {
        const body: URLSearchParams = await request.body!;
        accessToken = body.get("access_token");
      }
    }
    return accessToken;
  }

  /** Gets a token for an access token string. */
  async getToken(accessToken: string): Promise<Token<Client, User, Scope>> {
    const { tokenService } = this.services;
    if (!tokenService) throw new ServerError("token service required");
    const token = await tokenService.getToken(accessToken);

    if (
      !token ||
      (token.accessTokenExpiresAt && token.accessTokenExpiresAt < new Date())
    ) {
      throw new AccessDeniedError("invalid access_token");
    }

    return token;
  }

  /** Gets a token for a request and adds it onto the request. */
  async getTokenForRequest<Request extends OAuth2Request<Client, User, Scope>>(
    request: Request,
    getAccessToken: (
      request: Request,
      requireRefresh?: boolean,
    ) => Promise<string | null>,
  ): Promise<Token<Client, User, Scope>> {
    let { token, accessToken } = request;
    if (!token && token !== null) {
      request.token = null;
      request.accessToken = null;
      accessToken = await getAccessToken(request);
      request.accessToken = accessToken;
      if (accessToken) {
        try {
          token = await this.getToken(accessToken);
        } catch (error) {
          if (error.code !== "access_denied") throw error;
          accessToken = await getAccessToken(request, true);
          request.accessToken = accessToken;
        }
      }
      if (!accessToken) {
        accessToken = await this.getAccessToken(request);
        request.accessToken = accessToken;
      }
      if (!token && accessToken) token = await this.getToken(accessToken);
      request.token = token ?? null;
    }
    if (!token) {
      throw new AccessDeniedError(
        accessToken ? "invalid access_token" : "authentication required",
      );
    }
    return token;
  }

  /** Authenticates a request and verifies the token has the required scope. */
  async authenticate<Request extends OAuth2Request<Client, User, Scope>>(
    request: Request,
    response: OAuth2Response,
    next: () => Promise<unknown>,
    getAccessToken: (
      request: Request,
      requireRefresh?: boolean,
    ) => Promise<string | null>,
    acceptedScope?: Scope,
  ): Promise<void> {
    try {
      if (acceptedScope) request.acceptedScope = acceptedScope;

      const token = await this.getTokenForRequest(request, getAccessToken);
      request.token = token;
      if (acceptedScope && !token.scope?.has(acceptedScope)) {
        throw new AccessDeniedError("insufficient scope");
      }
      await this.authenticateSuccess(
        request as OAuth2AuthenticatedRequest<Client, User, Scope>,
        response,
        next,
      );
    } catch (error) {
      await this.authenticateError(request, response, error);
    }
  }

  /** Adds authentication scope headers to the response. */
  async authenticateResponse(
    request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    const { token, acceptedScope } = request;
    const { headers } = response;
    headers.set("X-OAuth-Scopes", token?.scope?.toString() ?? "");
    headers.set("X-Accepted-OAuth-Scopes", acceptedScope?.toString() ?? "");
    return await Promise.resolve();
  }

  /** Handles the response for an authenticated request. */
  async authenticateSuccess(
    request: OAuth2AuthenticatedRequest<Client, User, Scope>,
    response: OAuth2Response,
    next: () => Promise<unknown>,
  ): Promise<void> {
    await this.authenticateResponse(request, response);
    await next();
  }

  /** Handles the response for an unauthenticated request. */
  async authenticateError(
    request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
    error: OAuth2Error,
  ): Promise<void> {
    await this.authenticateResponse(request, response);
    await this.errorHandler(request, response, error);
  }
}

export { challengeMethods, generateCodeVerifier } from "./pkce.ts";
export type { ChallengeMethod, ChallengeMethods } from "./pkce.ts";

export type { Client, ClientInterface } from "./models/client.ts";
export { AbstractClientService } from "./services/client.ts";
export type { ClientServiceInterface } from "./services/client.ts";

export type { User } from "./models/user.ts";
export { AbstractUserService } from "./services/user.ts";
export type { UserServiceInterface } from "./services/user.ts";

export { SCOPE, Scope, SCOPE_TOKEN } from "./models/scope.ts";
export type { ScopeConstructor, ScopeInterface } from "./models/scope.ts";

export type { AccessToken, RefreshToken, Token } from "./models/token.ts";
export {
  AbstractAccessTokenService,
  AbstractRefreshTokenService,
} from "./services/token.ts";
export type { TokenServiceInterface } from "./services/token.ts";

export {
  authorizeParameters,
  authorizeUrl,
  loginRedirectFactory,
} from "./context.ts";
export type {
  AuthorizeParameters,
  ErrorBody,
  LoginRedirectOptions,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2AuthorizeRequest,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";

export {
  camelCase,
  NQCHAR,
  NQSCHAR,
  snakeCase,
  UNICODECHARNOCRLF,
  VSCHAR,
} from "./common.ts";

export {
  AccessDeniedError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  OAuth2Error,
  ServerError,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "./errors.ts";
export type { OAuth2ErrorInit } from "./errors.ts";
