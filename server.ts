import {
  AccessDenied,
  InvalidRequest,
  OAuth2Error,
  ServerError,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import { GrantInterface } from "./grants/grant.ts";
import { Client } from "./models/client.ts";
import { Token } from "./models/token.ts";
import { TokenServiceInterface } from "./services/token.ts";
import {
  authorizeParameters,
  ErrorBody,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2AuthorizeRequest,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "./models/scope.ts";
import { AuthorizationCodeGrant } from "./grants/authorization_code.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";

export interface OAuth2ServerGrants<Scope extends ScopeInterface> {
  [key: string]: GrantInterface<Scope>;
}

export interface OAuth2ServerServices<Scope extends ScopeInterface> {
  tokenService?: TokenServiceInterface<Scope>;
}

export interface OAuth2ServerOptions<Scope extends ScopeInterface> {
  grants: OAuth2ServerGrants<Scope>;
  services?: OAuth2ServerServices<Scope>;
  Scope?: ScopeConstructor<Scope>;
  realm?: string;
}

export interface BearerToken {
  "token_type": string;
  "access_token": string;
  "expires_in"?: number;
  "refresh_token"?: string;
  scope?: string;
}

const BEARER_TOKEN = /^ *(?:[Bb][Ee][Aa][Rr][Ee][Rr]) +([\w-.~+/]+=*) *$/;

export class OAuth2Server<Scope extends ScopeInterface = DefaultScope> {
  grants: OAuth2ServerGrants<Scope>;
  services: OAuth2ServerServices<Scope>;
  Scope: ScopeConstructor<Scope>;
  realm: string;

  constructor(options: OAuth2ServerOptions<Scope>) {
    this.grants = { ...options.grants };
    this.services = { ...options.services };
    this.Scope = options.Scope ??
      (DefaultScope as unknown as ScopeConstructor<Scope>);
    this.realm = options.realm ?? "Service";
  }

  /** Handles error responses. */
  errorHandler(
    request: OAuth2Request<Scope>,
    response: OAuth2Response,
    error: OAuth2Error,
  ): Promise<void> {
    response.status = error.status ?? 500;
    if (error.status === 401 && request.headers.has("authorization")) {
      response.headers.set(
        "WWW-Authenticate",
        `Basic realm="${this.realm}"`,
      );
    }
    const body: ErrorBody = {
      error: error.code ?? "server_error",
    };
    if (error.message) body.error_description = error.message;
    if (error.uri) body.error_uri = error.uri;
    response.body = body;
    return Promise.resolve();
  }

  /** Handles a token request. */
  async token(
    request: OAuth2Request<Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    try {
      if (request.method !== "POST") {
        throw new InvalidRequest("method must be POST");
      }

      const contentType: string | null = request.headers.get("content-type");
      if (contentType !== "application/x-www-form-urlencoded") {
        throw new InvalidRequest(
          "content-type header must be application/x-www-form-urlencoded",
        );
      }

      if (!request.hasBody) throw new InvalidRequest("request body required");

      const body: URLSearchParams = await request.body!;
      const grantType: string | null = body.get("grant_type");
      if (!grantType) throw new InvalidRequest("grant_type parameter required");
      if (!this.grants[grantType]) {
        throw new UnsupportedGrantType("invalid grant_type");
      }

      const grant = this.grants[grantType];
      const client: Client = await grant.getAuthenticatedClient(request);
      if (!client.grants.includes(grantType)) {
        throw new UnauthorizedClient(
          "client is not authorized to use this grant_type",
        );
      }

      request.token = await grant.token(request, client);
      await this.tokenSuccess(
        request as OAuth2AuthenticatedRequest<Scope>,
        response,
      );
    } catch (error) {
      await this.tokenError(request, response, error);
    }
  }

  /** Generates a bearer token from a token. */
  bearerToken(token: Token<Scope>): BearerToken {
    const bearerToken: BearerToken = {
      "token_type": "Bearer",
      "access_token": token.accessToken,
    };

    const { tokenService } = this.services;
    if (tokenService) {
      bearerToken["expires_in"] = tokenService.accessTokenLifetime;
    }

    if (token.refreshToken) bearerToken["refresh_token"] = token.refreshToken;

    if (token.scope) bearerToken.scope = token.scope.toJSON();

    return bearerToken;
  }

  /** Adds headers to the token response. */
  tokenResponse(
    _request: OAuth2Request<Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    const { headers } = response;
    headers.set("Content-Type", "application/json;charset=UTF-8");
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");
    return Promise.resolve();
  }

  /** Handles the response for a successful token request. */
  async tokenSuccess(
    request: OAuth2AuthenticatedRequest<Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    await this.tokenResponse(request, response);
    const { token } = request;
    const bearerToken: BearerToken = this.bearerToken(token);
    response.status = 200;
    response.body = bearerToken;
  }

  /** Handles the response for an unsuccessful token request. */
  async tokenError(
    request: OAuth2Request<Scope>,
    response: OAuth2Response,
    error: OAuth2Error,
  ): Promise<void> {
    await this.tokenResponse(request, response);
    await this.errorHandler(request, response, error);
  }

  /** Gets an access token string from the authorization header or post body. */
  async getAccessToken(request: OAuth2Request<Scope>): Promise<string | null> {
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
  async getToken(accessToken: string): Promise<Token<Scope>> {
    const { tokenService } = this.services;
    if (!tokenService) throw new ServerError("token service required");
    const token = await tokenService.getToken(accessToken);

    if (
      !token ||
      (token.accessTokenExpiresAt && token.accessTokenExpiresAt < new Date())
    ) {
      throw new AccessDenied("invalid access_token");
    }

    return token;
  }

  /** Authenticates a request and verifies the token has the required scope. */
  async authenticate<Request extends OAuth2Request<Scope>>(
    request: Request,
    response: OAuth2Response,
    next: () => Promise<unknown>,
    getAccessToken: (request: Request) => Promise<string | null>,
    acceptedScope?: Scope,
  ): Promise<void> {
    try {
      if (acceptedScope) request.acceptedScope = acceptedScope;

      let { token } = request;
      if (!token) {
        const accessToken: string | null = await getAccessToken(request) ??
          await this.getAccessToken(request);
        if (!accessToken) throw new AccessDenied("authentication required");
        token = await this.getToken(accessToken);
      }
      request.token = token;

      if (acceptedScope && !token.scope?.has(acceptedScope)) {
        throw new AccessDenied("insufficient scope");
      }
      await this.authenticateSuccess(
        request as OAuth2AuthenticatedRequest<Scope>,
        response,
        next,
      );
    } catch (error) {
      await this.authenticateError(request, response, error);
    }
  }

  /** Adds authentication scope headers to the response. */
  authenticateResponse(
    request: OAuth2Request<Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    const { token, acceptedScope } = request;
    const { headers } = response;
    headers.set("X-OAuth-Scopes", token?.scope?.toString() ?? "");
    headers.set("X-Accepted-OAuth-Scopes", acceptedScope?.toString() ?? "");
    return Promise.resolve();
  }

  /** Handles the response for an authenticated request. */
  async authenticateSuccess(
    request: OAuth2AuthenticatedRequest<Scope>,
    response: OAuth2Response,
    next: () => Promise<unknown>,
  ): Promise<void> {
    await this.authenticateResponse(request, response);
    await next();
  }

  /** Handles the response for an unauthenticated request. */
  async authenticateError(
    request: OAuth2Request<Scope>,
    response: OAuth2Response,
    error: OAuth2Error,
  ): Promise<void> {
    await this.authenticateResponse(request, response);
    await this.errorHandler(request, response, error);
  }

  /**
   * Authorizes a token request for the authorization code grant type.
   */
  async authorize<
    Request extends OAuth2Request<Scope>,
    AuthorizeRequest extends OAuth2AuthorizeRequest<Scope>,
    Response extends OAuth2Response,
  >(
    request: Request,
    response: Response,
    setAuthorization: (
      request: AuthorizeRequest,
    ) => Promise<void>,
    login: (
      request: AuthorizeRequest,
      response: Response,
    ) => Promise<void>,
    consent?: (
      request: AuthorizeRequest,
      response: Response,
    ) => Promise<void>,
  ): Promise<void> {
    try {
      request.authorizeParameters = await authorizeParameters(request);
      const {
        responseType,
        clientId,
        redirectUri,
        state,
        scope: scopeText,
        challenge,
        challengeMethod,
      } = request.authorizeParameters;

      const grantType = "authorization_code";
      if (!this.grants[grantType]) {
        throw new ServerError(
          "missing authorization code grant",
        );
      }
      const grant = this.grants[grantType] as AuthorizationCodeGrant<Scope>;

      if (!clientId) throw new InvalidRequest("client_id parameter required");

      const client: Client = await grant.getClient(clientId);
      if (!client.grants.includes("authorization_code")) {
        throw new UnauthorizedClient(
          "client is not authorized to use the authorization code grant type",
        );
      }
      if (!client.redirectUris?.length) {
        throw new UnauthorizedClient("no authorized redirect_uri");
      }

      if (redirectUri && !client.redirectUris.includes(redirectUri)) {
        throw new UnauthorizedClient("redirect_uri not authorized");
      }

      const redirectUrl = new URL(redirectUri ?? client.redirectUris![0]);
      request.redirectUrl = redirectUrl;
      const redirectSearchParams: URLSearchParams = redirectUrl.searchParams;

      if (!state) throw new InvalidRequest("state required");
      redirectSearchParams.set("state", state);

      if (!responseType) {
        throw new InvalidRequest("response_type required");
      }
      if (responseType !== "code") {
        throw new InvalidRequest("response_type not supported");
      }

      let scope: Scope | undefined = grant.parseScope(scopeText);
      request.requestedScope = scope;

      if (challengeMethod && !challenge) {
        throw new InvalidRequest(
          "code_challenge required when code_challenge_method is set",
        );
      }
      if (challenge && !grant.validateChallengeMethod(challengeMethod)) {
        throw new InvalidRequest("unsupported code_challenge_method");
      }

      await setAuthorization(request as unknown as AuthorizeRequest);
      const { user, authorizedScope } = request;
      if (!user) throw new AccessDenied("authentication required");

      scope = await grant.acceptedScope(client, user, scope);
      if (scope && (!authorizedScope || !authorizedScope.has(scope))) {
        throw new AccessDenied("not authorized");
      }

      const options: Omit<AuthorizationCode<Scope>, "code" | "expiresAt"> = {
        client,
        user,
      };
      if (scope) options.scope = scope;
      if (redirectUri) options.redirectUri = redirectUri;
      if (challenge) options.challenge = challenge;
      if (challengeMethod) {
        options.challengeMethod = challengeMethod;
      }
      const authorizationCode = await grant.generateAuthorizationCode(options);
      request.authorizationCode = authorizationCode;
      redirectSearchParams.set("code", authorizationCode.code);
      await this.authorizeSuccess(
        request as OAuth2AuthorizedRequest<Scope>,
        response,
      );
    } catch (error) {
      await this.authorizeError(request, response, error, login, consent);
    }
  }

  /** Handles the response for an authorization request. */
  async authorizeSuccess<
    Request extends OAuth2AuthorizedRequest<Scope>,
    Response extends OAuth2Response,
  >(
    request: Request,
    response: Response,
  ): Promise<void> {
    const { redirectUrl } = request;
    await response.redirect(redirectUrl);
  }

  /** Handles the response for an unauthorized request. */
  async authorizeError<
    Request extends OAuth2Request<Scope>,
    AuthorizeRequest extends OAuth2AuthorizeRequest<Scope>,
    Response extends OAuth2Response,
  >(
    request: Request,
    response: Response,
    error: OAuth2Error,
    login: (
      request: AuthorizeRequest,
      response: Response,
    ) => Promise<void>,
    consent?: (
      request: AuthorizeRequest,
      response: Response,
    ) => Promise<void>,
  ): Promise<void> {
    let errorHandled = false;
    try {
      if (!!request.authorizeParameters && error.code === "access_denied") {
        if (!request.user) {
          await login(request as unknown as AuthorizeRequest, response);
        } else if (consent) {
          await consent(request as unknown as AuthorizeRequest, response);
        }
        errorHandled = true;
      }
    } catch (e) {
      e.cause = error;
      error = e;
    }

    if (!errorHandled) {
      const { redirectUrl } = request;
      if (redirectUrl) {
        const { searchParams } = redirectUrl;
        searchParams.set("error", error.code ?? "server_error");
        if (error.message) searchParams.set("error_description", error.message);
        if (error.uri) searchParams.set("error_uri", error.uri);
        await response.redirect(redirectUrl);
      } else {
        await this.errorHandler(request, response, error);
      }
    }
  }
}
