import {
  AccessDeniedError,
  InvalidRequestError,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "./errors.ts";
import { GrantInterface } from "./grants/grant.ts";
import { ClientInterface } from "./models/client.ts";
import { Token } from "./models/token.ts";
import {
  authorizeParameters,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2AuthorizeRequest,
  OAuth2Request,
  OAuth2Response,
  TokenBody,
} from "./context.ts";
import { Scope as DefaultScope, ScopeInterface } from "./models/scope.ts";
import { AuthorizationCodeGrant } from "./grants/authorization_code.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";
import { ResourceServer, ResourceServerOptions } from "./resource_server.ts";

export interface AuthorizationServerGrants<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  [key: string]: GrantInterface<Client, User, Scope>;
}

export interface AuthorizationServerOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends ResourceServerOptions<Client, User, Scope> {
  grants: AuthorizationServerGrants<Client, User, Scope>;
}

export class AuthorizationServer<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> extends ResourceServer<Client, User, Scope> {
  grants: AuthorizationServerGrants<Client, User, Scope>;

  constructor(options: AuthorizationServerOptions<Client, User, Scope>) {
    super(options);
    this.grants = { ...options.grants };
  }

  /** Handles a token request. */
  async token(
    request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    try {
      if (request.method !== "POST") {
        throw new InvalidRequestError("method must be POST");
      }

      const contentType: string | null = request.headers.get("content-type");
      if (contentType !== "application/x-www-form-urlencoded") {
        throw new InvalidRequestError(
          "content-type header must be application/x-www-form-urlencoded",
        );
      }

      const body: URLSearchParams = await request.body;
      const grantType: string | null = body.get("grant_type");
      if (!grantType) {
        throw new InvalidRequestError("grant_type parameter required");
      }
      if (!this.grants[grantType]) {
        throw new UnsupportedGrantTypeError("invalid grant_type");
      }

      const grant = this.grants[grantType];
      const client: Client = await grant.getAuthenticatedClient(request);
      if (!client.grants?.includes(grantType)) {
        throw new UnauthorizedClientError(
          "client is not authorized to use this grant_type",
        );
      }

      request.token = await grant.token(request, client);
      await this.tokenSuccess(
        request as OAuth2AuthenticatedRequest<Client, User, Scope>,
        response,
      );
    } catch (error) {
      await this.tokenError(request, response, error);
    }
  }

  /** Generates a bearer token from a token. */
  bearerToken(token: Token<Client, User, Scope>): TokenBody {
    const bearerToken: TokenBody = {
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
  async tokenResponse(
    _request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    const { headers } = response;
    headers.set("Content-Type", "application/json;charset=UTF-8");
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");
    return await Promise.resolve();
  }

  /** Handles the response for a successful token request. */
  async tokenSuccess(
    request: OAuth2AuthenticatedRequest<Client, User, Scope>,
    response: OAuth2Response,
  ): Promise<void> {
    await this.tokenResponse(request, response);
    const { token } = request;
    const bearerToken: TokenBody = this.bearerToken(token);
    response.status = 200;
    response.body = bearerToken;
  }

  /** Handles the response for an unsuccessful token request. */
  async tokenError(
    request: OAuth2Request<Client, User, Scope>,
    response: OAuth2Response,
    error: OAuth2Error,
  ): Promise<void> {
    await this.tokenResponse(request, response);
    await this.errorHandler(request, response, error);
  }

  /**
   * Authorizes a token request for the authorization code grant type.
   */
  async authorize<
    Request extends OAuth2Request<Client, User, Scope>,
    AuthorizeRequest extends OAuth2AuthorizeRequest<Client, User, Scope>,
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
      const grant = this.grants[grantType] as AuthorizationCodeGrant<
        Client,
        User,
        Scope
      >;

      if (!clientId) {
        throw new InvalidRequestError("client_id parameter required");
      }

      const client: Client = await grant.getClient(clientId);
      if (!client.grants?.includes("authorization_code")) {
        throw new UnauthorizedClientError(
          "client is not authorized to use the authorization code grant type",
        );
      }
      if (!client.redirectUris?.length) {
        throw new UnauthorizedClientError("no authorized redirect_uri");
      }

      if (redirectUri && !client.redirectUris.includes(redirectUri)) {
        throw new UnauthorizedClientError("redirect_uri not authorized");
      }

      const redirectUrl = new URL(redirectUri ?? client.redirectUris![0]);
      request.redirectUrl = redirectUrl;
      const redirectSearchParams: URLSearchParams = redirectUrl.searchParams;

      if (!state) throw new InvalidRequestError("state required");
      redirectSearchParams.set("state", state);

      if (!responseType) {
        throw new InvalidRequestError("response_type required");
      }
      if (responseType !== "code") {
        throw new InvalidRequestError("response_type not supported");
      }

      let scope: Scope | null | undefined = grant.parseScope(scopeText);
      request.requestedScope = scope;

      if (challengeMethod && !challenge) {
        throw new InvalidRequestError(
          "code_challenge required when code_challenge_method is set",
        );
      }
      if (challenge && !grant.validateChallengeMethod(challengeMethod)) {
        throw new InvalidRequestError("unsupported code_challenge_method");
      }

      await setAuthorization(request as unknown as AuthorizeRequest);
      const { user, authorizedScope } = request;
      if (!user) throw new AccessDeniedError("authentication required");

      scope = await grant.acceptedScope(client, user, scope);
      if (scope && (!authorizedScope || !authorizedScope.has(scope))) {
        throw new AccessDeniedError("not authorized");
      }

      const options: Omit<
        AuthorizationCode<Client, User, Scope>,
        "code" | "expiresAt"
      > = {
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
        request as OAuth2AuthorizedRequest<Client, User, Scope>,
        response,
      );
    } catch (error) {
      await this.authorizeError(request, response, error, login, consent);
    }
  }

  /** Handles the response for an authorization request. */
  async authorizeSuccess<
    Request extends OAuth2AuthorizedRequest<Client, User, Scope>,
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
    Request extends OAuth2Request<Client, User, Scope>,
    AuthorizeRequest extends OAuth2AuthorizeRequest<Client, User, Scope>,
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

export {
  AbstractAccessTokenService,
  AbstractClientService,
  AbstractRefreshTokenService,
  AbstractUserService,
  AccessDeniedError,
  authorizeParameters,
  authorizeUrl,
  BEARER_TOKEN,
  camelCase,
  challengeMethods,
  DefaultScope,
  generateCodeVerifier,
  generateSalt,
  hashPassword,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  loginRedirectFactory,
  NQCHAR,
  NQSCHAR,
  OAuth2Error,
  ResourceServer,
  SCOPE,
  Scope,
  SCOPE_TOKEN,
  ServerError,
  snakeCase,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UNICODECHARNOCRLF,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
  UnsupportedTokenTypeError,
  VSCHAR,
} from "./resource_server.ts";
export type {
  AccessToken,
  AuthorizeParameters,
  ChallengeMethod,
  ChallengeMethods,
  Client,
  ClientInterface,
  ClientServiceInterface,
  ErrorBody,
  LoginRedirectOptions,
  OAuth2AuthenticatedRequest,
  OAuth2AuthorizedRequest,
  OAuth2AuthorizeRequest,
  OAuth2ErrorOptions,
  OAuth2Request,
  OAuth2Response,
  RefreshToken,
  ResourceServerOptions,
  ResourceServerServices,
  ScopeConstructor,
  ScopeInterface,
  Token,
  TokenBody,
  TokenServiceInterface,
  User,
  UserServiceInterface,
} from "./resource_server.ts";

export type { AuthorizationCode } from "./models/authorization_code.ts";
export { AbstractAuthorizationCodeService } from "./services/authorization_code.ts";
export type {
  AuthorizationCodeServiceInterface,
} from "./services/authorization_code.ts";

export { parseBasicAuth } from "./basic_auth.ts";
export type { BasicAuth } from "./basic_auth.ts";

export { AbstractGrant } from "./grants/grant.ts";
export type {
  ClientCredentials,
  GrantInterface,
  GrantOptions,
  GrantServices,
} from "./grants/grant.ts";

export { AuthorizationCodeGrant } from "./grants/authorization_code.ts";
export type {
  AuthorizationCodeGrantInterface,
  AuthorizationCodeGrantOptions,
  AuthorizationCodeGrantServices,
  GenerateAuthorizationCodeOptions,
  PKCEClientCredentials,
} from "./grants/authorization_code.ts";

export { ClientCredentialsGrant } from "./grants/client_credentials.ts";
export type {
  ClientCredentialsGrantInterface,
  ClientCredentialsGrantOptions,
  ClientCredentialsGrantServices,
} from "./grants/client_credentials.ts";

export { RefreshTokenGrant } from "./grants/refresh_token.ts";
export type {
  RefreshTokenGrantInterface,
  RefreshTokenGrantOptions,
} from "./grants/refresh_token.ts";
