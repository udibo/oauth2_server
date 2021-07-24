import {
  AccessDenied,
  InvalidRequest,
  ServerError,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import { Grant } from "./grants/grant.ts";
import { Client } from "./models/client.ts";
import { Token, TokenServiceInterface } from "./models/token.ts";
import {
  Authenticator,
  Context,
  ErrorHandler,
  errorHandler,
  getAccessToken,
  OAuth2Request,
  OAuth2Response,
} from "./context.ts";
import { Scope, ScopeConstructor, ScopeInterface } from "./models/scope.ts";
import { AuthorizationCodeGrant } from "./grants/authorization_code.ts";
import { AuthorizationCode } from "./models/authorization_code.ts";
import { User } from "./models/user.ts";

export interface OAuth2ServerGrants {
  [key: string]: Grant;
}

export interface OAuth2ServerServices {
  tokenService?: TokenServiceInterface;
}

export interface OAuth2ServerOptions {
  grants: OAuth2ServerGrants;
  services?: OAuth2ServerServices;
  Scope?: ScopeConstructor;
  realm?: string;
  errorHandler?: ErrorHandler;
}

export interface BearerToken {
  "token_type": string;
  "access_token": string;
  "access_token_expires_at"?: string;
  "refresh_token"?: string;
  "refresh_token_expires_at"?: string;
  scope?: string;
}

export class OAuth2Server {
  grants: OAuth2ServerGrants;
  services: OAuth2ServerServices;
  Scope: ScopeConstructor;
  realm: string;
  errorHandler: ErrorHandler;

  constructor(options: OAuth2ServerOptions) {
    this.grants = { ...options.grants };
    this.services = { ...options.services };
    this.Scope = options.Scope ?? Scope;
    this.realm = options.realm ?? "Service";
    this.errorHandler = options.errorHandler ?? errorHandler;
  }

  /** Generates and saves a token using the requested grant's token method. */
  async generateToken(request: OAuth2Request): Promise<Token> {
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

    const grant: Grant = this.grants[grantType];
    const client: Client = await grant.getAuthenticatedClient(request);
    if (!client.grants.includes(grantType)) {
      throw new UnauthorizedClient(
        "client is not authorized to use this grant_type",
      );
    }

    return await grant.token(request, client);
  }

  /** Generates a bearer token from a token. */
  bearerToken(token: Token): BearerToken {
    const bearerToken: BearerToken = {
      "token_type": "Bearer",
      "access_token": token.accessToken,
    };

    if (token.accessTokenExpiresAt) {
      bearerToken["access_token_expires_at"] = token.accessTokenExpiresAt
        .toJSON();
    }

    if (token.refreshToken) bearerToken["refresh_token"] = token.refreshToken;

    if (token.refreshTokenExpiresAt) {
      bearerToken["refresh_token_expires_at"] = token.refreshTokenExpiresAt
        .toJSON();
    }

    if (token.scope) bearerToken.scope = token.scope.toJSON();

    return bearerToken;
  }

  /** Handles a token request. */
  async token(context: Context): Promise<void> {
    const { request, response }: Context = context;
    const { headers }: OAuth2Response = response;
    headers.set("Content-Type", "application/json;charset=UTF-8");
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");

    try {
      const token: Token = await this.generateToken(request);
      const bearerToken: BearerToken = this.bearerToken(token);

      response.status = 200;
      response.body = bearerToken;
    } catch (error) {
      await this.errorHandler(response, error, this.realm);
      throw error;
    }
  }

  /** Authenticates a request and verifies the token has the required scope. */
  async authenticate(
    context: Context,
    scope?: ScopeInterface,
  ): Promise<Token> {
    const { tokenService }: OAuth2ServerServices = this.services;
    if (!tokenService) throw new ServerError("token service required");

    const { request, response, state }: Context = context;
    const accessToken: string | null = await getAccessToken(request);
    if (!accessToken) throw new AccessDenied("authentication required");

    const token: Token | undefined = "token" in state
      ? state.token
      : await tokenService.getAccessToken(
        accessToken,
      );
    if (
      !token ||
      (token.accessTokenExpiresAt && token.accessTokenExpiresAt < new Date())
    ) {
      state.token = undefined;
      throw new AccessDenied("invalid access_token");
    } else {
      state.token = token;
    }

    const { headers }: OAuth2Response = response;
    headers.set("X-OAuth-Scopes", token.scope?.toString() ?? "");
    headers.set("X-Accepted-OAuth-Scopes", scope?.toString() ?? "");
    if (scope && !token.scope?.has(scope)) {
      throw new AccessDenied("insufficient scope");
    }
    return token;
  }

  /** Creates an authenticator function for middleware. */
  authenticatorFactory(scope?: ScopeInterface | string): Authenticator {
    const { tokenService }: OAuth2ServerServices = this.services;
    if (!tokenService) throw new ServerError("token service required");

    const scopeClone: ScopeInterface | undefined = scope
      ? this.Scope.from(scope)
      : undefined;
    return async (context: Context) => {
      let token: Token | null = null;
      try {
        token = await (scopeClone
          ? this.authenticate(context, scopeClone)
          : this.authenticate(context));
      } catch (error) {
        await this.errorHandler(context.response, error, this.realm);
        throw error;
      }
      return token;
    };
  }

  /**
   * Authorizes a token request for the authorization code grant type.
   */
  async authorize(
    context: Context,
    user?: User | null,
  ): Promise<AuthorizationCode> {
    let authorizationCode: AuthorizationCode | null = null;
    let redirectUrl: URL | null = null;
    const { request, response } = context;

    try {
      let responseType: string | null = null;
      let clientId: string | null = null;
      let redirectUri: string | null = null;
      let state: string | null = null;
      let scopeText: string | null = null;
      let challenge: string | null = null;
      let challengeMethod: string | null = null;

      if (request.method === "POST") {
        const contentType: string | null = request.headers.get("content-type");
        if (
          contentType === "application/x-www-form-urlencoded" && request.hasBody
        ) {
          const body: URLSearchParams = await request.body!;
          responseType = body.get("response_type");
          clientId = body.get("client_id");
          redirectUri = body.get("redirect_uri");
          state = body.get("state");
          scopeText = body.get("scope");
          challenge = body.get("code_challenge");
          challengeMethod = body.get("code_challenge_method");
        }
      }

      const url: URL = request.url;
      const { searchParams } = url;

      const grantType = "authorization_code";
      if (!this.grants[grantType]) {
        throw new ServerError(
          "missing authorization code grant",
        );
      }
      const grant: AuthorizationCodeGrant = this
        .grants[grantType] as AuthorizationCodeGrant;

      if (!clientId) clientId = searchParams.get("client_id");
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

      if (!redirectUri) redirectUri = searchParams.get("redirect_uri");
      if (redirectUri && !client.redirectUris.includes(redirectUri)) {
        throw new UnauthorizedClient("redirect_uri not authorized");
      }

      redirectUrl = new URL(redirectUri ?? client.redirectUris![0]);
      const redirectSearchParams: URLSearchParams = redirectUrl.searchParams;

      if (!state) state = searchParams.get("state");
      if (!state) throw new InvalidRequest("state required");
      redirectSearchParams.set("state", state);

      if (!user) throw new AccessDenied("authentication required");

      if (!responseType) responseType = searchParams.get("response_type");
      if (!responseType) {
        throw new InvalidRequest("response_type parameter required");
      }
      if (responseType !== "code") {
        throw new InvalidRequest("response_type not supported");
      }

      if (!scopeText) scopeText = searchParams.get("scope");
      const scope: ScopeInterface | undefined = grant.parseScope(scopeText);
      await grant.validateScope(client, user, scope);

      if (!challenge) challenge = searchParams.get("code_challenge");

      if (!challengeMethod) {
        challengeMethod = searchParams.get("code_challenge_method");
      }
      if (challengeMethod && !challenge) {
        throw new InvalidRequest(
          "code_challenge required when code_challenge_method is set",
        );
      }
      if (challenge && !grant.validateChallengeMethod(challengeMethod)) {
        throw new InvalidRequest("unsupported code_challenge_method");
      }

      const options: Omit<AuthorizationCode, "code" | "expiresAt"> = {
        client,
        user,
      };
      if (scope) options.scope = scope;
      if (redirectUri) options.redirectUri = redirectUri;
      if (challenge) options.challenge = challenge;
      if (challengeMethod) {
        options.challengeMethod = challengeMethod;
      }

      authorizationCode = await grant.generateAuthorizationCode(options);
      redirectSearchParams.set("code", authorizationCode.code);
      response.redirect(redirectUrl);
    } catch (error) {
      if (redirectUrl) {
        const { searchParams } = redirectUrl;
        searchParams.set("error", error.code ?? "server_error");
        if (error.message) searchParams.set("error_description", error.message);
        if (error.uri) searchParams.set("error_uri", error.uri);
        response.redirect(redirectUrl);
      } else {
        await this.errorHandler(response, error, this.realm);
      }
      throw error;
    }

    return authorizationCode;
  }
}
